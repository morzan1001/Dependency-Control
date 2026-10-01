"""HTTP behaviour of the ad-hoc analysis job: POST /api/v1/analyze queues it, GET /api/v1/analyze/{job_id} answers it."""

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.core.config import settings
from app.core.constants import ADHOC_JOB_TTL_SECONDS, API_KEY_SURFACE_ADHOC, HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS
from app.core.housekeeping import requeue_waiting_adhoc_jobs
from app.core.init_db import create_indexes
from app.core.permissions import Permissions
from app.core.worker import AnalysisWorkerManager
from app.repositories.api_keys import ApiKeyRepository
from app.schemas.adhoc import AdhocAnalyzeRequest
from app.services.analysis.adhoc import run_adhoc_analysis
from app.services.gridfs_maintenance import load_gridfs_json

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_ANALYZE = "/api/v1/analyze"
_FIXTURES = Path(__file__).parents[1] / "fixtures"
_OWNER = "adhoc-user"
_ENVELOPE = {
    "findings",
    "stats",
    "dependencies",
    "epss_kev_summary",
    "reachability_summary",
    "recommendations",
    "analyzers",
    "waivers_applied",
    "waived_count",
}
_ENRICHMENT = "epss_kev"
_LICENSE_COMPLIANCE = "license_compliance"
_SECRET_MARKER = "swordfish"
_PENDING = "pending"
_PROCESSING = "processing"
_FAILED = "failed"
_COMPLETED = "completed"
_ANALYSIS_ERROR = "osv exploded"
_STALE = timedelta(seconds=HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS + 60)
_SILENT = timedelta(seconds=settings.HOUSEKEEPING_STUCK_SCAN_TIMEOUT_SECONDS + 60)
_TTL_SLACK = timedelta(minutes=5)

_SIZE_SBOMS = 12
_SIZE_COPIES = 60
_SIZE_FANOUT = 25
_SIZE_SCANNER_FINDINGS = 3_000
_SIZE_CALLGRAPH_FILES = 5_001
_OLD_SBOM_LIMIT = 10
_OLD_COMPONENT_LIMIT = 10_000
_OLD_EVIDENCE_LIMIT = 20_000
_OLD_GRAPH_LIMIT = 250_000
_OLD_SCANNER_LIMIT = 5_000
_OLD_CALLGRAPH_LIMIT = 50_000
_OLD_FINDINGS_LIMIT = 5_000
_MONGO_DOCUMENT_LIMIT = 16 * 1024 * 1024


def _fixture(path: str) -> Any:
    return json.loads((_FIXTURES / path).read_text())


def _request(**overrides: Any) -> dict[str, Any]:
    return {
        "sboms": [_fixture("sbom/rootfs.trivy.cdx.json")],
        "analyzers": [_LICENSE_COMPLIANCE],
        "apply_global_waivers": False,
        **overrides,
    }


async def _issue_key(db, permissions=(Permissions.ANALYZE_ADHOC,), owner=_OWNER):
    doc, plaintext = await ApiKeyRepository(db).create(owner, "ci", [API_KEY_SURFACE_ADHOC], 30)
    await db.users.insert_one(
        {
            "_id": owner,
            "username": owner,
            "email": f"{owner}@example.com",
            "permissions": list(permissions),
            "is_active": True,
            "hashed_password": "x",
        }
    )
    return doc, plaintext


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


async def _post(client, token, body=None) -> str:
    resp = await client.post(_ANALYZE, json=body or _request(), headers=_bearer(token))
    assert resp.status_code == 202, resp.text
    job = resp.json()
    assert job["status"] == _PENDING
    return job["job_id"]


async def _run(client, token, worker: AnalysisWorkerManager, body=None) -> str:
    job_id = await _post(client, token, body)
    await worker.queue.join()
    return job_id


def _idle_worker(monkeypatch) -> AnalysisWorkerManager:
    manager = AnalysisWorkerManager(num_workers=1)
    monkeypatch.setattr("app.api.v1.endpoints.analyze.worker_manager", manager)
    return manager


def _housekeeping_on(db, monkeypatch) -> None:
    async def _get_database():
        return db

    monkeypatch.setattr("app.core.housekeeping.get_database", _get_database)


def _without_timestamps(result: dict[str, Any]) -> dict[str, Any]:
    stamped = {key: result[key] for key in ("epss_kev_summary", "reachability_summary") if result[key]}
    return {**result, **{key: {**summary, "timestamp": None} for key, summary in stamped.items()}}


async def test_a_queued_analysis_answers_what_the_pipeline_computes(client, db, running_worker):
    _, token = await _issue_key(db)

    job_id = await _run(client, token, running_worker)
    resp = await client.get(f"{_ANALYZE}/{job_id}", headers=_bearer(token))

    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("application/json")
    body = resp.json()
    assert set(body) == _ENVELOPE
    assert set(body["analyzers"]["notes"]) == {_ENRICHMENT}
    expected = await run_adhoc_analysis(AdhocAnalyzeRequest(**_request()), db)
    assert _without_timestamps(body) == _without_timestamps(expected.model_dump(mode="json"))


async def test_the_result_renders_as_a_document(client, db, running_worker):
    _, token = await _issue_key(db)

    job_id = await _run(client, token, running_worker)
    resp = await client.get(f"{_ANALYZE}/{job_id}", params={"format": "html"}, headers=_bearer(token))

    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/html")
    assert resp.text.startswith("<!DOCTYPE html>")
    assert "alpine-baselayout-data" in resp.text


async def test_a_format_in_the_body_is_422(client, db, monkeypatch):
    _, token = await _issue_key(db)
    _idle_worker(monkeypatch)

    resp = await client.post(_ANALYZE, json=_request(format="html"), headers=_bearer(token))

    assert resp.status_code == 422, resp.text
    assert await db.adhoc_jobs.count_documents({}) == 0


async def test_only_the_owner_sees_a_job(client, db, monkeypatch):
    _, token = await _issue_key(db)
    _, stranger = await _issue_key(db, owner="someone-else")
    _idle_worker(monkeypatch)
    job_id = await _post(client, token)

    foreign = await client.get(f"{_ANALYZE}/{job_id}", headers=_bearer(stranger))
    unknown = await client.get(f"{_ANALYZE}/no-such-job", headers=_bearer(token))

    assert foreign.status_code == 404, foreign.text
    assert unknown.status_code == 404, unknown.text


async def test_a_waiting_job_answers_202_with_its_status(client, db, monkeypatch):
    _, token = await _issue_key(db)
    _idle_worker(monkeypatch)
    job_id = await _post(client, token)

    queued = await client.get(f"{_ANALYZE}/{job_id}", headers=_bearer(token))
    await db.adhoc_jobs.update_one(
        {"_id": job_id}, {"$set": {"status": _PROCESSING, "heartbeat_at": datetime.now(timezone.utc)}}
    )
    running = await client.get(f"{_ANALYZE}/{job_id}", headers=_bearer(token))

    assert (queued.status_code, queued.json()) == (202, {"job_id": job_id, "status": _PENDING})
    assert (running.status_code, running.json()) == (202, {"job_id": job_id, "status": _PROCESSING})


async def test_a_job_whose_worker_went_silent_is_500_and_left_alone(client, db, monkeypatch):
    _, token = await _issue_key(db)
    _idle_worker(monkeypatch)
    job_id = await _post(client, token)
    silent_since = datetime.now(timezone.utc) - _SILENT
    await db.adhoc_jobs.update_one({"_id": job_id}, {"$set": {"status": _PROCESSING, "heartbeat_at": silent_since}})
    before = await db.adhoc_jobs.find_one({"_id": job_id})

    resp = await client.get(f"{_ANALYZE}/{job_id}", headers=_bearer(token))

    assert resp.status_code == 500, resp.text
    assert resp.json()["detail"]
    assert await db.adhoc_jobs.find_one({"_id": job_id}) == before


async def test_a_failed_analysis_is_500_with_its_error_and_never_requeued(client, db, running_worker, monkeypatch):
    _, token = await _issue_key(db)

    async def _explode(_request, _db):
        raise RuntimeError(_ANALYSIS_ERROR)

    monkeypatch.setattr("app.core.worker.run_adhoc_analysis", _explode)
    job_id = await _run(client, token, running_worker)
    resp = await client.get(f"{_ANALYZE}/{job_id}", headers=_bearer(token))

    assert (resp.status_code, resp.json()) == (500, {"detail": _ANALYSIS_ERROR})
    await db.adhoc_jobs.update_one({"_id": job_id}, {"$set": {"created_at": datetime.now(timezone.utc) - _STALE}})
    _housekeeping_on(db, monkeypatch)
    await requeue_waiting_adhoc_jobs(running_worker)
    assert running_worker.queue.empty()
    assert (await db.adhoc_jobs.find_one({"_id": job_id}))["status"] == _FAILED


async def test_a_finished_job_and_its_files_expire_a_day_later(client, db, running_worker):
    await create_indexes(db)
    _, token = await _issue_key(db)

    job_id = await _run(client, token, running_worker)
    finished = datetime.now(timezone.utc)
    job = await db.adhoc_jobs.find_one({"_id": job_id})
    indexes = await db.adhoc_jobs.index_information()

    assert job["status"] == _COMPLETED
    assert abs(job["expires_at"] - (finished + timedelta(seconds=ADHOC_JOB_TTL_SECONDS))) < _TTL_SLACK
    assert indexes["expires_at_1"]["expireAfterSeconds"] == 0
    assert {"input_file_id_1", "result_file_id_1"} <= set(indexes)


async def test_a_pending_job_that_lost_its_queue_entry_is_run(client, db, running_worker, monkeypatch):
    _, token = await _issue_key(db)
    _idle_worker(monkeypatch)
    job_id = await _post(client, token)
    await db.adhoc_jobs.update_one({"_id": job_id}, {"$set": {"created_at": datetime.now(timezone.utc) - _STALE}})
    _housekeeping_on(db, monkeypatch)

    await requeue_waiting_adhoc_jobs(running_worker)
    await running_worker.queue.join()
    resp = await client.get(f"{_ANALYZE}/{job_id}", headers=_bearer(token))

    assert resp.status_code == 200, resp.text


async def test_requeue_waits_while_every_worker_has_a_job(client, db, monkeypatch):
    _, token = await _issue_key(db)
    manager = _idle_worker(monkeypatch)
    job_id = await _post(client, token)
    await db.adhoc_jobs.update_one({"_id": job_id}, {"$set": {"created_at": datetime.now(timezone.utc) - _STALE}})
    _housekeeping_on(db, monkeypatch)

    await requeue_waiting_adhoc_jobs(manager)

    assert manager.queue.qsize() == 1


async def test_a_processing_job_is_never_requeued(client, db, monkeypatch):
    _, token = await _issue_key(db)
    _idle_worker(monkeypatch)
    job_id = await _post(client, token)
    await db.adhoc_jobs.update_one(
        {"_id": job_id}, {"$set": {"status": _PROCESSING, "created_at": datetime.now(timezone.utc) - _STALE}}
    )
    _housekeeping_on(db, monkeypatch)
    manager = AnalysisWorkerManager(num_workers=1)

    await requeue_waiting_adhoc_jobs(manager)

    assert manager.queue.empty()


async def test_a_job_queued_twice_runs_once(client, db, running_worker, monkeypatch):
    _, token = await _issue_key(db)
    runs = 0

    async def _counted(request, database):
        nonlocal runs
        runs += 1
        return await run_adhoc_analysis(request, database)

    monkeypatch.setattr("app.core.worker.run_adhoc_analysis", _counted)
    job_id = await _post(client, token)
    await running_worker.add_adhoc_job(job_id)
    await running_worker.queue.join()

    assert runs == 1
    assert (await db.adhoc_jobs.find_one({"_id": job_id}))["status"] == _COMPLETED


def _inflated_sbom(position: int) -> dict[str, Any]:
    """The trivy rootfs SBOM with its libraries copied under unique names and a 25-wide dependency fan-out."""
    sbom = _fixture("sbom/rootfs.trivy.cdx.json")
    libraries = [c for c in sbom["components"] if c["type"] == "library"]
    copies = []
    for n in range(_SIZE_COPIES):
        for library in libraries:
            renamed = f"/{library['name']}-s{position}c{n}@"
            copies.append(
                {
                    **library,
                    "name": f"{library['name']}-s{position}c{n}",
                    "bom-ref": library["bom-ref"].replace(f"/{library['name']}@", renamed),
                    "purl": library["purl"].replace(f"/{library['name']}@", renamed),
                }
            )
    refs = [copy["bom-ref"] for copy in copies]
    sbom["components"] = [c for c in sbom["components"] if c["type"] != "library"] + copies
    sbom["dependencies"] = [{"ref": ref, "dependsOn": refs[k + 1 : k + 1 + _SIZE_FANOUT]} for k, ref in enumerate(refs)]
    return sbom


def _in_service(path: str, n: int) -> str:
    return f"services/svc-{n:06d}/{path}"


def _inflated_scanners() -> dict[str, Any]:
    line = _fixture("secrets/trufflehog_v3_line.json")
    location = line["SourceMetadata"]["Data"]["Filesystem"]
    result = _fixture("sast/opengrep_result.json")
    return {
        "trufflehog": {
            "findings": [
                {
                    **line,
                    "SourceMetadata": {"Data": {"Filesystem": {**location, "file": _in_service(location["file"], n)}}},
                }
                for n in range(_SIZE_SCANNER_FINDINGS)
            ]
        },
        "opengrep": {
            "findings": [{**result, "path": _in_service(result["path"], n)} for n in range(_SIZE_SCANNER_FINDINGS)]
        },
    }


def _madge_callgraph() -> dict[str, Any]:
    """madge `--json --include-npm` output of source files importing ten of 2 000 npm packages each."""
    return {
        "format": "madge",
        **{
            f"src/features/f{i:06d}/components/Widget.tsx": [
                f"../../node_modules/pkg-{(i * 10 + j) % 2_000:04d}/dist/esm/components/primitives/index.js"
                for j in range(10)
            ]
            for i in range(_SIZE_CALLGRAPH_FILES)
        },
    }


async def test_an_analysis_past_every_old_limit_completes_whole(client, db, running_worker):
    _, token = await _issue_key(db)
    body = _request(
        sboms=[_inflated_sbom(position) for position in range(_SIZE_SBOMS)],
        scanners=_inflated_scanners(),
        callgraph=_madge_callgraph(),
    )
    components = [c for sbom in body["sboms"] for c in sbom["components"]]
    graph = [ref for sbom in body["sboms"] for entry in sbom["dependencies"] for ref in [entry, *entry["dependsOn"]]]
    assert len(body["sboms"]) > _OLD_SBOM_LIMIT
    assert len(components) > _OLD_COMPONENT_LIMIT
    assert sum(len(c.get("properties", [])) for c in components) > _OLD_EVIDENCE_LIMIT
    assert len(graph) > _OLD_GRAPH_LIMIT
    assert 2 * _SIZE_SCANNER_FINDINGS > _OLD_SCANNER_LIMIT
    assert sum(len(v) for k, v in body["callgraph"].items() if k != "format") > _OLD_CALLGRAPH_LIMIT

    job_id = await _run(client, token, running_worker, body)
    resp = await client.get(f"{_ANALYZE}/{job_id}", headers=_bearer(token))

    assert resp.status_code == 200, resp.text[:2000]
    job = await db.adhoc_jobs.find_one({"_id": job_id})
    stored = await load_gridfs_json(AsyncIOMotorGridFSBucket(db), job["result_file_id"])
    assert len(resp.content) > _MONGO_DOCUMENT_LIMIT
    assert resp.json() == stored
    types = Counter(finding["type"] for finding in stored["findings"])
    assert (types["secret"], types["sast"]) == (_SIZE_SCANNER_FINDINGS, _SIZE_SCANNER_FINDINGS)
    assert len(stored["findings"]) > _OLD_FINDINGS_LIMIT
    expected = await run_adhoc_analysis(AdhocAnalyzeRequest(**body), db)
    assert _without_timestamps(stored) == _without_timestamps(expected.model_dump(mode="json"))


async def test_unauthenticated_requests_are_rejected(db):
    from app.db.mongodb import get_database
    from app.main import app

    saved = dict(app.dependency_overrides)
    app.dependency_overrides.clear()

    async def _fake_get_database():
        return db

    app.dependency_overrides[get_database] = _fake_get_database
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            posted = await ac.post(_ANALYZE, json=_request())
            fetched = await ac.get(f"{_ANALYZE}/some-job")
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved)

    assert posted.status_code == 401, posted.text
    assert fetched.status_code == 401, fetched.text


async def test_revoked_key_is_rejected(client, db):
    doc, token = await _issue_key(db)
    await ApiKeyRepository(db).revoke(doc["_id"], _OWNER)

    resp = await client.post(_ANALYZE, json=_request(), headers=_bearer(token))

    assert resp.status_code == 401, resp.text


async def test_a_key_without_the_permission_is_rejected(client, db):
    _, token = await _issue_key(db, permissions=())

    resp = await client.post(_ANALYZE, json=_request(), headers=_bearer(token))

    assert resp.status_code == 403, resp.text


async def test_malformed_body_is_422_without_echoing_the_payload(client, db):
    _, token = await _issue_key(db)

    resp = await client.post(
        _ANALYZE,
        content=b'{"sboms": "not-a-list", "secret_marker": "' + _SECRET_MARKER.encode() + b'"}',
        headers={**_bearer(token), "Content-Type": "application/json"},
    )

    assert resp.status_code == 422, resp.text
    assert _SECRET_MARKER not in resp.text
    detail = resp.json()["detail"]
    assert {(error["type"], error["loc"][0]) for error in detail} == {
        ("list_type", "body"),
        ("extra_forbidden", "body"),
    }
    assert not [error for error in detail if "input" in error]
