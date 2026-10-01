"""Every upload route reads its body one way: no size cap, auth before the first byte, one 422 shape."""

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.core.constants import API_KEY_SURFACE_ADHOC
from app.core.init_db import create_indexes
from app.core.permissions import Permissions
from app.core.security import get_password_hash
from app.models.project import Project
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.api_keys import ApiKeyRepository
from app.repositories.callgraphs import CallgraphRepository
from app.services.gridfs_maintenance import gridfs_ref_id, load_gridfs_json

_FIXTURES = Path(__file__).parents[1] / "fixtures"
_OLD_BODY_CAP = 25 * 1024 * 1024
_PROJECT_ID = "upload-uniformity"
_API_KEY_SECRET = "uniformity-secret"
_API_KEY = {"X-API-Key": f"{_PROJECT_ID}.{_API_KEY_SECRET}"}
_ADHOC_OWNER = "uniformity-adhoc"
_ADHOC_TOKEN = "dck_" + "u" * 64
_ADHOC_KEY = {"Authorization": f"Bearer {_ADHOC_TOKEN}"}
_RUN = {"pipeline_id": 4242, "commit_hash": "c" * 40, "branch": "main"}
_TRUNCATED_JSON = json.dumps({**_RUN, "findings": []}).encode()[:-3]


def _fixture(path: str) -> Any:
    return json.loads((_FIXTURES / path).read_text())


def _copies_past_the_old_cap(entries: Any) -> int:
    return _OLD_BODY_CAP // len(json.dumps(entries).encode()) + 1


def _syft_sbom() -> dict[str, Any]:
    sbom = _fixture("sbom/mono.syft.json")
    artifacts = sbom["artifacts"]
    sbom["artifacts"] = [
        {
            **artifact,
            "id": f"{artifact['id']}-{n}",
            "name": f"{artifact['name']}-{n}",
            "purl": artifact["purl"].replace(f"/{artifact['name']}@", f"/{artifact['name']}-{n}@"),
        }
        for n in range(_copies_past_the_old_cap(artifacts))
        for artifact in artifacts
    ]
    return {**_RUN, "sboms": [sbom]}


def _cbom() -> dict[str, Any]:
    cbom = _fixture("cbom/cyclonedx_1_6_with_crypto_assets.json")
    [asset] = [c for c in cbom["components"] if c["type"] == "cryptographic-asset"]
    cbom["components"] += [
        {**asset, "bom-ref": f"{asset['bom-ref']}-{n:06d}"} for n in range(_copies_past_the_old_cap(asset))
    ]
    return {**_RUN, "cbom": cbom}


def _in_service(path: str, n: int) -> str:
    return f"services/svc-{n:06d}/{path}"


def _trufflehog() -> dict[str, Any]:
    line = _fixture("secrets/trufflehog_v3_line.json")
    location = line["SourceMetadata"]["Data"]["Filesystem"]
    findings = [
        {**line, "SourceMetadata": {"Data": {"Filesystem": {**location, "file": _in_service(location["file"], n)}}}}
        for n in range(_copies_past_the_old_cap(line))
    ]
    return {**_RUN, "findings": findings}


def _opengrep() -> dict[str, Any]:
    result = _fixture("sast/opengrep_result.json")
    findings = [{**result, "path": _in_service(result["path"], n)} for n in range(_copies_past_the_old_cap(result))]
    return {**_RUN, "findings": findings}


def _kics() -> dict[str, Any]:
    report = _fixture("iac/kics_2.1.20_results.json")
    copies = _copies_past_the_old_cap([query["files"] for query in report["queries"]])
    queries = [
        {
            **query,
            "files": [
                {**file, "file_name": _in_service(file["file_name"], n)}
                for n in range(copies)
                for file in query["files"]
            ],
        }
        for query in report["queries"]
    ]
    return {**_RUN, "kics_version": report["kics_version"], "queries": queries}


def _bearer() -> dict[str, Any]:
    report = _fixture("sast/bearer_2.1.1_findings.json")
    copies = _copies_past_the_old_cap(report)
    findings = {
        severity: [
            {
                **finding,
                "filename": _in_service(finding["filename"], n),
                "full_filename": _in_service(finding["full_filename"], n),
                "fingerprint": f"{finding['fingerprint']}-{n}",
            }
            for n in range(copies)
            for finding in group
        ]
        for severity, group in report.items()
    }
    return {**_RUN, "findings": findings}


def _madge_imports(file_index: int) -> list[str]:
    return [
        f"../../node_modules/pkg-{(file_index * 10 + j) % 2_000:04d}/dist/esm/components/primitives/index.js"
        for j in range(10)
    ]


def _madge() -> dict[str, Any]:
    """madge `--json --include-npm` output of a monorepo whose source files import ten of 2 000 npm packages."""
    files = _copies_past_the_old_cap({"src/features/f000000/components/Widget.tsx": _madge_imports(0)})
    data = {f"src/features/f{i:06d}/components/Widget.tsx": _madge_imports(i) for i in range(files)}
    return {**_RUN, "format": "madge", "data": data}


async def _stored_sbom_artifacts(db, _response: dict[str, Any]) -> int:
    scan = await db.scans.find_one({"project_id": _PROJECT_ID})
    [ref] = scan["sbom_refs"]
    return len((await load_gridfs_json(AsyncIOMotorGridFSBucket(db), gridfs_ref_id(ref)))["artifacts"])


async def _stored_adhoc_artifacts(db, response: dict[str, Any]) -> int:
    job = await db.adhoc_jobs.find_one({"_id": response["job_id"]})
    return len((await load_gridfs_json(AsyncIOMotorGridFSBucket(db), job["input_file_id"]))["sboms"][0]["artifacts"])


async def _stored_crypto_assets(db, response: dict[str, Any]) -> int:
    return await db.crypto_assets.count_documents({"scan_id": response["scan_id"]})


def _stored_scanner_entries(count: Callable[[Any], int]) -> Callable[[Any, dict[str, Any]], Awaitable[int]]:
    async def stored(db, response: dict[str, Any]) -> int:
        [row] = await db.analysis_results.find({"scan_id": response["scan_id"]}).to_list(None)
        return count(await AnalysisResultRepository(db).load_result(row))

    return stored


async def _stored_callgraph_imports(db, _response: dict[str, Any]) -> int:
    repo = CallgraphRepository(db)
    graph = await repo.load_graph(await repo.collection.find_one({"project_id": _PROJECT_ID}))
    return sum(usage["import_count"] for usage in graph["module_usage"].values())


def _findings(result: Any) -> int:
    return len(result["findings"])


def _kics_files(result: Any) -> int:
    return sum(len(query["files"]) for query in result["queries"])


def _bearer_findings(result: Any) -> int:
    return sum(map(len, result["findings"].values()))


@dataclass(frozen=True)
class _Upload:
    route: str
    body: Callable[[], dict[str, Any]]
    sent: Callable[[dict[str, Any]], int]
    stored: Callable[[Any, dict[str, Any]], Awaitable[int]]
    chunked: bool = False
    auth: dict[str, str] = field(default_factory=lambda: _API_KEY)


_UPLOADS = [
    pytest.param(
        _Upload("/api/v1/ingest", _syft_sbom, lambda body: len(body["sboms"][0]["artifacts"]), _stored_sbom_artifacts),
        id="sbom",
    ),
    pytest.param(
        _Upload(
            "/api/v1/ingest/cbom",
            _cbom,
            lambda body: sum(c["type"] == "cryptographic-asset" for c in body["cbom"]["components"]),
            _stored_crypto_assets,
            chunked=True,
        ),
        id="cbom",
    ),
    pytest.param(
        _Upload("/api/v1/ingest/trufflehog", _trufflehog, _findings, _stored_scanner_entries(_findings)),
        id="trufflehog",
    ),
    pytest.param(
        _Upload("/api/v1/ingest/opengrep", _opengrep, _findings, _stored_scanner_entries(_findings)),
        id="opengrep",
    ),
    pytest.param(
        _Upload("/api/v1/ingest/kics", _kics, _kics_files, _stored_scanner_entries(_kics_files)),
        id="kics",
    ),
    pytest.param(
        _Upload("/api/v1/ingest/bearer", _bearer, _bearer_findings, _stored_scanner_entries(_bearer_findings)),
        id="bearer",
    ),
    pytest.param(
        _Upload(
            f"/api/v1/projects/{_PROJECT_ID}/callgraph",
            _madge,
            lambda body: sum(map(len, body["data"].values())),
            _stored_callgraph_imports,
        ),
        id="callgraph",
    ),
    pytest.param(
        _Upload(
            "/api/v1/analyze",
            lambda: {"sboms": _syft_sbom()["sboms"]},
            lambda body: len(body["sboms"][0]["artifacts"]),
            _stored_adhoc_artifacts,
            auth=_ADHOC_KEY,
        ),
        id="analyze",
    ),
]


@pytest_asyncio.fixture
async def app_client(db, monkeypatch) -> AsyncIterator[AsyncClient]:
    """The real app with only the database swapped: every route authenticates for real."""
    from app.api.deps import get_database
    from app.core.worker import AnalysisWorkerManager
    from app.main import app

    async def _test_database():
        return db

    await create_indexes(db)
    project = Project(id=_PROJECT_ID, name="upload-uniformity").model_dump(by_alias=True)
    await db.projects.insert_one({**project, "api_key_hash": get_password_hash(_API_KEY_SECRET)})
    monkeypatch.setattr("app.repositories.api_keys.generate_plaintext_token", lambda: _ADHOC_TOKEN)
    await ApiKeyRepository(db).create(_ADHOC_OWNER, "ci", [API_KEY_SURFACE_ADHOC], 30)
    await db.users.insert_one(
        {
            "_id": _ADHOC_OWNER,
            "username": _ADHOC_OWNER,
            "email": f"{_ADHOC_OWNER}@example.com",
            "permissions": [Permissions.ANALYZE_ADHOC],
        }
    )
    monkeypatch.setattr("app.api.v1.endpoints.analyze.worker_manager", AnalysisWorkerManager(num_workers=1))
    saved = dict(app.dependency_overrides)
    app.dependency_overrides.clear()
    app.dependency_overrides[get_database] = _test_database
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            yield client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved)


async def _chunks(body: bytes) -> AsyncIterator[bytes]:
    chunk_size = 1024 * 1024
    for start in range(0, len(body), chunk_size):
        yield body[start : start + chunk_size]


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("upload", _UPLOADS)
async def test_an_upload_past_every_old_limit_is_accepted(app_client, db, upload: _Upload):
    body = upload.body()
    raw = json.dumps(body).encode()
    assert len(raw) > _OLD_BODY_CAP

    resp = await app_client.post(
        upload.route,
        content=_chunks(raw) if upload.chunked else raw,
        headers={**upload.auth, "Content-Type": "application/json"},
    )

    assert resp.is_success, resp.text[:2000]
    assert await upload.stored(db, resp.json()) == upload.sent(body)


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("upload", _UPLOADS)
async def test_an_unauthenticated_upload_is_refused_before_its_body_is_read(app_client, upload: _Upload):
    body_read = False

    async def _watched_body() -> AsyncIterator[bytes]:
        nonlocal body_read
        body_read = True
        yield _TRUNCATED_JSON

    resp = await app_client.post(upload.route, content=_watched_body(), headers={"Content-Type": "application/json"})

    assert resp.status_code == 401, resp.text
    assert not body_read


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("upload", _UPLOADS)
async def test_malformed_json_is_422(app_client, upload: _Upload):
    resp = await app_client.post(
        upload.route, content=_TRUNCATED_JSON, headers={**upload.auth, "Content-Type": "application/json"}
    )

    assert resp.status_code == 422, resp.text
    [error] = resp.json()["detail"]
    assert (error["type"], error["loc"][0]) == ("json_invalid", "body")
    assert "input" not in error
