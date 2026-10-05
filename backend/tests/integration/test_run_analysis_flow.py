"""run_analysis on a FakeDatabase: analyzer set, GitHub token, final status and what reaches notifications."""

import asyncio
import inspect
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.core.constants import (
    ANALYSIS_MAX_RETRIES,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_COMPLETED_WITH_ERRORS,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    WEBHOOK_EVENT_VULNERABILITY_FOUND,
)
from app.core.init_db import create_indexes
from app.models.project import Scan
from app.models.stats import Stats
from app.services.analysis import engine
from app.services.crypto_policy.seeder import seed_crypto_policies
from app.services.notifications import notification_service
from app.services.webhooks import webhook_service
from tests.helpers.analyzers import serve_analyzer
from tests.helpers.enrichment import Upstreams, serve_enrichment
from tests.helpers.sboms import store_sbom

_PROJECT_ID = "notify-project"
_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
_WORKER = "pod-a/worker-0"
_LAST_ATTEMPT = ANALYSIS_MAX_RETRIES - 1
_EMPTY_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}


async def _seed_scan(db) -> str:
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=[], status="processing", worker_id=_WORKER)
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    return scan.id


@pytest.fixture(autouse=True)
def _no_gridfs(monkeypatch):
    monkeypatch.setattr(engine, "AsyncIOMotorGridFSBucket", lambda _db: None)


@pytest_asyncio.fixture
async def stored_sbom(db, monkeypatch) -> dict:
    """A stored SBOM without components, for a run that has to reach its analyzers."""
    monkeypatch.setattr(engine, "AsyncIOMotorGridFSBucket", AsyncIOMotorGridFSBucket)
    await create_indexes(db)
    return await store_sbom(db, _EMPTY_SBOM)


@pytest.fixture
def notified(monkeypatch) -> list[Stats]:
    sent: list[Stats] = []

    async def _capture(project_id, scan_id, scan_doc, stats, status, error, failed, findings, analyzer_outcomes, db):
        sent.append(stats)

    monkeypatch.setattr(engine, "_send_integrations_and_notifications", _capture)
    return sent


@pytest.mark.asyncio
async def test_an_analysis_stamps_only_its_own_scan_and_notifies_its_own_stats(db, notified, monkeypatch):
    """Its one waiver pass is the analysed scan's: no project recalculation follows it."""
    await db.waivers.insert_one(
        {"_id": "w-1", "project_id": _PROJECT_ID, "finding_id": "x", "reason": "r", "created_by": "u"}
    )
    calls: list[str] = []

    async def _recalculate(project_id, *args, **kwargs):
        calls.append(project_id)
        return Stats(critical=7)

    monkeypatch.setattr("app.services.stats.recalculate_project_stats", _recalculate)

    assert await engine.run_analysis(await _seed_scan(db), [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert calls == []
    assert notified == [Stats()]


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_clean_re_analysis_clears_the_error_of_the_earlier_run(db, notified):
    scan_id = await _seed_scan(db)
    await db.scans.update_one({"_id": scan_id}, {"$set": {"error": "Analyzer failed: bearer", "completed_at": _T0}})

    assert await engine.run_analysis(scan_id, [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert "error" not in await db.scans.find_one({"_id": scan_id})


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_re_analysis_purges_the_row_of_an_analyzer_the_project_no_longer_runs(db, notified):
    scan_id = await _seed_scan(db)
    await db.analysis_results.insert_many(
        [
            {"scan_id": scan_id, "analyzer_name": "typosquatting", "result": {"typosquatting_issues": []}},
            {"scan_id": scan_id, "analyzer_name": "trufflehog", "result": {"findings": []}},
        ]
    )

    await engine.run_analysis(scan_id, [], ["trivy"], db, worker_id=_WORKER)

    names = set(await db.analysis_results.distinct("analyzer_name", {"scan_id": scan_id}))
    assert "typosquatting" not in names
    assert "trufflehog" in names


@pytest.mark.asyncio
async def test_a_scan_that_is_not_finalized_is_not_notified(db, notified, monkeypatch):
    async def _rescheduled(*args, **kwargs):
        return SCAN_STATUS_PENDING

    monkeypatch.setattr(engine, "_finalize_scan_and_project", _rescheduled)

    assert await engine.run_analysis(await _seed_scan(db), [], [], db, worker_id=_WORKER) == SCAN_STATUS_PENDING

    assert notified == []


def _gridfs_outage(monkeypatch, while_listing=lambda: asyncio.sleep(0)) -> dict:
    """GridFS holds none of the scan's SBOM files."""

    async def _no_stored_files(_filter):
        await while_listing()
        for stored in ():
            yield stored

    monkeypatch.setattr(engine, "AsyncIOMotorGridFSBucket", lambda _db: SimpleNamespace(find=_no_stored_files))
    file_id = "69d5332257c8763c8d8c82d7"
    return {"storage": "gridfs", "file_id": file_id, "type": "gridfs_reference", "gridfs_id": file_id}


@pytest.mark.asyncio
async def test_a_result_that_arrives_during_a_failing_run_reschedules_it_instead_of_failing_it(
    db, notified, monkeypatch
):
    ref = _gridfs_outage(monkeypatch)
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=[ref], status="processing", worker_id=_WORKER)
    await db.scans.insert_one(scan.model_dump(by_alias=True))

    async def _late_result(*_args):
        await db.scans.update_one({"_id": scan.id}, {"$set": {"last_result_at": datetime.now(timezone.utc)}})

    monkeypatch.setattr(engine, "_run_vuln_enrichments", _late_result)

    assert await engine.run_analysis(scan.id, [ref], [], db, worker_id=_WORKER) == SCAN_STATUS_PENDING

    assert (await db.scans.find_one({"_id": scan.id}))["status"] == SCAN_STATUS_PENDING
    assert notified == []


@pytest.mark.asyncio
async def test_a_run_that_lost_its_claim_keeps_the_findings_and_announces_nothing(db, notified):
    """Housekeeping handed the scan to another worker; that run owns its findings and its verdict."""
    scan_id = await _seed_scan(db)
    await db.scans.update_one({"_id": scan_id}, {"$set": {"worker_id": "pod-b/worker-0"}})
    await db.findings.insert_one({"_id": "f1", "scan_id": scan_id, "project_id": _PROJECT_ID})

    assert await engine.run_analysis(scan_id, [], [], db, worker_id=_WORKER) is None

    assert (await db.scans.find_one({"_id": scan_id}))["status"] == "processing"
    assert await db.findings.count_documents({"scan_id": scan_id}) == 1
    assert notified == []


@pytest.mark.asyncio
async def test_a_failing_notification_leaves_the_finalized_scan_completed(db, monkeypatch):
    monkeypatch.setattr(engine, "_send_integrations_and_notifications", AsyncMock(side_effect=RuntimeError("smtp")))
    scan_id = await _seed_scan(db)

    assert await engine.run_analysis(scan_id, [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert (await db.scans.find_one({"_id": scan_id}))["status"] == SCAN_STATUS_COMPLETED


@pytest.mark.asyncio
async def test_a_failing_head_waiver_bookkeeping_still_announces_the_completed_scan(db, notified, monkeypatch):
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": "p", "default_branch": "main"})
    restamp = engine.restamp_waivers

    async def _failing_on_head(finding_repo, waiver_repo, scan_id, waivers):
        if waiver_repo is not None:
            raise RuntimeError("waiver bookkeeping")
        return await restamp(finding_repo, waiver_repo, scan_id, waivers)

    monkeypatch.setattr(engine, "restamp_waivers", _failing_on_head)
    scan_id = await _seed_scan(db)

    assert await engine.run_analysis(scan_id, [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert (await db.scans.find_one({"_id": scan_id}))["status"] == SCAN_STATUS_COMPLETED
    assert notified == [Stats()]


@pytest.fixture
def enrichment_inputs(monkeypatch) -> dict:
    seen: dict = {}

    async def _capture(active_analyzers, *args):
        seen["analyzers"] = active_analyzers
        seen["github_token"] = args[-2]

    monkeypatch.setattr(engine, "_run_vuln_enrichments", _capture)
    return seen


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_cbom_scan_runs_the_crypto_analyzers_once_beside_the_configured_ones(db, notified, enrichment_inputs):
    await seed_crypto_policies(db)
    scan = Scan(
        project_id=_PROJECT_ID, branch="main", sbom_refs=[], status="processing", scan_type="cbom", worker_id=_WORKER
    )
    await db.scans.insert_one(scan.model_dump(by_alias=True))

    assert await engine.run_analysis(scan.id, [], ["osv"], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert enrichment_inputs["analyzers"] == ["osv"]
    rows = await db.analysis_results.find({"scan_id": scan.id}).to_list(None)
    assert sorted(row["analyzer_name"] for row in rows) == sorted(engine.CRYPTO_ANALYZERS)


@pytest.mark.asyncio
async def test_the_settings_github_token_is_used_before_any_instance_token(db, notified, enrichment_inputs):
    await db.system_settings.insert_one({"_id": "current", "github_token": "settings-token"})
    await db.github_instances.insert_one({"_id": "gh", "is_active": True, "access_token": "instance-token"})

    assert await engine.run_analysis(await _seed_scan(db), [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert enrichment_inputs["github_token"] == "settings-token"


_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
_GHES_ISSUER = "https://ghes.corp.example/_services/token"


def _github_instance(_id: str, created_at: datetime, **fields) -> dict:
    return {
        "_id": _id,
        "is_active": True,
        "url": _ACTIONS_ISSUER,
        "github_url": "https://github.com",
        "created_at": created_at,
        **fields,
    }


@pytest.mark.asyncio
async def test_without_a_settings_token_the_github_com_instance_token_is_used(db, notified, enrichment_inputs):
    await db.github_instances.insert_one(_github_instance("gh", _T0, access_token="instance-token"))

    assert await engine.run_analysis(await _seed_scan(db), [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert enrichment_inputs["github_token"] == "instance-token"


class _SettingsProbe:
    name = "maintainer_risk"

    def __init__(self) -> None:
        self.settings: dict = {}

    async def analyze(self, sbom, settings=None, parsed_components=None):
        self.settings = settings or {}
        return {"maintainer_issues": []}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_instance_token_reaches_the_analyzers_too(db, notified, enrichment_inputs, monkeypatch, stored_sbom):
    await db.github_instances.insert_one(_github_instance("gh", _T0, access_token="instance-token"))
    probe = serve_analyzer(monkeypatch, "maintainer_risk", _SettingsProbe())

    await engine.run_analysis(await _seed_scan(db), [stored_sbom], ["maintainer_risk"], db, worker_id=_WORKER)

    assert probe.settings["github_token"] == "instance-token"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ghes_fields",
    [
        pytest.param({"url": _GHES_ISSUER, "github_url": "https://ghes.corp.example"}, id="ghes-web-url"),
        pytest.param({"url": _GHES_ISSUER, "github_url": None}, id="ghes-without-web-url"),
        pytest.param({"url": _GHES_ISSUER}, id="ghes-web-url-absent"),
    ],
)
async def test_a_ghes_instance_token_is_never_sent_to_github_com(db, notified, enrichment_inputs, ghes_fields):
    await db.github_instances.insert_one(
        {"_id": "ghes", "is_active": True, "created_at": _T0, "access_token": "ghes-pat", **ghes_fields}
    )

    assert await engine.run_analysis(await _seed_scan(db), [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert enrichment_inputs["github_token"] is None


@pytest.mark.asyncio
async def test_the_github_com_token_is_chosen_over_an_older_ghes_instance(db, notified, enrichment_inputs):
    await db.github_instances.insert_one(
        _github_instance("ghes", _T0, url=_GHES_ISSUER, github_url="https://ghes.corp.example", access_token="ghes-pat")
    )
    await db.github_instances.insert_one(_github_instance("gh", _T0 + timedelta(days=1), access_token="gh-token"))

    assert await engine.run_analysis(await _seed_scan(db), [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert enrichment_inputs["github_token"] == "gh-token"


@pytest.mark.asyncio
async def test_of_several_github_com_instances_the_oldest_token_is_used(db, notified, enrichment_inputs):
    await db.github_instances.insert_one(_github_instance("newer", _T0 + timedelta(days=1), access_token="newer"))
    await db.github_instances.insert_one(_github_instance("older", _T0, access_token="older"))

    assert await engine.run_analysis(await _seed_scan(db), [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert enrichment_inputs["github_token"] == "older"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields",
    [
        pytest.param({"access_token": ""}, id="empty-token"),
        pytest.param({"access_token": "gh-token", "is_active": False}, id="inactive"),
    ],
)
async def test_without_a_usable_instance_token_ghsa_runs_unauthenticated(db, notified, enrichment_inputs, fields):
    await db.github_instances.insert_one(_github_instance("gh", _T0, **fields))

    assert await engine.run_analysis(await _seed_scan(db), [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert enrichment_inputs["github_token"] is None


@pytest.mark.asyncio
async def test_a_run_whose_sboms_all_fail_to_load_is_failed_and_announced_as_failed(db, notified, monkeypatch):
    ref = _gridfs_outage(monkeypatch)
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=[ref], status="processing", worker_id=_WORKER)
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    failure_notice = AsyncMock()
    monkeypatch.setattr(engine, "notify_analysis_failed", failure_notice)

    assert await engine.run_analysis(scan.id, [ref], [], db, worker_id=_WORKER) == SCAN_STATUS_FAILED

    stored = await db.scans.find_one({"_id": scan.id})
    assert (stored["status"], stored["error"]) == ("failed", "SBOM could not be loaded or parsed for analysis")
    assert notified == []
    failure_notice.assert_awaited_once_with(db, scan.id, _PROJECT_ID, "SBOM could not be loaded or parsed for analysis")


@pytest.mark.asyncio
async def test_a_run_whose_sbom_was_replaced_meanwhile_is_rescheduled_before_finalizing(db, notified):
    """The re-ingested SBOM is only analysed if this run, still on the old one, gives the scan back."""
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=[], status="processing", worker_id=_WORKER)
    await db.scans.insert_one(scan.model_dump(by_alias=True) | {"sbom_generation": 2})

    assert await engine.run_analysis(scan.id, [], [], db, worker_id=_WORKER, sbom_generation=1) == SCAN_STATUS_PENDING

    assert (await db.scans.find_one({"_id": scan.id}))["status"] == "pending"
    assert notified == []


@pytest.mark.asyncio
async def test_a_run_whose_old_sbom_failed_to_load_after_a_replace_is_rescheduled_not_failed(db, notified, monkeypatch):
    ref = _gridfs_outage(monkeypatch)
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=[ref], status="processing", worker_id=_WORKER)
    await db.scans.insert_one(scan.model_dump(by_alias=True) | {"sbom_generation": 2})

    assert (
        await engine.run_analysis(scan.id, [ref], [], db, worker_id=_WORKER, sbom_generation=1) == SCAN_STATUS_PENDING
    )

    assert (await db.scans.find_one({"_id": scan.id}))["status"] == "pending"


async def _finished_scan_with_an_analysis(db, ref: dict, retry_count: int) -> str:
    """A late result reopened a finished scan whose findings, results and inventory are stored."""
    scan = Scan(
        project_id=_PROJECT_ID,
        branch="main",
        sbom_refs=[ref],
        status="processing",
        worker_id=_WORKER,
        completed_at=_T0,
        retry_count=retry_count,
    )
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    await db.findings.insert_one({"_id": "f1", "scan_id": scan.id, "project_id": _PROJECT_ID})
    await db.analysis_results.insert_one({"_id": "r1", "scan_id": scan.id, "analyzer_name": "epss_kev"})
    await db.dependencies.insert_one({"_id": "d1", "scan_id": scan.id, "project_id": _PROJECT_ID})
    return scan.id


async def _assert_the_earlier_analysis_is_intact(db, scan_id: str) -> None:
    assert [f["_id"] async for f in db.findings.find({"scan_id": scan_id})] == ["f1"]
    assert await db.analysis_results.count_documents({"scan_id": scan_id}) == 1
    assert await db.dependencies.count_documents({"scan_id": scan_id}) == 1


@pytest.mark.asyncio
async def test_a_re_analysis_whose_sbom_fails_to_load_is_retried_with_the_earlier_analysis_in_place(
    db, notified, monkeypatch
):
    ref = _gridfs_outage(monkeypatch)
    scan_id = await _finished_scan_with_an_analysis(db, ref, retry_count=0)

    assert await engine.run_analysis(scan_id, [ref], [], db, worker_id=_WORKER) == SCAN_STATUS_PENDING

    stored = await db.scans.find_one({"_id": scan_id})
    assert (stored["status"], stored["retry_count"], stored["worker_id"]) == (SCAN_STATUS_PENDING, 1, None)
    await _assert_the_earlier_analysis_is_intact(db, scan_id)
    assert notified == []


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_worker_retries_an_unreadable_re_analysis_before_keeping_the_earlier_analysis(
    db, notified, running_worker, monkeypatch
):
    ref = _gridfs_outage(monkeypatch)
    scan_id = await _finished_scan_with_an_analysis(db, ref, retry_count=0)
    await db.scans.update_one({"_id": scan_id}, {"$set": {"status": SCAN_STATUS_PENDING, "worker_id": None}})
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": "proj", "active_analyzers": []})
    failure_notice = AsyncMock()
    monkeypatch.setattr("app.core.worker.notify_analysis_failed", failure_notice)

    await running_worker.add_job(scan_id)
    await asyncio.wait_for(running_worker.queue.join(), timeout=10)

    stored = await db.scans.find_one({"_id": scan_id})
    assert (stored["status"], stored["retry_count"]) == (SCAN_STATUS_COMPLETED_WITH_ERRORS, _LAST_ATTEMPT)
    await _assert_the_earlier_analysis_is_intact(db, scan_id)
    failure_notice.assert_not_called()


@pytest.mark.asyncio
async def test_a_re_analysis_whose_sbom_fails_to_load_on_its_last_attempt_keeps_the_earlier_analysis(
    db, notified, monkeypatch
):
    ref = _gridfs_outage(monkeypatch)
    scan_id = await _finished_scan_with_an_analysis(db, ref, retry_count=_LAST_ATTEMPT)

    assert await engine.run_analysis(scan_id, [ref], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED_WITH_ERRORS

    stored = await db.scans.find_one({"_id": scan_id})
    assert stored["status"] == SCAN_STATUS_COMPLETED_WITH_ERRORS
    assert "previous analysis" in stored["error"]
    await _assert_the_earlier_analysis_is_intact(db, scan_id)
    assert notified == []


@pytest.mark.asyncio
async def test_a_result_that_arrives_while_the_last_attempt_loads_its_sbom_reschedules_it(db, notified, monkeypatch):
    scan_id = ""

    async def _result_lands_while_the_files_are_listed():
        await db.scans.update_one({"_id": scan_id}, {"$set": {"last_result_at": datetime.now(timezone.utc)}})
        await asyncio.sleep(0.01)

    ref = _gridfs_outage(monkeypatch, _result_lands_while_the_files_are_listed)
    scan_id = await _finished_scan_with_an_analysis(db, ref, retry_count=_LAST_ATTEMPT)

    assert await engine.run_analysis(scan_id, [ref], [], db, worker_id=_WORKER) == SCAN_STATUS_PENDING

    assert (await db.scans.find_one({"_id": scan_id}))["status"] == SCAN_STATUS_PENDING
    await _assert_the_earlier_analysis_is_intact(db, scan_id)


@pytest.mark.asyncio
async def test_a_re_analysis_whose_sbom_was_replaced_meanwhile_is_rescheduled(db, notified, monkeypatch):
    ref = _gridfs_outage(monkeypatch)
    scan = Scan(
        project_id=_PROJECT_ID,
        branch="main",
        sbom_refs=[ref],
        status="processing",
        worker_id=_WORKER,
        completed_at=_T0,
        retry_count=_LAST_ATTEMPT,
    )
    await db.scans.insert_one(scan.model_dump(by_alias=True) | {"sbom_generation": 2})

    outcome = await engine.run_analysis(scan.id, [ref], [], db, worker_id=_WORKER, sbom_generation=1)

    assert outcome == SCAN_STATUS_PENDING
    assert (await db.scans.find_one({"_id": scan.id}))["status"] == "pending"


@pytest.mark.asyncio
async def test_a_re_analysis_that_keeps_the_earlier_analysis_heads_the_project_again(db, notified, monkeypatch):
    """While it was processing, an older build took the head; usable again, it takes the head back."""
    ref = _gridfs_outage(monkeypatch)
    await db.scans.insert_one(
        {"_id": "older", "project_id": _PROJECT_ID, "branch": "main", "status": "completed", "created_at": _T0}
        | {"sbom_refs": [ref], "stats": {}}
    )
    scan = Scan(
        project_id=_PROJECT_ID,
        branch="main",
        sbom_refs=[ref],
        status="processing",
        worker_id=_WORKER,
        created_at=_T0 + timedelta(hours=1),
        completed_at=_T0 + timedelta(hours=1),
        retry_count=_LAST_ATTEMPT,
    )
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": "proj", "latest_scan_id": "older"})

    await engine.run_analysis(scan.id, [ref], [], db, worker_id=_WORKER)

    assert (await db.projects.find_one({"_id": _PROJECT_ID}))["latest_scan_id"] == scan.id


@pytest.fixture
def handed_over(monkeypatch) -> AsyncMock:
    run = AsyncMock()
    monkeypatch.setattr(engine, "run_pending_reachability_for_scan", run, raising=False)
    return run


async def _callgraph_upload(db, scan_id: str) -> None:
    """What the upload endpoint leaves behind for a scan that is still being analysed."""
    await db.callgraphs.insert_one({"_id": "cg-1", "project_id": _PROJECT_ID, "scan_id": scan_id, "language": "python"})
    await db.scans.update_one({"_id": scan_id}, {"$set": {"reachability_pending": True}})


@pytest.mark.asyncio
async def test_a_callgraph_uploaded_during_the_run_is_applied_once_the_scan_is_final(
    db, notified, handed_over, monkeypatch
):
    scan_id = await _seed_scan(db)

    async def _upload_after_the_callgraph_lookup(*_args):
        await _callgraph_upload(db, scan_id)

    monkeypatch.setattr(engine, "_run_vuln_enrichments", _upload_after_the_callgraph_lookup)

    assert await engine.run_analysis(scan_id, [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    handed_over.assert_awaited_once_with(scan_id, _PROJECT_ID, db)


@pytest.mark.asyncio
async def test_a_failing_hand_over_is_logged_and_the_final_scan_is_still_announced(db, notified, handed_over, caplog):
    scan_id = await _seed_scan(db)
    await _callgraph_upload(db, scan_id)
    handed_over.side_effect = RuntimeError("mongo down")

    assert await engine.run_analysis(scan_id, [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert (await db.scans.find_one({"_id": scan_id}))["status"] == SCAN_STATUS_COMPLETED
    assert len(notified) == 1
    assert "mongo down" in caplog.text


@pytest.mark.asyncio
async def test_a_pending_marker_without_a_callgraph_is_left_for_the_upload(db, notified):
    scan_id = await _seed_scan(db)
    await db.scans.update_one({"_id": scan_id}, {"$set": {"reachability_pending": True}})

    assert await engine.run_analysis(scan_id, [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert (await db.scans.find_one({"_id": scan_id}))["reachability_pending"] is True


@pytest.mark.asyncio
async def test_a_re_analysis_that_keeps_the_earlier_analysis_applies_a_callgraph_uploaded_meanwhile(
    db, notified, handed_over, monkeypatch
):
    ref = _gridfs_outage(monkeypatch)
    scan = Scan(
        project_id=_PROJECT_ID,
        branch="main",
        sbom_refs=[ref],
        status="processing",
        worker_id=_WORKER,
        completed_at=_T0,
        retry_count=_LAST_ATTEMPT,
    )
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    await _callgraph_upload(db, scan.id)

    assert await engine.run_analysis(scan.id, [ref], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED_WITH_ERRORS

    handed_over.assert_awaited_once_with(scan.id, _PROJECT_ID, db)


@pytest.mark.asyncio
async def test_a_failing_hand_over_after_keeping_the_earlier_analysis_still_returns_the_outcome(
    db, notified, handed_over, monkeypatch, caplog
):
    ref = _gridfs_outage(monkeypatch)
    scan_id = await _finished_scan_with_an_analysis(db, ref, retry_count=_LAST_ATTEMPT)
    await _callgraph_upload(db, scan_id)
    handed_over.side_effect = RuntimeError("mongo down")

    assert await engine.run_analysis(scan_id, [ref], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED_WITH_ERRORS

    assert "mongo down" in caplog.text


_LOG4SHELL = "CVE-2021-44228"
_TEXT4SHELL_FINDING = "org.apache.commons:commons-text:1.9"


class _CannedReport:
    def __init__(self, report: dict) -> None:
        self.report = report

    async def analyze(self, sbom, settings=None, parsed_components=None):
        return self.report


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_vulnerability_alert_carries_the_enrichment_and_leaves_out_waived_findings(
    db, monkeypatch, fake_cache, stored_sbom
):
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": "proj", "default_branch": "main"})
    await db.waivers.insert_one(
        {"_id": "w-1", "project_id": _PROJECT_ID, "finding_id": _TEXT4SHELL_FINDING, "reason": "r", "created_by": "u"}
    )
    scan_id = await _seed_scan(db)
    trivy = {
        "Results": [
            {
                "Target": "app",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": _LOG4SHELL,
                        "PkgName": "org.apache.logging.log4j:log4j-core",
                        "InstalledVersion": "2.14.1",
                        "Severity": "CRITICAL",
                    },
                    {
                        "VulnerabilityID": "CVE-2022-42889",
                        "PkgName": "org.apache.commons:commons-text",
                        "InstalledVersion": "1.9",
                        "Severity": "CRITICAL",
                    },
                ],
            }
        ]
    }
    serve_analyzer(monkeypatch, "trivy", _CannedReport(trivy))
    serve_enrichment(monkeypatch, fake_cache, Upstreams(kev=(_LOG4SHELL,)))
    delivered = AsyncMock()
    monkeypatch.setattr(webhook_service, "trigger_webhooks", delivered)
    monkeypatch.setattr(notification_service, "notify_project_members", AsyncMock())

    await engine.run_analysis(scan_id, [stored_sbom], ["trivy", "epss_kev"], db, worker_id=_WORKER)

    alerts = {c.kwargs["event_type"]: c.kwargs["payload"] for c in delivered.await_args_list}
    vulnerabilities = alerts[WEBHOOK_EVENT_VULNERABILITY_FOUND]["vulnerabilities"]
    assert (vulnerabilities["kev"], [v["id"] for v in vulnerabilities["top"]]) == (1, [_LOG4SHELL])


_BASE_IMAGE_CVES = ("CVE-2024-0727", "CVE-2024-2511", "CVE-2024-4741")


def _base_image_reports() -> tuple[dict, dict]:
    """Trivy and grype on one OS package of a shared base image; grype keys each CVE's GHSA as its alias."""
    package = {"name": "libssl3", "version": "3.0.11-1~deb12u2"}
    trivy = {
        "Results": [
            {
                "Target": "debian 12",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": cve,
                        "PkgName": package["name"],
                        "InstalledVersion": package["version"],
                        "FixedVersion": "3.0.14-1~deb12u1",
                        "Severity": "MEDIUM",
                    }
                    for cve in _BASE_IMAGE_CVES
                ],
            }
        ]
    }
    grype = {
        "matches": [
            {
                "vulnerability": {"id": f"GHSA-{n:04x}-ssl3-deb1", "severity": "Medium"},
                "relatedVulnerabilities": [{"id": cve}],
                "artifact": package,
            }
            for n, cve in enumerate(_BASE_IMAGE_CVES)
        ]
    }
    return trivy, grype


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_sboms_sharing_a_base_image_retain_one_entry_per_advisory(
    db, notified, enrichment_inputs, monkeypatch, stored_sbom
):
    trivy, grype = _base_image_reports()
    serve_analyzer(monkeypatch, "trivy", _CannedReport(trivy))
    serve_analyzer(monkeypatch, "grype", _CannedReport(grype))
    retained: list[int] = []
    process_sbom = engine._process_sbom

    # Counted as each SBOM starts: what the earlier SBOMs left held while this one is loaded.
    async def _count_retained(*args, **kwargs):
        aggregator = inspect.signature(process_sbom).bind(*args, **kwargs).arguments["aggregator"]
        retained.append(sum(len(f.details.get("vulnerabilities", [])) for f in aggregator.findings.values()))
        return await process_sbom(*args, **kwargs)

    monkeypatch.setattr(engine, "_process_sbom", _count_retained)
    sboms = [stored_sbom, *[await store_sbom(db, _EMPTY_SBOM) for _ in range(2)]]

    await engine.run_analysis(await _seed_scan(db), sboms, ["grype", "trivy"], db, worker_id=_WORKER)

    assert retained == [0, len(_BASE_IMAGE_CVES), len(_BASE_IMAGE_CVES)]
