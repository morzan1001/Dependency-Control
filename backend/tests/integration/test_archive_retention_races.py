"""Retention, archive and restore running at the same time on several pods never lose a scan."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from prometheus_client import REGISTRY
from pymongo.errors import AutoReconnect, NetworkTimeout

from app.api.v1.endpoints import callgraph, cbom_ingest
from app.core import housekeeping
from app.core.constants import ARCHIVE_BATCH_SIZE, HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS, RESCAN_HISTORY_RUNS
from app.core.housekeeping import _archive_scans_and_delete, _expire_group, _run_retention
from app.models.release import Release
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.archive_metadata import ArchiveMetadataRepository
from app.repositories.distributed_locks import DistributedLocksRepository
from app.repositories.findings import FindingRepository
from app.repositories.releases import ReleaseRepository
from app.repositories.scans import ScanRepository
from app.services import archive, stats
from app.services.analysis.stats import _STATS_CURSOR_HINT
from app.services.archive import restore_scan

_NOW = datetime.now(timezone.utc)
_PROJECT_ID = "test-project-id"
_RUN = {"pipeline_id": 515151, "commit_hash": "e" * 40, "branch": "main"}
_CALLGRAPH = {"format": "generic", "language": "python", "data": {"imports": [], "analyzed_modules": []}}
_SECRET = json.loads((Path(__file__).parents[1] / "fixtures/secrets/trufflehog_v3_line.json").read_text())
_VULNERABILITY = {
    "_id": "vulnerability",
    "id": "CVE-2024-0001",
    "finding_id": "CVE-2024-0001",
    "project_id": _PROJECT_ID,
    "type": "vulnerability",
    "severity": "HIGH",
    "component": "requests",
    "description": "CVE-2024-0001 in requests",
    "scanners": ["osv"],
    "details": {},
}
_CBOM = json.loads((Path(__file__).parents[1] / "fixtures/cbom/legacy_crypto_mixed.json").read_text())


def _scan(scan_id: str, age_days: float, **fields) -> dict:
    return {
        "_id": scan_id,
        "project_id": _PROJECT_ID,
        "branch": "main",
        "status": "completed",
        "created_at": _NOW - timedelta(days=age_days),
        "sbom_refs": [],
        **fields,
    }


async def _remaining(db) -> set[str]:
    return {doc["_id"] async for doc in db.scans.find({}, {"_id": 1})}


async def _kill_idle_scan_cursors(db) -> None:
    idle = {"type": "idleCursor", "ns": f"{db.name}.scans"}
    ops = await db.client.admin.aggregate([{"$currentOp": {"idleCursors": True}}, {"$match": idle}]).to_list(None)
    if ops:
        await db.command("killCursors", "scans", cursors=[op["cursor"]["cursorId"] for op in ops])


async def _ingest(client, headers, scanner: str, findings: list) -> str:
    resp = await client.post(f"/api/v1/ingest/{scanner}", json={**_RUN, "findings": findings}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["scan_id"]


async def _analysed_run(client, db, headers) -> str:
    """A CI run whose secret scan came in and was analysed."""
    scan_id = await _ingest(client, headers, "trufflehog", [_SECRET])
    await db.scans.update_one({"_id": scan_id}, {"$set": {"status": "completed"}})
    return scan_id


async def _retried_job(client, db, headers) -> None:
    """A retried CI job of the run posts again, and the analysis it triggers finishes."""
    scan_id = await _ingest(client, headers, "opengrep", [])
    await db.scans.update_one({"_id": scan_id}, {"$set": {"status": "completed"}})


async def _cbom_job(client, headers) -> None:
    resp = await client.post("/api/v1/ingest/cbom", json={**_RUN, "cbom": _CBOM}, headers=headers)
    assert resp.status_code == 202, resp.text


async def _callgraph_upload(client, headers, project) -> None:
    with patch("app.api.deps._authenticate_ci", new_callable=AsyncMock, return_value=project):
        resp = await client.post(
            f"/api/v1/projects/{_PROJECT_ID}/callgraph", json={**_RUN, **_CALLGRAPH}, headers=headers
        )
    assert resp.status_code == 200, resp.text


def _interleave(monkeypatch, owner, name: str, write: Callable[[], Awaitable[object]], *, after: bool = False) -> None:
    """Run write once, right before (or after) the next call of owner.name."""
    real = getattr(owner, name)

    async def call(*args, **kwargs):
        monkeypatch.setattr(owner, name, real)
        if not after:
            await write()
        result = await real(*args, **kwargs)
        if after:
            await write()
        return result

    monkeypatch.setattr(owner, name, call)


async def _paused_before(monkeypatch, owner, name: str, post: Awaitable[None]) -> Callable[[], Awaitable[None]]:
    """Start post, pause it right before its call of owner.name, and return what lets it finish."""
    paused, resume = asyncio.Event(), asyncio.Event()

    async def pause() -> None:
        paused.set()
        await resume.wait()

    _interleave(monkeypatch, owner, name, pause)
    task = asyncio.create_task(post)
    await asyncio.wait([asyncio.ensure_future(paused.wait()), task], return_when=asyncio.FIRST_COMPLETED)
    if task.done():
        task.result()

    async def finish() -> None:
        resume.set()
        await task

    return finish


def _delete_during(monkeypatch, post: Callable[[], Awaitable[None]], owner, name: str, *, after: bool = False) -> None:
    """The batch delete runs inside post, right before (or after) its call of owner.name."""
    real_delete = housekeeping._delete_expirable

    async def post_around_the_delete(*args):
        _interleave(monkeypatch, owner, name, lambda: real_delete(*args), after=after)
        await post()

    monkeypatch.setattr(housekeeping, "_delete_expirable", post_around_the_delete)


def _archive_failures(reason: str) -> float:
    return REGISTRY.get_sample_value("archive_failures_total", {"operation": "archive", "reason": reason}) or 0.0


async def _analyzers(db, scan_id: str) -> set[str]:
    return {row["analyzer_name"] async for row in db.analysis_results.find({"scan_id": scan_id})}


@pytest.fixture
def retention_archives(archive_env, monkeypatch):
    monkeypatch.setattr(housekeeping, "is_archive_enabled", lambda: True)
    return archive_env


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_second_pod_skips_retention_while_the_first_still_runs_it(db, retention_archives, monkeypatch):
    await db.projects.insert_one(
        {"_id": _PROJECT_ID, "name": "p", "retention_days": 90, "retention_action": "archive", "default_branch": "main"}
    )
    await db.scans.insert_many([_scan("old", 200), _scan("head", 1)])
    first_pod_mid_batch, finish_first_batch = asyncio.Event(), asyncio.Event()
    archived: list[str] = []
    real_archive_scan = archive.archive_scan

    async def archive_scan(db_, scan_id):
        archived.append(scan_id)
        if len(archived) == 1:
            first_pod_mid_batch.set()
            await finish_first_batch.wait()
        return await real_archive_scan(db_, scan_id)

    monkeypatch.setattr(archive, "archive_scan", archive_scan)
    monkeypatch.setattr(housekeeping, "_RETENTION_LOCK_TTL_SECONDS", 0.3)
    first_pod = asyncio.create_task(_run_retention(db))
    await first_pod_mid_batch.wait()
    await asyncio.sleep(0.9)
    await _run_retention(db)
    finish_first_batch.set()
    await first_pod

    assert archived == ["old"]
    assert await _remaining(db) == {"head"}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_only_a_finished_retention_run_keeps_the_other_pods_out(db, monkeypatch):
    runs = 0
    first_run_started = asyncio.Event()

    async def expire_scans(_db):
        nonlocal runs
        runs += 1
        first_run_started.set()
        if runs == 1:
            await asyncio.Event().wait()

    monkeypatch.setattr(housekeeping, "_expire_scans", expire_scans)
    rolled_out_pod = asyncio.create_task(_run_retention(db))
    await first_run_started.wait()
    rolled_out_pod.cancel()
    with pytest.raises(asyncio.CancelledError):
        await rolled_out_pod
    await _run_retention(db)
    await _run_retention(db)

    assert runs == 2
    lock = await db.distributed_locks.find_one({"_id": "retention"})
    assert lock["expires_at"] - lock["acquired_at"] >= timedelta(hours=HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS)


class _StopLoop(Exception):
    """Ends the endless housekeeping loop."""


@pytest.mark.asyncio
async def test_every_housekeeping_pass_bids_for_retention(monkeypatch):
    async def noop(*_args, **_kwargs):
        return None

    for task in (
        "recover_stuck_scans",
        "check_scheduled_rescans",
        "get_database",
        "update_db_stats",
        "update_archive_stats",
        "update_cache_stats",
        "run_waiver_recalc",
        "reconcile_release_flags",
        "prune_old_audit_entries",
        "sweep_expired_compliance_reports",
        "_reap_orphan_s3_objects",
        "_reap_orphan_callgraphs",
        "reap_orphan_gridfs_files",
        "sync_branch_status",
        "reconcile_update_frequency_ledger",
    ):
        monkeypatch.setattr(housekeeping, task, noop)
    bid = AsyncMock(side_effect=[AutoReconnect("primary stepped down"), None])
    expire = AsyncMock()
    monkeypatch.setattr(housekeeping, "_run_retention", bid)
    monkeypatch.setattr(housekeeping, "_expire_scans", expire)
    monkeypatch.setattr(housekeeping, "asyncio", SimpleNamespace(sleep=AsyncMock(side_effect=[None, _StopLoop])))
    with pytest.raises(_StopLoop):
        await housekeeping.housekeeping_loop()

    assert (bid.await_count, expire.await_count) == (2, 0)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_rescan_history_cap_whose_build_cursor_died_still_caps_every_build(db, monkeypatch):
    builds = 2 * ARCHIVE_BATCH_SIZE + 2
    await db.scans.insert_many(
        _scan(f"rescan-{build}-{age}", age, original_scan_id=f"build-{build}", is_rescan=True)
        for build in range(builds)
        for age in range(RESCAN_HISTORY_RUNS + 1)
    )
    _interleave(monkeypatch, housekeeping, "_handle_retention_action", partial(_kill_idle_scan_cursors, db))
    await _expire_group(db, 90, {}, "delete", "retention")

    assert await db.scans.count_documents({}) == builds * RESCAN_HISTORY_RUNS


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_rescan_history_cap_whose_run_cursor_died_still_caps_the_build(db, monkeypatch):
    runs = 4 * ARCHIVE_BATCH_SIZE
    await db.scans.insert_many(
        _scan(f"rescan-{run}", run / 100, original_scan_id="build", is_rescan=True) for run in range(runs)
    )
    _interleave(monkeypatch, housekeeping, "_handle_retention_action", partial(_kill_idle_scan_cursors, db))
    await _expire_group(db, 90, {}, "delete", "retention")

    assert await db.scans.count_documents({}) == RESCAN_HISTORY_RUNS


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("action", ["delete", "archive"])
@pytest.mark.parametrize("change", [{"pinned": True}, {"status": "pending"}], ids=["pinned", "reopened"])
async def test_a_scan_pinned_or_reopened_after_retention_read_it_is_kept(
    db, retention_archives, monkeypatch, action, change
):
    await db.scans.insert_one(_scan("x", 200))
    real_unreferenced = housekeeping._unreferenced

    async def change_after_the_read(db_, scans):
        unreferenced = await real_unreferenced(db_, scans)
        await db_.scans.update_one({"_id": "x"}, {"$set": change})
        return unreferenced

    monkeypatch.setattr(housekeeping, "_unreferenced", change_after_the_read)
    await _expire_group(db, 90, {}, action, "retention")

    assert await _remaining(db) == {"x"}
    assert await db.archive_metadata.count_documents({}) == 0


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_scan_released_while_its_batch_was_archived_is_kept(db, retention_archives, monkeypatch):
    await db.scans.insert_many([_scan("x", 200), _scan("y", 200)])
    release = Release(project_id=_PROJECT_ID, environment="prod", scan_id="x", released_at=_NOW)
    _interleave(monkeypatch, archive, "_save_archive_metadata", lambda: ReleaseRepository(db).record(release))
    await _archive_scans_and_delete(db, ["x", "y"], "retention")

    assert await _remaining(db) == {"x"}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_scan_restored_while_another_pod_still_archives_its_batch_is_kept(db, retention_archives, monkeypatch):
    await db.scans.insert_many([_scan("x", 200), _scan("y", 200)])
    real_archive_scan = archive.archive_scan
    interleaved: list[str] = []

    async def second_pod_archives_x_and_a_user_restores_it(db_, scan_id):
        if scan_id == "y" and not interleaved:
            interleaved.append(scan_id)
            await _archive_scans_and_delete(db_, ["x"], "second pod")
            assert await restore_scan(db_, "x") is not None
        return await real_archive_scan(db_, scan_id)

    monkeypatch.setattr(archive, "archive_scan", second_pod_archives_x_and_a_user_restores_it)
    await _archive_scans_and_delete(db, ["x", "y"], "first pod")

    restored = await db.scans.find_one({"_id": "x"})
    assert restored is not None
    assert restored["pinned"] is True


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_callgraph_posted_while_its_run_was_archived_is_kept(
    client, db, api_key_headers, _project, retention_archives, monkeypatch
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    upload = _callgraph_upload(client, api_key_headers, _project)
    finish_the_upload = await _paused_before(monkeypatch, callgraph, "upload_gridfs_json", upload)
    _interleave(monkeypatch, archive, "_save_archive_metadata", finish_the_upload)
    await _archive_scans_and_delete(db, [scan_id], "retention")

    assert await db.callgraphs.count_documents({"scan_id": scan_id}) == 1


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_reachability_verdicts_of_a_pass_that_outlived_its_lock_during_the_archive_are_kept(
    client, db, api_key_headers, _project, retention_archives, monkeypatch
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    await db.findings.insert_one(_VULNERABILITY | {"scan_id": scan_id})
    # Its stats refresh finds the lock taken, so only the touch dates the verdicts.
    monkeypatch.setattr(stats, "_acquire_with_backoff", AsyncMock(return_value=False))
    upload = _callgraph_upload(client, api_key_headers, _project)
    finish_the_upload = await _paused_before(monkeypatch, FindingRepository, "set_fields", upload)
    await db.distributed_locks.delete_one({"_id": f"reachability:{scan_id}"})
    _interleave(monkeypatch, housekeeping, "_delete_expirable", finish_the_upload)
    await _archive_scans_and_delete(db, [scan_id], "first pass")
    await _archive_scans_and_delete(db, [scan_id], "second pass")

    assert await restore_scan(db, scan_id) is not None
    assert (await db.findings.find_one({"scan_id": scan_id}))["details"].get("reachability")


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_reachability_stats_of_a_pass_that_outlived_its_lock_during_the_archive_are_kept(
    client, db, api_key_headers, _project, retention_archives, monkeypatch
):
    await db.findings.create_index(_STATS_CURSOR_HINT)
    scan_id = await _analysed_run(client, db, api_key_headers)
    await db.findings.insert_one(_VULNERABILITY | {"scan_id": scan_id})
    upload = _callgraph_upload(client, api_key_headers, _project)
    finish_the_upload = await _paused_before(monkeypatch, stats, "refresh_scan_stats", upload)
    await db.distributed_locks.delete_one({"_id": f"reachability:{scan_id}"})
    _interleave(monkeypatch, housekeeping, "_delete_expirable", finish_the_upload)
    await _archive_scans_and_delete(db, [scan_id], "first pass")
    await _archive_scans_and_delete(db, [scan_id], "second pass")

    assert await restore_scan(db, scan_id) is not None
    restored = await db.scans.find_one({"_id": scan_id}, {"_id": 0, "stats.reachability.unknown_count": 1})
    assert restored == {"stats": {"reachability": {"unknown_count": 1}}}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_run_whose_reachability_pass_is_under_way_is_left_to_the_next_pass(
    client, db, api_key_headers, _project, retention_archives, monkeypatch
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    await db.findings.insert_one(_VULNERABILITY | {"scan_id": scan_id})
    upload = _callgraph_upload(client, api_key_headers, _project)
    finish_the_upload = await _paused_before(monkeypatch, FindingRepository, "set_fields", upload)
    await _archive_scans_and_delete(db, [scan_id], "first pass")
    await finish_the_upload()
    await _archive_scans_and_delete(db, [scan_id], "second pass")

    assert await restore_scan(db, scan_id) is not None
    assert (await db.findings.find_one({"scan_id": scan_id}))["details"].get("reachability")


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_reachability_pass_that_claims_as_its_run_is_read_leaves_it_to_the_next_pass(
    db, retention_archives, monkeypatch
):
    await db.scans.insert_one(_scan("x", 200, reachability_pending=True))
    collection = type(db.scans)
    real_find_one = collection.find_one

    async def lock_and_claim_first(self, *args, **kwargs):
        if self.name == "scans":
            monkeypatch.setattr(collection, "find_one", real_find_one)
            assert await DistributedLocksRepository(db).acquire_lock("reachability:x", "pass", 600)
            await db.scans.update_one({"_id": "x"}, {"$unset": {"reachability_pending": ""}})
        return await real_find_one(self, *args, **kwargs)

    monkeypatch.setattr(collection, "find_one", lock_and_claim_first)
    await _archive_scans_and_delete(db, ["x"], "retention")

    assert await _remaining(db) == {"x"}
    assert await db.archive_metadata.count_documents({}) == 0


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_retried_job_whose_ingest_meets_the_batch_delete_keeps_its_result(
    client, db, api_key_headers, retention_archives, monkeypatch
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    retried_job = partial(_retried_job, client, db, api_key_headers)
    _delete_during(monkeypatch, retried_job, AnalysisResultRepository, "save_result", after=True)
    await _archive_scans_and_delete(db, [scan_id], "retention")

    assert "opengrep" in await _analyzers(db, scan_id)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_retried_cbom_job_whose_ingest_meets_the_batch_delete_keeps_its_assets(
    client, db, api_key_headers, retention_archives, monkeypatch
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    cbom_job = partial(_cbom_job, client, api_key_headers)
    _delete_during(monkeypatch, cbom_job, cbom_ingest, "_store_crypto_assets", after=True)
    await _archive_scans_and_delete(db, [scan_id], "retention")

    assert await db.crypto_assets.count_documents({"scan_id": scan_id}) == 3


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_callgraph_whose_upload_meets_the_batch_delete_is_kept(
    client, db, api_key_headers, _project, retention_archives, monkeypatch
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    _delete_during(
        monkeypatch, partial(_callgraph_upload, client, api_key_headers, _project), ScanRepository, "distinct"
    )
    await _archive_scans_and_delete(db, [scan_id], "retention")

    assert await db.callgraphs.count_documents({"scan_id": scan_id}) == 1


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_archive_whose_metadata_insert_landed_but_timed_out_stays_restorable(db, retention_archives):
    await db.scans.insert_one(_scan("x", 200))
    real_create = ArchiveMetadataRepository.create

    async def create_then_time_out(self, metadata):
        await real_create(self, metadata)
        raise NetworkTimeout("no reply to the insert")

    with patch.object(ArchiveMetadataRepository, "create", create_then_time_out):
        await _archive_scans_and_delete(db, ["x"], "first pass")
    await _archive_scans_and_delete(db, ["x"], "second pass")

    assert await _remaining(db) == set()
    assert await restore_scan(db, "x") is not None


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_restore_whose_metadata_delete_failed_leaves_the_archive_restorable(
    db, retention_archives, monkeypatch
):
    await db.scans.insert_many([_scan("x", 200), _scan("y", 200)])
    await _archive_scans_and_delete(db, ["x"], "first pass")
    with patch.object(
        ArchiveMetadataRepository, "delete_by_scan_id", AsyncMock(side_effect=AutoReconnect("primary stepped down"))
    ):
        assert await restore_scan(db, "x") is not None
    await db.scans.update_one({"_id": "x"}, {"$set": {"pinned": False}})
    real_archive_scan = archive.archive_scan

    async def another_pod_reaps_stale_metadata_during_the_batch(db_, scan_id):
        if scan_id == "y":
            await housekeeping._reap_stale_metadata(db_)
        return await real_archive_scan(db_, scan_id)

    monkeypatch.setattr(archive, "archive_scan", another_pod_reaps_stale_metadata_during_the_batch)
    await _archive_scans_and_delete(db, ["x", "y"], "second pass")
    monkeypatch.setattr(archive, "archive_scan", real_archive_scan)
    await _archive_scans_and_delete(db, ["x"], "third pass")

    assert await _remaining(db) == set()
    assert await restore_scan(db, "x") is not None


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("during_the_archive", [False, True], ids=["recreated-after-it", "written-during-it"])
async def test_a_run_ingested_into_after_its_archive_began_is_not_deleted_for_that_archive(
    client, db, api_key_headers, retention_archives, monkeypatch, during_the_archive
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    retried_job = partial(_retried_job, client, db, api_key_headers)
    if during_the_archive:
        _interleave(monkeypatch, archive, "_load_scan_for_archive", retried_job, after=True)
        # The pass that ran this archive died before its delete.
        await archive.archive_scan(db, scan_id)
    else:
        _interleave(monkeypatch, housekeeping, "delete_scans_and_related_data", retried_job, after=True)
        await _archive_scans_and_delete(db, [scan_id], "first pass")
    kept_both = _archive_failures("written_since_archive")
    await _archive_scans_and_delete(db, [scan_id], "second pass")

    assert "opengrep" in await _analyzers(db, scan_id)
    assert _archive_failures("written_since_archive") == kept_both + 1


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_run_written_to_during_its_batch_is_archived_afresh_by_the_next_pass(
    client, db, api_key_headers, retention_archives, monkeypatch
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    _interleave(monkeypatch, archive, "_save_archive_metadata", lambda: _retried_job(client, db, api_key_headers))
    await _archive_scans_and_delete(db, [scan_id], "first pass")
    await _archive_scans_and_delete(db, [scan_id], "second pass")

    assert await _remaining(db) == set()
    assert await restore_scan(db, scan_id) is not None
    assert await _analyzers(db, scan_id) == {"trufflehog", "opengrep"}


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("other_archives_first", [True, False], ids=["other-archives-first", "this-archives-first"])
async def test_a_run_written_to_while_a_second_runner_overlaps_its_batch_stays_restorable(
    client, db, api_key_headers, retention_archives, monkeypatch, other_archives_first
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    other_holds_its_delete, this_runner_done = asyncio.Event(), asyncio.Event()
    other: list[asyncio.Task] = []
    real_delete = housekeeping._delete_expirable

    async def start_the_other_runner() -> None:
        other.append(asyncio.create_task(_archive_scans_and_delete(db, [scan_id], "other runner")))
        await other_holds_its_delete.wait()

    async def delete_expirable(db_, scans, label):
        if label == "other runner":
            other_holds_its_delete.set()
            await this_runner_done.wait()
        elif not other:
            await start_the_other_runner()
        return await real_delete(db_, scans, label)

    async def write_then_overlap() -> None:
        await _retried_job(client, db, api_key_headers)
        if other_archives_first:
            await start_the_other_runner()

    monkeypatch.setattr(housekeeping, "_delete_expirable", delete_expirable)
    _interleave(monkeypatch, archive, "archive_scan", write_then_overlap)
    await _archive_scans_and_delete(db, [scan_id], "this runner")
    this_runner_done.set()
    await other[0]

    assert await _remaining(db) == set()
    assert await restore_scan(db, scan_id) is not None
    assert await _analyzers(db, scan_id) == {"trufflehog", "opengrep"}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_run_written_to_during_a_batch_that_reused_its_older_archive_keeps_that_archive(
    client, db, api_key_headers, retention_archives, monkeypatch
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    # A pass archived the run and died inside its cascade, leaving that bundle the only copy of the result.
    await archive.archive_scan(db, scan_id)
    await db.analysis_results.delete_many({"scan_id": scan_id})
    _interleave(
        monkeypatch, archive, "_load_scan_for_archive", partial(_retried_job, client, db, api_key_headers), after=True
    )
    await _archive_scans_and_delete(db, [scan_id], "second pass")

    assert await db.archive_metadata.count_documents({"scan_id": scan_id}) == 1


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("header_keys_scan", [True, False], ids=["header-with-its-scan", "header-without-a-scan"])
async def test_a_restore_beaten_to_the_scan_by_an_ingest_leaves_the_ingested_scan_alone(
    client, db, api_key_headers, retention_archives, monkeypatch, header_keys_scan
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    await _archive_scans_and_delete(db, [scan_id], "retention")
    real_header = archive._handle_header_event

    async def retry_before_the_header_insert(db_, data, collections_restored):
        await _retried_job(client, db, api_key_headers)
        if not header_keys_scan:
            data.pop("scan")
        return await real_header(db_, data, collections_restored)

    monkeypatch.setattr(archive, "_handle_header_event", retry_before_the_header_insert)

    assert await restore_scan(db, scan_id) is None
    assert await _remaining(db) == {scan_id}
    assert await _analyzers(db, scan_id) == {"opengrep"}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_archive_whose_lock_another_pod_took_over_during_the_upload_gives_the_scan_up(
    db, retention_archives, monkeypatch
):
    await db.scans.insert_one(_scan("x", 200))
    real_upload = archive.upload_stream

    async def upload_then_lose_the_lock(*args, **kwargs):
        total = await real_upload(*args, **kwargs)
        await db.distributed_locks.update_one({"_id": "archive:x"}, {"$set": {"expires_at": _NOW}})
        assert await DistributedLocksRepository(db).acquire_lock("archive:x", "other-pod", ttl_seconds=600)
        return total

    monkeypatch.setattr(archive, "upload_stream", upload_then_lose_the_lock)
    await _archive_scans_and_delete(db, ["x"], "retention")

    assert await _remaining(db) == {"x"}
    assert await db.archive_metadata.count_documents({}) == 0
    assert retention_archives.objects == {}
    assert (await db.distributed_locks.find_one({"_id": "archive:x"}))["holder"] == "other-pod"


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_archive_that_cannot_confirm_its_lock_after_the_upload_drops_it(db, retention_archives, monkeypatch):
    await db.scans.insert_one(_scan("x", 200))
    renew = AsyncMock(side_effect=AutoReconnect("primary stepped down"))
    monkeypatch.setattr(DistributedLocksRepository, "renew_lock", renew)
    failures = _archive_failures("unknown")

    assert await archive.archive_scan(db, "x") is None
    assert retention_archives.objects == {}
    assert _archive_failures("unknown") == failures + 1


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_archive_that_outlasts_its_lock_ttl_still_lands(db, retention_archives, monkeypatch):
    await db.scans.insert_one(_scan("x", 200))
    real_upload = archive.upload_stream

    async def slow_upload_while_the_ttl_monitor_runs(*args, **kwargs):
        await asyncio.sleep(0.9)
        await db.distributed_locks.delete_many({"expires_at": {"$lt": datetime.now(timezone.utc)}})
        return await real_upload(*args, **kwargs)

    monkeypatch.setattr(archive, "_ARCHIVE_LOCK_TTL_SECONDS", 0.3)
    monkeypatch.setattr(archive, "upload_stream", slow_upload_while_the_ttl_monitor_runs)
    await _archive_scans_and_delete(db, ["x"], "retention")

    assert await _remaining(db) == set()
    assert await db.archive_metadata.count_documents({}) == 1


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("release_fails", [False, True], ids=["clean-stop", "cancel-swallowed-by-a-failed-release"])
async def test_a_retention_run_whose_lock_an_operator_took_over_stops_archiving(
    db, retention_archives, monkeypatch, release_fails
):
    await db.projects.insert_one(
        {"_id": _PROJECT_ID, "name": "p", "retention_days": 90, "retention_action": "archive", "default_branch": "main"}
    )
    await db.scans.insert_many([_scan("old1", 300), _scan("old2", 200), _scan("head", 1)])
    operator_lock = {"holder": "operator", "expires_at": (_NOW + timedelta(hours=24)).replace(microsecond=0)}
    real_upload, real_release = archive.upload_stream, DistributedLocksRepository.release_lock
    uploads: list[str] = []

    async def slow_upload(*args, **kwargs):
        uploads.append(args[0])
        if len(uploads) == 1:
            await db.distributed_locks.replace_one({"_id": "retention"}, operator_lock)
        await asyncio.sleep(1)
        return await real_upload(*args, **kwargs)

    async def release_lock(self, lock_name, holder_id):
        if release_fails and lock_name == "archive:old1":
            raise AutoReconnect("connection reset while releasing")
        return await real_release(self, lock_name, holder_id)

    monkeypatch.setattr(housekeeping, "_RETENTION_LOCK_TTL_SECONDS", 0.3)
    monkeypatch.setattr(archive, "upload_stream", slow_upload)
    monkeypatch.setattr(DistributedLocksRepository, "release_lock", release_lock)
    await _run_retention(db)

    assert await _remaining(db) == {"old1", "old2", "head"}
    assert await db.archive_metadata.count_documents({}) == 0
    assert await db.distributed_locks.find_one({"_id": "retention"}, {"_id": 0}) == operator_lock


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("cascade_resumes", [False, True], ids=["cascade-died", "cascade-finishes-later"])
async def test_a_run_written_to_while_an_overlapping_runner_cascades_it_keeps_that_runners_archive(
    client, db, api_key_headers, retention_archives, monkeypatch, cascade_resumes
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    cut_short, resume = asyncio.Event(), asyncio.Event()
    real_cascade, real_archive_scan = housekeeping.delete_scans_and_related_data, archive.archive_scan
    other: list[asyncio.Task] = []

    async def cascade(db_, scan_ids, label):
        if label == "other runner":
            await db_.analysis_results.delete_many({"scan_id": {"$in": scan_ids}})
            cut_short.set()
            if not cascade_resumes:
                return 0
            await resume.wait()
        return await real_cascade(db_, scan_ids, label)

    async def other_runner_cascades_then_a_job_writes(db_, scan_id_):
        monkeypatch.setattr(archive, "archive_scan", real_archive_scan)
        other.append(asyncio.create_task(_archive_scans_and_delete(db_, [scan_id_], "other runner")))
        await cut_short.wait()
        metadata = await real_archive_scan(db_, scan_id_)
        await _retried_job(client, db, api_key_headers)
        return metadata

    monkeypatch.setattr(housekeeping, "delete_scans_and_related_data", cascade)
    monkeypatch.setattr(archive, "archive_scan", other_runner_cascades_then_a_job_writes)
    await _archive_scans_and_delete(db, [scan_id], "this runner")
    resume.set()
    await other[0]

    assert await db.archive_metadata.count_documents({"scan_id": scan_id}) == 1


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_restore_written_to_during_a_batch_that_reused_its_archive_keeps_that_archive(
    client, db, api_key_headers, retention_archives, monkeypatch
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    real_archive_scan = archive.archive_scan
    finish_the_restore: list[Callable[[], Awaitable[None]]] = []

    async def other_runner_archives_then_a_job_meets_a_restore(db_, scan_id_):
        monkeypatch.setattr(archive, "archive_scan", real_archive_scan)
        await _archive_scans_and_delete(db_, [scan_id_], "other runner")
        metadata = await real_archive_scan(db_, scan_id_)
        restore = restore_scan(db_, scan_id_)
        finish_the_restore.append(await _paused_before(monkeypatch, archive, "_handle_doc_event", restore))
        await _retried_job(client, db, api_key_headers)
        return metadata

    monkeypatch.setattr(archive, "archive_scan", other_runner_archives_then_a_job_meets_a_restore)
    await _archive_scans_and_delete(db, [scan_id], "this runner")
    restoring_scan_kept_its_archive = await db.archive_metadata.count_documents({"scan_id": scan_id}) == 1
    await finish_the_restore[0]()

    assert restoring_scan_kept_its_archive


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_archiving_a_scan_another_runner_archived_and_deleted_returns_that_archive(db, retention_archives):
    await db.scans.insert_one(_scan("x", 200))
    first = await archive.archive_scan(db, "x")
    await db.scans.delete_one({"_id": "x"})
    second = await archive.archive_scan(db, "x")

    assert getattr(second, "s3_key", None) == first.s3_key
    assert set(retention_archives.objects) == {first.s3_key}
