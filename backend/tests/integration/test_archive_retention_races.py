"""Retention, archive and restore running at the same time on several pods never lose a scan."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from pymongo.errors import AutoReconnect, NetworkTimeout

from app.core import housekeeping
from app.core.housekeeping import _archive_scans_and_delete, _expire_group, _run_retention
from app.repositories.archive_metadata import ArchiveMetadataRepository
from app.repositories.distributed_locks import DistributedLocksRepository
from app.services import archive
from app.services.archive import restore_scan

_NOW = datetime.now(timezone.utc)
_PROJECT_ID = "test-project-id"
_RUN = {"pipeline_id": 515151, "commit_hash": "e" * 40, "branch": "main"}
_CALLGRAPH = {"format": "generic", "language": "python", "data": {"imports": [], "analyzed_modules": []}}
_SECRET = json.loads((Path(__file__).parents[1] / "fixtures/secrets/trufflehog_v3_line.json").read_text())


def _scan(scan_id: str, age_days: int, **fields) -> dict:
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


async def _callgraph_upload(client, headers, project) -> None:
    with patch("app.api.deps._authenticate_ci", new_callable=AsyncMock, return_value=project):
        resp = await client.post(f"/api/v1/projects/{_PROJECT_ID}/callgraph", json={**_RUN, **_CALLGRAPH}, headers=headers)
    assert resp.status_code == 200, resp.text


def _before_the_metadata_save(monkeypatch, write: Callable[[], Awaitable[None]]) -> None:
    real_save = archive._save_archive_metadata

    async def write_then_save(*args, **kwargs):
        monkeypatch.setattr(archive, "_save_archive_metadata", real_save)
        await write()
        return await real_save(*args, **kwargs)

    monkeypatch.setattr(archive, "_save_archive_metadata", write_then_save)


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
    monkeypatch.setattr(housekeeping, "_RETENTION_LOCK_TTL_SECONDS", 0.3, raising=False)
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
        "run_housekeeping",
        "sync_branch_status",
        "reconcile_update_frequency_ledger",
    ):
        monkeypatch.setattr(housekeeping, task, noop)
    bid = AsyncMock()
    monkeypatch.setattr(housekeeping, "_run_retention", bid)
    monkeypatch.setattr(housekeeping, "asyncio", SimpleNamespace(sleep=AsyncMock(side_effect=[None, _StopLoop])))
    with pytest.raises(_StopLoop):
        await housekeeping.housekeeping_loop()

    assert bid.await_count == 2


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
async def test_a_scan_ingested_into_while_it_was_archived_is_kept(
    client, db, api_key_headers, retention_archives, monkeypatch
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    _before_the_metadata_save(monkeypatch, lambda: _retried_job(client, db, api_key_headers))
    await _archive_scans_and_delete(db, [scan_id], "retention")

    assert await _analyzers(db, scan_id) == {"trufflehog", "opengrep"}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_callgraph_posted_while_its_run_was_archived_is_kept(
    client, db, api_key_headers, _project, retention_archives, monkeypatch
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    _before_the_metadata_save(monkeypatch, lambda: _callgraph_upload(client, api_key_headers, _project))
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
    if during_the_archive:
        _before_the_metadata_save(monkeypatch, lambda: _retried_job(client, db, api_key_headers))
    await _archive_scans_and_delete(db, [scan_id], "first pass")
    if not during_the_archive:
        await _retried_job(client, db, api_key_headers)
    await _archive_scans_and_delete(db, [scan_id], "second pass")

    assert "opengrep" in await _analyzers(db, scan_id)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_restore_beaten_to_the_scan_by_an_ingest_leaves_the_ingested_scan_alone(
    client, db, api_key_headers, retention_archives, monkeypatch
):
    scan_id = await _analysed_run(client, db, api_key_headers)
    await _archive_scans_and_delete(db, [scan_id], "retention")
    real_header = archive._handle_header_event

    async def retry_before_the_header_insert(*args, **kwargs):
        await _retried_job(client, db, api_key_headers)
        return await real_header(*args, **kwargs)

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
