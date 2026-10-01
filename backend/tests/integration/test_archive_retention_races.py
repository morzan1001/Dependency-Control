"""Retention, archive and restore running at the same time on several pods never lose a scan."""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.core import housekeeping
from app.core.housekeeping import _archive_scans_and_delete, _expire_group, _run_retention
from app.services import archive
from app.services.archive import restore_scan

_NOW = datetime.now(timezone.utc)
_PROJECT_ID = "test-project-id"
_RUN = {"pipeline_id": 515151, "commit_hash": "e" * 40, "branch": "main"}
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
    real_save = archive._save_archive_metadata

    async def ingest_and_analyse_before_the_save(*args, **kwargs):
        await _ingest(client, api_key_headers, "opengrep", [])
        await db.scans.update_one({"_id": scan_id}, {"$set": {"status": "completed"}})
        return await real_save(*args, **kwargs)

    monkeypatch.setattr(archive, "_save_archive_metadata", ingest_and_analyse_before_the_save)
    await _archive_scans_and_delete(db, [scan_id], "retention")

    assert await _analyzers(db, scan_id) == {"trufflehog", "opengrep"}
