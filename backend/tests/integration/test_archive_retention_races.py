"""Retention, archive and restore running at the same time on several pods never lose a scan."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.core import housekeeping
from app.core.housekeeping import _run_retention
from app.services import archive

_NOW = datetime.now(timezone.utc)
_PROJECT_ID = "test-project-id"


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
