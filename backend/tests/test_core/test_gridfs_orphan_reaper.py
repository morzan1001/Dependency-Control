"""K12: housekeeping sweep deletes GridFS files no scan references, honouring the safety window."""

from datetime import datetime, timedelta, timezone

import pytest

from app.services.gridfs_maintenance import reap_orphan_gridfs_files
from tests.mocks.fake_mongo import FakeDatabase

_OLD = datetime.now(timezone.utc) - timedelta(hours=48)
_FRESH = datetime.now(timezone.utc) - timedelta(minutes=5)

# 24-hex-char ObjectId strings, as referenced by prod sbom_refs.
_REFERENCED_ID = "69d5332257c8763c8d8c82d7"
_ORPHAN_OLD_ID = "69d5332357c8763c8d8c82de"
_ORPHAN_FRESH_ID = "69d5332457c8763c8d8c82ef"


class _FakeBucket:
    def __init__(self, db):
        self._files = db["fs.files"]

    async def delete(self, oid):
        await self._files.delete_one({"_id": str(oid)})


@pytest.fixture
def db(monkeypatch):
    fake = FakeDatabase()
    monkeypatch.setattr("app.services.gridfs_maintenance.AsyncIOMotorGridFSBucket", _FakeBucket)
    return fake


async def _seed(db):
    await db.scans.insert_one(
        {
            "_id": "scan-1",
            "project_id": "p1",
            "sbom_refs": [
                {
                    "storage": "gridfs",
                    "type": "gridfs_reference",
                    "gridfs_id": _REFERENCED_ID,
                    "file_id": _REFERENCED_ID,
                }
            ],
        }
    )
    await db["fs.files"].insert_one({"_id": _REFERENCED_ID, "length": 100, "uploadDate": _OLD})
    await db["fs.files"].insert_one({"_id": _ORPHAN_OLD_ID, "length": 200, "uploadDate": _OLD})
    await db["fs.files"].insert_one({"_id": _ORPHAN_FRESH_ID, "length": 300, "uploadDate": _FRESH})


@pytest.mark.asyncio
async def test_old_orphans_are_deleted_referenced_and_fresh_files_survive(db):
    await _seed(db)

    deleted = await reap_orphan_gridfs_files(db)

    assert deleted == 1
    remaining = {d["_id"] async for d in db["fs.files"].find({})}
    assert remaining == {_REFERENCED_ID, _ORPHAN_FRESH_ID}, (
        "only the aged orphan may be reaped; referenced and fresh uploads must survive"
    )


@pytest.mark.asyncio
async def test_compliance_report_artifacts_survive_the_sweep(db):
    """Compliance artifacts share the default fs bucket but are referenced only by compliance_reports."""
    artifact_id = "69d5332557c8763c8d8c82f0"
    await db.compliance_reports.insert_one({"_id": "report-1", "artifact_gridfs_id": artifact_id})
    await db["fs.files"].insert_one({"_id": artifact_id, "length": 400, "uploadDate": _OLD})
    await db["fs.files"].insert_one({"_id": _ORPHAN_OLD_ID, "length": 200, "uploadDate": _OLD})

    deleted = await reap_orphan_gridfs_files(db)

    assert deleted == 1
    remaining = {d["_id"] async for d in db["fs.files"].find({})}
    assert remaining == {artifact_id}, "a live report's artifact must never be reaped"


@pytest.mark.asyncio
async def test_reaper_is_a_noop_without_orphans(db):
    await db.scans.insert_one(
        {"_id": "scan-1", "project_id": "p1", "sbom_refs": [{"type": "gridfs_reference", "gridfs_id": _REFERENCED_ID}]}
    )
    await db["fs.files"].insert_one({"_id": _REFERENCED_ID, "length": 100, "uploadDate": _OLD})

    assert await reap_orphan_gridfs_files(db) == 0
    assert await db["fs.files"].count_documents({}) == 1
