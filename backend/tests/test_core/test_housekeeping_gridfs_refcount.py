"""Tests for GridFS-ref-counting during retention housekeeping.

Regression test for the orphan-SBOM bug: when a rescan inherits its source
scan's ``sbom_refs`` dict (which contains the original scan's ``gridfs_id``),
multiple scans end up sharing the same GridFS file. The retention cleanup
must NOT delete a GridFS file that any other (non-deleted) scan still
references — otherwise the surviving scans hit
``Failed to load SBOM from GridFS: no file in gridfs collection`` on their
next worker run.

See ``app/core/housekeeping.py:_cleanup_gridfs_files``.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.housekeeping import _delete_scans_and_related_data
from tests.mocks.fake_mongo import FakeDatabase


def _gridfs_ref(gid: str) -> dict:
    return {"type": "gridfs_reference", "gridfs_id": gid, "file_id": gid}


@pytest.mark.asyncio
async def test_cleanup_skips_gridfs_file_still_referenced_by_other_scan():
    """A rescan-chain scenario: scan A is the original ingest, scan B is a
    rescan that copied A's ``sbom_refs``. When retention deletes B, A's
    GridFS file must survive because A still references it.
    """
    db = FakeDatabase()
    shared_gid = "6a06edb3dcb1d39dc6d91793"

    await db.scans.insert_many(
        [
            {
                "_id": "scan-A",
                "project_id": "p1",
                "status": "completed",
                "is_rescan": False,
                "sbom_refs": [_gridfs_ref(shared_gid)],
            },
            {
                "_id": "scan-B",
                "project_id": "p1",
                "status": "completed",
                "is_rescan": True,
                "original_scan_id": "scan-A",
                "sbom_refs": [_gridfs_ref(shared_gid)],
            },
        ]
    )

    mock_bucket = AsyncMock()
    with patch(
        "app.core.housekeeping.AsyncIOMotorGridFSBucket",
        return_value=mock_bucket,
    ):
        await _delete_scans_and_related_data(db, ["scan-B"], "test")

    # scan-A's GridFS file must NOT be deleted — scan-A still references it.
    mock_bucket.delete.assert_not_called()


@pytest.mark.asyncio
async def test_cleanup_deletes_gridfs_file_when_no_other_scan_refs_it():
    """Sanity check: the ref-counting must still allow real cleanup when
    the deleted scan is the last referent of its GridFS file.
    """
    db = FakeDatabase()
    orphan_gid = "5a06edb3dcb1d39dc6d91793"

    await db.scans.insert_one(
        {
            "_id": "scan-A",
            "project_id": "p1",
            "status": "completed",
            "is_rescan": False,
            "sbom_refs": [_gridfs_ref(orphan_gid)],
        }
    )

    mock_bucket = AsyncMock()
    with patch(
        "app.core.housekeeping.AsyncIOMotorGridFSBucket",
        return_value=mock_bucket,
    ):
        await _delete_scans_and_related_data(db, ["scan-A"], "test")

    # The GridFS file should be deleted exactly once — no surviving references.
    assert mock_bucket.delete.await_count == 1


@pytest.mark.asyncio
async def test_cleanup_deletes_mixed_refs_correctly():
    """Deleted scan references two files; one is shared with a survivor,
    the other is exclusive. Only the exclusive file should be deleted.
    """
    db = FakeDatabase()
    shared_gid = "6a06edb3dcb1d39dc6d91793"
    exclusive_gid = "7a06edb3dcb1d39dc6d91793"

    await db.scans.insert_many(
        [
            {
                "_id": "scan-A",
                "project_id": "p1",
                "status": "completed",
                "is_rescan": False,
                "sbom_refs": [_gridfs_ref(shared_gid)],
            },
            {
                "_id": "scan-B",
                "project_id": "p1",
                "status": "completed",
                "is_rescan": True,
                "original_scan_id": "scan-A",
                "sbom_refs": [_gridfs_ref(shared_gid), _gridfs_ref(exclusive_gid)],
            },
        ]
    )

    mock_bucket = AsyncMock()
    with patch(
        "app.core.housekeeping.AsyncIOMotorGridFSBucket",
        return_value=mock_bucket,
    ):
        await _delete_scans_and_related_data(db, ["scan-B"], "test")

    # Only exclusive_gid should be deleted; shared_gid is still on scan-A.
    deleted_ids = {str(call.args[0]) for call in mock_bucket.delete.await_args_list}
    assert exclusive_gid in deleted_ids
    assert shared_gid not in deleted_ids
