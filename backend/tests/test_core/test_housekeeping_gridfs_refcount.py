"""GridFS ref-counting during retention: cleanup must not delete a file another scan still references."""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.housekeeping import _delete_scans_and_related_data
from tests.mocks.fake_mongo import FakeDatabase


def _gridfs_ref(gid: str) -> dict:
    return {"type": "gridfs_reference", "gridfs_id": gid, "file_id": gid}


@pytest.mark.asyncio
async def test_cleanup_skips_gridfs_file_still_referenced_by_other_scan():
    """Rescan B copied A's sbom_refs; deleting B must keep A's shared GridFS file."""
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
    """Ref-counting must still allow cleanup when the deleted scan is the last referent."""
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
    """A deleted scan's exclusive file is deleted; a file shared with a survivor is kept."""
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
