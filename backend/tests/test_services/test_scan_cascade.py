"""Everything a scan owns goes with it, and every caller removes the same set.

Two hand-maintained lists of the same collections is how crypto_assets and finding_records came to
outlive their project, so the divergence test below compares the paths rather than trusting either.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.constants import ARCHIVE_GRIDFS_FRAME, SCAN_KEYED_COLLECTIONS, SCAN_SCOPED_COLLECTIONS
from app.services.scan_cascade import delete_scans_and_related_data
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT_ID = "p1"
_SCAN_ID = "s1"
_OTHER_SCAN_ID = "s2"
_SURVIVOR_SCAN_ID = "s-other-project"
_GRIDFS_ID = "507f1f77bcf86cd799439011"
_RETENTION_LABEL = "retention"


async def _seed_scan(db: Any, scan_id: str, project_id: str = _PROJECT_ID) -> None:
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": project_id,
            "status": "completed",
            "sbom_refs": [{"type": "gridfs_reference", "gridfs_id": _GRIDFS_ID, "storage": "gridfs"}],
        }
    )
    for collection in SCAN_SCOPED_COLLECTIONS:
        await db[collection].insert_one(
            {"_id": f"{collection}-{scan_id}", "project_id": project_id, "scan_id": scan_id}
        )
    for collection in SCAN_KEYED_COLLECTIONS:
        await db[collection].insert_one({"_id": scan_id, "project_id": project_id})


async def _remaining(db: Any, scan_id: str) -> dict[str, int]:
    counts = {name: await db[name].count_documents({"scan_id": scan_id}) for name in SCAN_SCOPED_COLLECTIONS}
    counts.update({name: await db[name].count_documents({"_id": scan_id}) for name in SCAN_KEYED_COLLECTIONS})
    counts["scans"] = await db.scans.count_documents({"_id": scan_id})
    return counts


@pytest.mark.asyncio
async def test_the_cascade_empties_every_collection_a_scan_is_keyed_into(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.services.scan_cascade.cleanup_gridfs_files", AsyncMock())
    db = FakeDatabase()
    await _seed_scan(db, _SCAN_ID)
    await _seed_scan(db, _OTHER_SCAN_ID)

    assert await delete_scans_and_related_data(db, [_SCAN_ID, _OTHER_SCAN_ID], _RETENTION_LABEL) == 2

    assert set((await _remaining(db, _SCAN_ID)).values()) == {0}
    assert set((await _remaining(db, _OTHER_SCAN_ID)).values()) == {0}


@pytest.mark.asyncio
async def test_the_cascade_leaves_another_scans_rows_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.services.scan_cascade.cleanup_gridfs_files", AsyncMock())
    db = FakeDatabase()
    await _seed_scan(db, _SCAN_ID)
    await _seed_scan(db, _SURVIVOR_SCAN_ID, project_id="p2")

    await delete_scans_and_related_data(db, [_SCAN_ID])

    assert set((await _remaining(db, _SURVIVOR_SCAN_ID)).values()) == {1}


@pytest.mark.asyncio
async def test_the_cascade_asks_gridfs_to_spare_files_another_scan_still_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refcount check is what keeps a rescan's copied sbom_refs from being orphaned."""
    cleanup = AsyncMock()
    monkeypatch.setattr("app.services.scan_cascade.cleanup_gridfs_files", cleanup)
    db = FakeDatabase()
    await _seed_scan(db, _SCAN_ID)

    await delete_scans_and_related_data(db, [_SCAN_ID])

    cleanup.assert_awaited_once_with(db, [_GRIDFS_ID], deleted_scan_ids=[_SCAN_ID])


class _RecordingDatabase:
    """A FakeDatabase that names every collection a delete was issued against, and its query."""

    def __init__(self) -> None:
        self._db = FakeDatabase()
        self.deletes: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Any:
        return self[name]

    def __getitem__(self, name: str) -> Any:
        collection = self._db[name]
        if not getattr(collection, "_delete_recorded", False):
            original = collection.delete_many

            async def _record(query: dict[str, Any], _name: str = name, _original: Any = original) -> Any:
                self.deletes.append((_name, query))
                return await _original(query)

            collection.delete_many = _record
            collection._delete_recorded = True
        return collection


def _scan_scoped(deletes: list[tuple[str, dict[str, Any]]], scan_id: str) -> set[str]:
    return {name for name, query in deletes if scan_id in repr(query)}


@pytest.mark.asyncio
async def test_project_deletion_and_retention_remove_the_same_scan_scoped_collections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One cascade, so a collection added to one path cannot be missing from the other."""
    from app.api.v1.endpoints.projects import delete_project

    monkeypatch.setattr("app.services.scan_cascade.cleanup_gridfs_files", AsyncMock())
    monkeypatch.setattr(
        "app.api.v1.endpoints.projects.check_project_access", AsyncMock(return_value=MagicMock(id=_PROJECT_ID))
    )

    retention_db = _RecordingDatabase()
    await _seed_scan(retention_db, _SCAN_ID)
    await delete_scans_and_related_data(retention_db, [_SCAN_ID], _RETENTION_LABEL)

    project_db = _RecordingDatabase()
    await project_db.projects.insert_one({"_id": _PROJECT_ID, "name": "p"})
    await _seed_scan(project_db, _SCAN_ID)
    await delete_project(_PROJECT_ID, MagicMock(), project_db)

    assert _scan_scoped(project_db.deletes, _SCAN_ID) == _scan_scoped(retention_db.deletes, _SCAN_ID)
    assert set((await _remaining(project_db, _SCAN_ID)).values()) == {0}


def test_the_archive_bundle_carries_exactly_what_the_cascade_removes() -> None:
    """An archive that snapshots less than deletion removes loses the difference for good."""
    from app.models.archive import ArchiveMetadata
    from app.services.archive import _RESTORABLE_COLLECTIONS

    assert _RESTORABLE_COLLECTIONS == {*SCAN_SCOPED_COLLECTIONS, ARCHIVE_GRIDFS_FRAME}
    assert set(ArchiveMetadata(project_id="p", scan_id="s", s3_key="k", s3_bucket="b").collections_included) == {
        "scans",
        *SCAN_SCOPED_COLLECTIONS,
        ARCHIVE_GRIDFS_FRAME,
    }
