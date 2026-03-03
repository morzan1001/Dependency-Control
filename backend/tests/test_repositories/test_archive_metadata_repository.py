"""Tests for ArchiveMetadataRepository.

Tests query logic and CRUD operations using mocked MongoDB.
ArchiveMetadataRepository extends BaseRepository which uses db[collection_name]
(dict access), so we configure __getitem__ on the mock db.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

from app.repositories.archive_metadata import ArchiveMetadataRepository
from tests.mocks.mongodb import create_mock_collection


def _make_mock_db(collection):
    """Create a mock database that supports dict-style access for BaseRepository."""
    db = MagicMock()
    # BaseRepository.__init__ does: self.collection = db[self.collection_name]
    db.__getitem__ = MagicMock(return_value=collection)
    return db


def _make_archive_doc(**overrides):
    """Create a raw archive metadata document."""
    doc = {
        "_id": "archive-1",
        "project_id": "proj-1",
        "scan_id": "scan-1",
        "s3_key": "proj-1/scan-1.json.gz",
        "s3_bucket": "dc-archives",
        "archived_at": datetime(2025, 6, 1, tzinfo=timezone.utc),
        "branch": "main",
        "commit_hash": "abc123",
        "original_size_bytes": 5000,
        "compressed_size_bytes": 1000,
    }
    doc.update(overrides)
    return doc


class TestFindByProject:
    def test_returns_archives_for_project(self):
        docs = [
            _make_archive_doc(_id="a-1", scan_id="scan-1"),
            _make_archive_doc(_id="a-2", scan_id="scan-2"),
        ]
        collection = create_mock_collection(find=docs)
        db = _make_mock_db(collection)
        repo = ArchiveMetadataRepository(db)

        result = asyncio.run(repo.find_by_project("proj-1"))

        assert len(result) == 2
        assert result[0].scan_id == "scan-1"
        assert result[1].scan_id == "scan-2"

    def test_returns_empty_list_when_none_found(self):
        collection = create_mock_collection(find=[])
        db = _make_mock_db(collection)
        repo = ArchiveMetadataRepository(db)

        result = asyncio.run(repo.find_by_project("proj-1"))

        assert result == []

    def test_applies_skip_and_limit(self):
        collection = create_mock_collection(find=[])
        db = _make_mock_db(collection)
        repo = ArchiveMetadataRepository(db)

        asyncio.run(repo.find_by_project("proj-1", skip=10, limit=5))

        cursor = collection.find.return_value
        cursor.skip.assert_called_once_with(10)
        cursor.limit.assert_called_once_with(5)


class TestCountByProject:
    def test_counts_archives(self):
        collection = create_mock_collection(count_documents=5)
        db = _make_mock_db(collection)
        repo = ArchiveMetadataRepository(db)

        result = asyncio.run(repo.count_by_project("proj-1"))

        assert result == 5
        collection.count_documents.assert_called_once_with({"project_id": "proj-1"})

    def test_returns_zero_when_none(self):
        collection = create_mock_collection(count_documents=0)
        db = _make_mock_db(collection)
        repo = ArchiveMetadataRepository(db)

        result = asyncio.run(repo.count_by_project("proj-1"))

        assert result == 0


class TestFindByScanId:
    def test_returns_archive_when_found(self):
        doc = _make_archive_doc()
        collection = create_mock_collection(find_one=doc)
        db = _make_mock_db(collection)
        repo = ArchiveMetadataRepository(db)

        result = asyncio.run(repo.find_by_scan_id("scan-1"))

        assert result is not None
        assert result.scan_id == "scan-1"
        assert result.s3_key == "proj-1/scan-1.json.gz"

    def test_returns_none_when_not_found(self):
        collection = create_mock_collection(find_one=None)
        db = _make_mock_db(collection)
        repo = ArchiveMetadataRepository(db)

        result = asyncio.run(repo.find_by_scan_id("nonexistent"))

        assert result is None


class TestDeleteByScanId:
    def test_returns_true_on_success(self):
        collection = create_mock_collection()
        collection.delete_one = AsyncMock(return_value=MagicMock(deleted_count=1))
        db = _make_mock_db(collection)
        repo = ArchiveMetadataRepository(db)

        result = asyncio.run(repo.delete_by_scan_id("scan-1"))

        assert result is True
        collection.delete_one.assert_called_once_with({"scan_id": "scan-1"})

    def test_returns_false_when_not_found(self):
        collection = create_mock_collection()
        collection.delete_one = AsyncMock(return_value=MagicMock(deleted_count=0))
        db = _make_mock_db(collection)
        repo = ArchiveMetadataRepository(db)

        result = asyncio.run(repo.delete_by_scan_id("nonexistent"))

        assert result is False


class TestCRUD:
    def test_create(self):
        from app.models.archive import ArchiveMetadata

        collection = create_mock_collection()
        db = _make_mock_db(collection)
        repo = ArchiveMetadataRepository(db)

        metadata = ArchiveMetadata(
            project_id="proj-1",
            scan_id="scan-1",
            s3_key="proj-1/scan-1.json.gz",
            s3_bucket="dc-archives",
        )

        result = asyncio.run(repo.create(metadata))

        collection.insert_one.assert_called_once()
        assert result.scan_id == "scan-1"

    def test_get_by_id_found(self):
        doc = _make_archive_doc()
        collection = create_mock_collection(find_one=doc)
        db = _make_mock_db(collection)
        repo = ArchiveMetadataRepository(db)

        result = asyncio.run(repo.get_by_id("archive-1"))

        assert result is not None
        assert result.project_id == "proj-1"

    def test_get_by_id_not_found(self):
        collection = create_mock_collection(find_one=None)
        db = _make_mock_db(collection)
        repo = ArchiveMetadataRepository(db)

        result = asyncio.run(repo.get_by_id("nonexistent"))

        assert result is None
