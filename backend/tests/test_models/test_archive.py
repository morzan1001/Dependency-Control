"""Tests for ArchiveMetadata model.

Tests validation, defaults, and serialization.
"""

from datetime import datetime, timezone

from app.models.archive import ArchiveMetadata


class TestArchiveMetadata:
    def test_minimal_valid_metadata(self):
        metadata = ArchiveMetadata(
            project_id="proj-1",
            scan_id="scan-1",
            s3_key="proj-1/scan-1.json.gz",
            s3_bucket="dc-archives",
        )
        assert metadata.project_id == "proj-1"
        assert metadata.scan_id == "scan-1"
        assert metadata.s3_key == "proj-1/scan-1.json.gz"
        assert metadata.s3_bucket == "dc-archives"

    def test_id_auto_generated(self):
        metadata = ArchiveMetadata(
            project_id="proj-1",
            scan_id="scan-1",
            s3_key="proj-1/scan-1.json.gz",
            s3_bucket="dc-archives",
        )
        assert metadata.id is not None
        assert len(metadata.id) > 0

    def test_archived_at_auto_set(self):
        metadata = ArchiveMetadata(
            project_id="proj-1",
            scan_id="scan-1",
            s3_key="proj-1/scan-1.json.gz",
            s3_bucket="dc-archives",
        )
        assert metadata.archived_at is not None
        assert metadata.archived_at.tzinfo is not None

    def test_optional_fields_default_to_none(self):
        metadata = ArchiveMetadata(
            project_id="proj-1",
            scan_id="scan-1",
            s3_key="proj-1/scan-1.json.gz",
            s3_bucket="dc-archives",
        )
        assert metadata.branch is None
        assert metadata.commit_hash is None
        assert metadata.scan_created_at is None
        assert metadata.scan_completed_at is None
        assert metadata.scan_status is None
        assert metadata.original_size_bytes is None
        assert metadata.compressed_size_bytes is None

    def test_collections_included_default(self):
        metadata = ArchiveMetadata(
            project_id="proj-1",
            scan_id="scan-1",
            s3_key="proj-1/scan-1.json.gz",
            s3_bucket="dc-archives",
        )
        assert "scans" in metadata.collections_included
        assert "findings" in metadata.collections_included
        assert "gridfs_sboms" in metadata.collections_included

    def test_full_metadata(self):
        metadata = ArchiveMetadata(
            project_id="proj-1",
            scan_id="scan-1",
            s3_key="proj-1/scan-1.json.gz",
            s3_bucket="dc-archives",
            branch="main",
            commit_hash="abc123",
            scan_created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            scan_completed_at=datetime(2025, 1, 1, 1, 0, tzinfo=timezone.utc),
            scan_status="completed",
            original_size_bytes=5000,
            compressed_size_bytes=1000,
        )
        assert metadata.branch == "main"
        assert metadata.commit_hash == "abc123"
        assert metadata.original_size_bytes == 5000
        assert metadata.compressed_size_bytes == 1000

    def test_serialization_alias(self):
        metadata = ArchiveMetadata(
            project_id="proj-1",
            scan_id="scan-1",
            s3_key="proj-1/scan-1.json.gz",
            s3_bucket="dc-archives",
        )
        dumped = metadata.model_dump(by_alias=True)
        assert "_id" in dumped
        assert "id" not in dumped

    def test_validation_alias_accepts_underscore_id(self):
        metadata = ArchiveMetadata(
            **{
                "_id": "custom-id",
                "project_id": "proj-1",
                "scan_id": "scan-1",
                "s3_key": "proj-1/scan-1.json.gz",
                "s3_bucket": "dc-archives",
            }
        )
        assert metadata.id == "custom-id"

    def test_populate_by_name(self):
        metadata = ArchiveMetadata(
            id="my-id",
            project_id="proj-1",
            scan_id="scan-1",
            s3_key="proj-1/scan-1.json.gz",
            s3_bucket="dc-archives",
        )
        assert metadata.id == "my-id"
