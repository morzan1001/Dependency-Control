"""Tests for ArchiveMetadata model."""

from datetime import datetime, timezone

from app.models.archive import ArchiveMetadata


class TestArchiveMetadata:
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
        assert metadata.compressed_size_bytes is None

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
            compressed_size_bytes=1000,
        )
        assert metadata.branch == "main"
        assert metadata.commit_hash == "abc123"
        assert metadata.compressed_size_bytes == 1000
