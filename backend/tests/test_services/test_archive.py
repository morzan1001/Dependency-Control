"""Tests for archive service (archive_scan, restore_scan).

Tests the core archiving and restoring logic with mocked S3 and MongoDB.
"""

import asyncio
import gzip
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.archive import ArchiveMetadata
from app.services.archive import (
    _extract_gridfs_ids_from_refs,
    _serialize_doc,
    archive_scan,
    restore_scan,
)

MODULE = "app.services.archive"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scan_doc(**overrides):
    """Create a minimal scan document for testing."""
    doc = {
        "_id": "scan-1",
        "project_id": "proj-1",
        "branch": "main",
        "commit_hash": "abc123",
        "created_at": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "completed_at": datetime(2025, 1, 1, 1, 0, tzinfo=timezone.utc),
        "status": "completed",
        "sbom_refs": [],
    }
    doc.update(overrides)
    return doc


def _make_archive_metadata(**overrides):
    """Create an ArchiveMetadata instance for testing."""
    defaults = {
        "project_id": "proj-1",
        "scan_id": "scan-1",
        "s3_key": "proj-1/scan-1.json.gz",
        "s3_bucket": "dc-archives",
        "branch": "main",
        "commit_hash": "abc123",
        "original_size_bytes": 1000,
        "compressed_size_bytes": 200,
    }
    defaults.update(overrides)
    return ArchiveMetadata(**defaults)


def _make_mock_db(scan_doc=None, findings=None, finding_records=None,
                  dependencies=None, analysis_results=None, callgraphs=None):
    """Create a mock database with collection mocks."""
    db = MagicMock()

    # scans
    db.scans.find_one = AsyncMock(return_value=scan_doc)
    scans_cursor = MagicMock()
    scans_cursor.to_list = AsyncMock(return_value=[scan_doc] if scan_doc else [])
    db.scans.find = MagicMock(return_value=scans_cursor)
    db.scans.insert_one = AsyncMock()

    # findings
    findings_cursor = MagicMock()
    findings_cursor.to_list = AsyncMock(return_value=findings or [])
    db.findings.find = MagicMock(return_value=findings_cursor)
    db.findings.insert_many = AsyncMock()

    # finding_records
    fr_cursor = MagicMock()
    fr_cursor.to_list = AsyncMock(return_value=finding_records or [])
    db.finding_records.find = MagicMock(return_value=fr_cursor)
    db.finding_records.insert_many = AsyncMock()

    # dependencies
    deps_cursor = MagicMock()
    deps_cursor.to_list = AsyncMock(return_value=dependencies or [])
    db.dependencies.find = MagicMock(return_value=deps_cursor)
    db.dependencies.insert_many = AsyncMock()

    # analysis_results
    ar_cursor = MagicMock()
    ar_cursor.to_list = AsyncMock(return_value=analysis_results or [])
    db.analysis_results.find = MagicMock(return_value=ar_cursor)
    db.analysis_results.insert_many = AsyncMock()

    # callgraphs
    cg_cursor = MagicMock()
    cg_cursor.to_list = AsyncMock(return_value=callgraphs or [])
    db.callgraphs.find = MagicMock(return_value=cg_cursor)
    db.callgraphs.insert_many = AsyncMock()

    return db


# ---------------------------------------------------------------------------
# _serialize_doc
# ---------------------------------------------------------------------------

class TestSerializeDoc:
    def test_converts_objectid(self):
        from bson import ObjectId

        oid = ObjectId("507f1f77bcf86cd799439011")
        result = _serialize_doc({"_id": oid})
        assert result["_id"] == "507f1f77bcf86cd799439011"

    def test_converts_datetime(self):
        dt = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = _serialize_doc({"created_at": dt})
        assert result["created_at"] == dt.isoformat()

    def test_converts_nested_dict(self):
        from bson import ObjectId

        doc = {"meta": {"ref_id": ObjectId("507f1f77bcf86cd799439011")}}
        result = _serialize_doc(doc)
        assert result["meta"]["ref_id"] == "507f1f77bcf86cd799439011"

    def test_converts_list_with_objectids(self):
        from bson import ObjectId

        doc = {"ids": [ObjectId("507f1f77bcf86cd799439011"), "normal-string"]}
        result = _serialize_doc(doc)
        assert result["ids"][0] == "507f1f77bcf86cd799439011"
        assert result["ids"][1] == "normal-string"

    def test_preserves_plain_values(self):
        doc = {"name": "test", "count": 42, "active": True, "tags": ["a", "b"]}
        result = _serialize_doc(doc)
        assert result == doc

    def test_converts_list_of_dicts(self):
        from bson import ObjectId

        doc = {"items": [{"_id": ObjectId("507f1f77bcf86cd799439011")}]}
        result = _serialize_doc(doc)
        assert result["items"][0]["_id"] == "507f1f77bcf86cd799439011"


# ---------------------------------------------------------------------------
# _extract_gridfs_ids_from_refs
# ---------------------------------------------------------------------------

class TestExtractGridfsIds:
    def test_extracts_gridfs_ids(self):
        refs = [
            {"type": "gridfs_reference", "gridfs_id": "gid-1"},
            {"type": "gridfs_reference", "gridfs_id": "gid-2"},
        ]
        result = _extract_gridfs_ids_from_refs(refs)
        assert result == ["gid-1", "gid-2"]

    def test_ignores_non_gridfs_refs(self):
        refs = [
            {"type": "url_reference", "url": "https://example.com/sbom.json"},
            {"type": "gridfs_reference", "gridfs_id": "gid-1"},
        ]
        result = _extract_gridfs_ids_from_refs(refs)
        assert result == ["gid-1"]

    def test_handles_empty_list(self):
        assert _extract_gridfs_ids_from_refs([]) == []

    def test_skips_refs_without_gridfs_id(self):
        refs = [{"type": "gridfs_reference"}]
        result = _extract_gridfs_ids_from_refs(refs)
        assert result == []


# ---------------------------------------------------------------------------
# archive_scan
# ---------------------------------------------------------------------------

class TestArchiveScan:
    def test_returns_none_when_s3_not_configured(self):
        with patch(f"{MODULE}.is_archive_enabled", return_value=False):
            result = asyncio.run(archive_scan(MagicMock(), "scan-1"))
        assert result is None

    def test_returns_existing_metadata_if_already_archived(self):
        existing = _make_archive_metadata()

        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=existing)

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
        ):
            result = asyncio.run(archive_scan(MagicMock(), "scan-1"))

        assert result == existing

    def test_returns_none_when_scan_not_found(self):
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=None)

        db = _make_mock_db(scan_doc=None)

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
        ):
            result = asyncio.run(archive_scan(db, "scan-1"))

        assert result is None

    def test_archives_scan_successfully(self):
        scan_doc = _make_scan_doc()
        findings = [{"_id": "f-1", "scan_id": "scan-1", "severity": "high"}]
        dependencies = [{"_id": "d-1", "scan_id": "scan-1", "purl": "pkg:pypi/requests@2.31.0"}]

        db = _make_mock_db(
            scan_doc=scan_doc,
            findings=findings,
            dependencies=dependencies,
        )

        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=None)
        mock_repo.create = AsyncMock(side_effect=lambda m: m)

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.upload_bytes", new_callable=AsyncMock) as mock_upload,
            patch(f"{MODULE}.settings") as mock_settings,
        ):
            mock_settings.S3_BUCKET_NAME = "dc-archives"
            result = asyncio.run(archive_scan(db, "scan-1"))

        assert result is not None
        assert result.scan_id == "scan-1"
        assert result.project_id == "proj-1"
        assert result.s3_key == "proj-1/scan-1.json.gz"
        mock_upload.assert_called_once()
        mock_repo.create.assert_called_once()

        # Verify the uploaded data is valid gzip JSON
        uploaded_data = mock_upload.call_args[0][1]
        decompressed = gzip.decompress(uploaded_data)
        bundle = json.loads(decompressed)
        assert bundle["scan_id"] == "scan-1"
        assert len(bundle["findings"]) == 1
        assert len(bundle["dependencies"]) == 1

    def test_returns_none_on_s3_upload_failure(self):
        scan_doc = _make_scan_doc()
        db = _make_mock_db(scan_doc=scan_doc)

        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=None)

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.upload_bytes", new_callable=AsyncMock, side_effect=Exception("S3 error")),
            patch(f"{MODULE}.settings") as mock_settings,
        ):
            mock_settings.S3_BUCKET_NAME = "dc-archives"
            result = asyncio.run(archive_scan(db, "scan-1"))

        assert result is None
        mock_repo.create.assert_not_called()

    def test_includes_gridfs_sboms_in_bundle(self):
        scan_doc = _make_scan_doc(sbom_refs=[
            {"type": "gridfs_reference", "gridfs_id": "gfs-1"},
        ])
        db = _make_mock_db(scan_doc=scan_doc)

        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=None)
        mock_repo.create = AsyncMock(side_effect=lambda m: m)

        mock_sbom_data = [{"gridfs_id": "gfs-1", "filename": "sbom.json", "data": {"bomFormat": "CycloneDX"}}]

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.upload_bytes", new_callable=AsyncMock) as mock_upload,
            patch(f"{MODULE}._load_gridfs_sboms", new_callable=AsyncMock, return_value=mock_sbom_data),
            patch(f"{MODULE}.settings") as mock_settings,
        ):
            mock_settings.S3_BUCKET_NAME = "dc-archives"
            result = asyncio.run(archive_scan(db, "scan-1"))

        assert result is not None
        uploaded_data = mock_upload.call_args[0][1]
        bundle = json.loads(gzip.decompress(uploaded_data))
        assert len(bundle["gridfs_sboms"]) == 1
        assert bundle["gridfs_sboms"][0]["data"]["bomFormat"] == "CycloneDX"


# ---------------------------------------------------------------------------
# restore_scan
# ---------------------------------------------------------------------------

class TestRestoreScan:
    def test_returns_none_when_s3_not_configured(self):
        with patch(f"{MODULE}.is_archive_enabled", return_value=False):
            result = asyncio.run(restore_scan(MagicMock(), "scan-1"))
        assert result is None

    def test_returns_none_when_no_archive_metadata(self):
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=None)

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
        ):
            result = asyncio.run(restore_scan(MagicMock(), "scan-1"))

        assert result is None

    def test_returns_none_when_s3_download_fails(self):
        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.download_bytes", new_callable=AsyncMock, side_effect=Exception("Download failed")),
        ):
            result = asyncio.run(restore_scan(MagicMock(), "scan-1"))

        assert result is None

    def test_returns_none_when_scan_already_exists(self):
        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)

        # Create a valid compressed bundle
        bundle = {
            "version": 1,
            "scan": {"_id": "scan-1", "project_id": "proj-1"},
            "findings": [],
            "finding_records": [],
            "dependencies": [],
            "analysis_results": [],
            "callgraphs": [],
            "gridfs_sboms": [],
        }
        compressed = gzip.compress(json.dumps(bundle).encode("utf-8"))

        db = MagicMock()
        # Scan already exists in DB
        db.scans.find_one = AsyncMock(return_value={"_id": "scan-1"})

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.download_bytes", new_callable=AsyncMock, return_value=compressed),
        ):
            result = asyncio.run(restore_scan(db, "scan-1"))

        assert result is None

    def test_restores_scan_successfully(self):
        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)
        mock_repo.delete_by_scan_id = AsyncMock(return_value=True)

        bundle = {
            "version": 1,
            "scan": {"_id": "scan-1", "project_id": "proj-1", "status": "completed"},
            "findings": [{"_id": "f-1", "scan_id": "scan-1"}],
            "finding_records": [{"_id": "fr-1", "scan_id": "scan-1"}],
            "dependencies": [{"_id": "d-1", "scan_id": "scan-1"}],
            "analysis_results": [],
            "callgraphs": [],
            "gridfs_sboms": [],
        }
        compressed = gzip.compress(json.dumps(bundle).encode("utf-8"))

        db = MagicMock()
        # Scan does NOT exist in DB yet
        db.scans.find_one = AsyncMock(return_value=None)
        db.scans.insert_one = AsyncMock()
        db.findings.insert_many = AsyncMock()
        db.finding_records.insert_many = AsyncMock()
        db.dependencies.insert_many = AsyncMock()
        db.analysis_results.insert_many = AsyncMock()
        db.callgraphs.insert_many = AsyncMock()

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.download_bytes", new_callable=AsyncMock, return_value=compressed),
            patch(f"{MODULE}.delete_object", new_callable=AsyncMock) as mock_delete_s3,
        ):
            result = asyncio.run(restore_scan(db, "scan-1"))

        assert result is not None
        assert result["scan_id"] == "scan-1"
        assert result["project_id"] == "proj-1"
        assert "scans" in result["collections_restored"]
        assert "findings" in result["collections_restored"]
        assert "finding_records" in result["collections_restored"]
        assert "dependencies" in result["collections_restored"]

        db.scans.insert_one.assert_called_once()
        db.findings.insert_many.assert_called_once()
        db.finding_records.insert_many.assert_called_once()
        db.dependencies.insert_many.assert_called_once()
        mock_delete_s3.assert_called_once_with("proj-1/scan-1.json.gz")
        mock_repo.delete_by_scan_id.assert_called_once_with("scan-1")

    def test_restore_handles_gridfs_sboms(self):
        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)
        mock_repo.delete_by_scan_id = AsyncMock(return_value=True)

        bundle = {
            "version": 1,
            "scan": {"_id": "scan-1", "project_id": "proj-1"},
            "findings": [],
            "finding_records": [],
            "dependencies": [],
            "analysis_results": [],
            "callgraphs": [],
            "gridfs_sboms": [
                {"gridfs_id": "507f1f77bcf86cd799439011", "filename": "sbom.json", "data": {"bomFormat": "CycloneDX"}},
            ],
        }
        compressed = gzip.compress(json.dumps(bundle).encode("utf-8"))

        db = MagicMock()
        db.scans.find_one = AsyncMock(return_value=None)
        db.scans.insert_one = AsyncMock()

        mock_fs = MagicMock()
        mock_fs.upload_from_stream_with_id = AsyncMock()

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.download_bytes", new_callable=AsyncMock, return_value=compressed),
            patch(f"{MODULE}.delete_object", new_callable=AsyncMock),
            patch(f"{MODULE}.AsyncIOMotorGridFSBucket", return_value=mock_fs),
        ):
            result = asyncio.run(restore_scan(db, "scan-1"))

        assert result is not None
        assert "gridfs_sboms" in result["collections_restored"]
        mock_fs.upload_from_stream_with_id.assert_called_once()

    def test_restore_continues_if_s3_delete_fails(self):
        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)
        mock_repo.delete_by_scan_id = AsyncMock(return_value=True)

        bundle = {
            "version": 1,
            "scan": {"_id": "scan-1", "project_id": "proj-1"},
            "findings": [],
            "finding_records": [],
            "dependencies": [],
            "analysis_results": [],
            "callgraphs": [],
            "gridfs_sboms": [],
        }
        compressed = gzip.compress(json.dumps(bundle).encode("utf-8"))

        db = MagicMock()
        db.scans.find_one = AsyncMock(return_value=None)
        db.scans.insert_one = AsyncMock()

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.download_bytes", new_callable=AsyncMock, return_value=compressed),
            patch(f"{MODULE}.delete_object", new_callable=AsyncMock, side_effect=Exception("S3 delete failed")),
        ):
            result = asyncio.run(restore_scan(db, "scan-1"))

        # Restore should still succeed even if S3 cleanup fails
        assert result is not None
        assert result["scan_id"] == "scan-1"
        mock_repo.delete_by_scan_id.assert_called_once()


# ---------------------------------------------------------------------------
# archive_scan with encryption
# ---------------------------------------------------------------------------

class TestArchiveScanEncryption:
    def test_archives_with_encryption(self):
        scan_doc = _make_scan_doc()
        db = _make_mock_db(scan_doc=scan_doc)

        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=None)
        mock_repo.create = AsyncMock(side_effect=lambda m: m)

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.upload_bytes", new_callable=AsyncMock) as mock_upload,
            patch(f"{MODULE}.settings") as mock_settings,
            patch(f"{MODULE}.is_encryption_enabled", return_value=True),
            patch(f"{MODULE}.encrypt", return_value=b"encrypted-data") as mock_encrypt,
        ):
            mock_settings.S3_BUCKET_NAME = "dc-archives"
            result = asyncio.run(archive_scan(db, "scan-1"))

        assert result is not None
        mock_encrypt.assert_called_once()
        # Upload should receive the encrypted data, not raw compressed
        uploaded_data = mock_upload.call_args[0][1]
        assert uploaded_data == b"encrypted-data"

    def test_archives_without_encryption(self):
        scan_doc = _make_scan_doc()
        db = _make_mock_db(scan_doc=scan_doc)

        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=None)
        mock_repo.create = AsyncMock(side_effect=lambda m: m)

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.upload_bytes", new_callable=AsyncMock) as mock_upload,
            patch(f"{MODULE}.settings") as mock_settings,
            patch(f"{MODULE}.is_encryption_enabled", return_value=False),
            patch(f"{MODULE}.encrypt") as mock_encrypt,
        ):
            mock_settings.S3_BUCKET_NAME = "dc-archives"
            result = asyncio.run(archive_scan(db, "scan-1"))

        assert result is not None
        mock_encrypt.assert_not_called()
        # Upload should receive raw gzip data
        uploaded_data = mock_upload.call_args[0][1]
        decompressed = gzip.decompress(uploaded_data)
        bundle = json.loads(decompressed)
        assert bundle["scan_id"] == "scan-1"


# ---------------------------------------------------------------------------
# restore_scan with encryption
# ---------------------------------------------------------------------------

class TestRestoreScanEncryption:
    def test_restores_encrypted_archive(self):
        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)
        mock_repo.delete_by_scan_id = AsyncMock(return_value=True)

        bundle = {
            "version": 1,
            "scan": {"_id": "scan-1", "project_id": "proj-1"},
            "findings": [],
            "finding_records": [],
            "dependencies": [],
            "analysis_results": [],
            "callgraphs": [],
            "gridfs_sboms": [],
        }
        compressed = gzip.compress(json.dumps(bundle).encode("utf-8"))

        db = MagicMock()
        db.scans.find_one = AsyncMock(return_value=None)
        db.scans.insert_one = AsyncMock()

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.download_bytes", new_callable=AsyncMock, return_value=b"encrypted-blob"),
            patch(f"{MODULE}.delete_object", new_callable=AsyncMock),
            patch(f"{MODULE}.is_encryption_enabled", return_value=True),
            patch(f"{MODULE}.decrypt", return_value=compressed) as mock_decrypt,
        ):
            result = asyncio.run(restore_scan(db, "scan-1"))

        assert result is not None
        mock_decrypt.assert_called_once_with(b"encrypted-blob")
        assert result["scan_id"] == "scan-1"

    def test_restores_without_encryption(self):
        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)
        mock_repo.delete_by_scan_id = AsyncMock(return_value=True)

        bundle = {
            "version": 1,
            "scan": {"_id": "scan-1", "project_id": "proj-1"},
            "findings": [],
            "finding_records": [],
            "dependencies": [],
            "analysis_results": [],
            "callgraphs": [],
            "gridfs_sboms": [],
        }
        compressed = gzip.compress(json.dumps(bundle).encode("utf-8"))

        db = MagicMock()
        db.scans.find_one = AsyncMock(return_value=None)
        db.scans.insert_one = AsyncMock()

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.download_bytes", new_callable=AsyncMock, return_value=compressed),
            patch(f"{MODULE}.delete_object", new_callable=AsyncMock),
            patch(f"{MODULE}.is_encryption_enabled", return_value=False),
            patch(f"{MODULE}.decrypt") as mock_decrypt,
        ):
            result = asyncio.run(restore_scan(db, "scan-1"))

        assert result is not None
        mock_decrypt.assert_not_called()
        assert result["scan_id"] == "scan-1"
