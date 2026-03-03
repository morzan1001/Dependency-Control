"""Tests for archive API endpoints.

Tests list, restore, and download endpoints with mocked dependencies.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
import pytest

from app.models.archive import ArchiveMetadata

MODULE = "app.api.v1.endpoints.archives"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_archive_metadata(**overrides):
    """Create an ArchiveMetadata instance for testing."""
    defaults = {
        "id": "archive-1",
        "project_id": "proj-1",
        "scan_id": "scan-1",
        "s3_key": "proj-1/scan-1.json.gz",
        "s3_bucket": "dc-archives",
        "branch": "main",
        "commit_hash": "abc123",
        "scan_created_at": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "archived_at": datetime(2025, 6, 1, tzinfo=timezone.utc),
        "compressed_size_bytes": 1000,
        "original_size_bytes": 5000,
    }
    defaults.update(overrides)
    return ArchiveMetadata(**defaults)


# ---------------------------------------------------------------------------
# list_archives
# ---------------------------------------------------------------------------

class TestListArchives:
    def test_returns_paginated_archives(self, admin_user):
        from app.api.v1.endpoints.archives import list_archives

        archives = [
            _make_archive_metadata(scan_id="scan-1"),
            _make_archive_metadata(id="archive-2", scan_id="scan-2"),
        ]

        mock_repo = MagicMock()
        mock_repo.count_by_project = AsyncMock(return_value=2)
        mock_repo.find_by_project = AsyncMock(return_value=archives)

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
        ):
            result = asyncio.run(
                list_archives(
                    project_id="proj-1",
                    current_user=admin_user,
                    db=MagicMock(),
                    page=1,
                    size=20,
                )
            )

        assert result.total == 2
        assert len(result.items) == 2
        assert result.items[0].scan_id == "scan-1"
        assert result.page == 1
        assert result.pages == 1

    def test_raises_501_when_s3_not_configured(self, admin_user):
        from app.api.v1.endpoints.archives import list_archives

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=False),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(
                list_archives(
                    project_id="proj-1",
                    current_user=admin_user,
                    db=MagicMock(),
                    page=1,
                    size=20,
                )
            )

        assert exc_info.value.status_code == 501

    def test_empty_archives(self, admin_user):
        from app.api.v1.endpoints.archives import list_archives

        mock_repo = MagicMock()
        mock_repo.count_by_project = AsyncMock(return_value=0)
        mock_repo.find_by_project = AsyncMock(return_value=[])

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
        ):
            result = asyncio.run(
                list_archives(
                    project_id="proj-1",
                    current_user=admin_user,
                    db=MagicMock(),
                    page=1,
                    size=20,
                )
            )

        assert result.total == 0
        assert len(result.items) == 0
        assert result.pages == 1

    def test_pagination_calculates_pages(self, admin_user):
        from app.api.v1.endpoints.archives import list_archives

        mock_repo = MagicMock()
        mock_repo.count_by_project = AsyncMock(return_value=45)
        mock_repo.find_by_project = AsyncMock(return_value=[])

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
        ):
            result = asyncio.run(
                list_archives(
                    project_id="proj-1",
                    current_user=admin_user,
                    db=MagicMock(),
                    page=2,
                    size=20,
                )
            )

        assert result.total == 45
        assert result.pages == 3
        assert result.page == 2


# ---------------------------------------------------------------------------
# restore_archive
# ---------------------------------------------------------------------------

class TestRestoreArchive:
    def test_restores_archive_successfully(self, admin_user):
        from app.api.v1.endpoints.archives import restore_archive

        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)

        restore_result = {
            "scan_id": "scan-1",
            "project_id": "proj-1",
            "collections_restored": ["scans", "findings"],
        }

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.restore_scan", new_callable=AsyncMock, return_value=restore_result),
        ):
            result = asyncio.run(
                restore_archive(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert result.scan_id == "scan-1"
        assert "scans" in result.collections_restored

    def test_raises_501_when_s3_not_configured(self, admin_user):
        from app.api.v1.endpoints.archives import restore_archive

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=False),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(
                restore_archive(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert exc_info.value.status_code == 501

    def test_raises_404_when_archive_not_found(self, admin_user):
        from app.api.v1.endpoints.archives import restore_archive

        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=None)

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(
                restore_archive(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert exc_info.value.status_code == 404

    def test_raises_404_when_archive_belongs_to_different_project(self, admin_user):
        from app.api.v1.endpoints.archives import restore_archive

        metadata = _make_archive_metadata(project_id="other-project")
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(
                restore_archive(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert exc_info.value.status_code == 404

    def test_raises_500_when_restore_fails(self, admin_user):
        from app.api.v1.endpoints.archives import restore_archive

        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.restore_scan", new_callable=AsyncMock, return_value=None),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(
                restore_archive(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert exc_info.value.status_code == 500


# ---------------------------------------------------------------------------
# download_archive
# ---------------------------------------------------------------------------

class TestDownloadArchive:
    def test_downloads_archive(self, admin_user):
        from app.api.v1.endpoints.archives import download_archive

        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)

        archive_data = b"compressed-data"

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.download_bytes", new_callable=AsyncMock, return_value=archive_data),
        ):
            result = asyncio.run(
                download_archive(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert result.media_type == "application/gzip"
        assert result.headers["Content-Disposition"] == 'attachment; filename="scan-1.json.gz"'
        assert result.headers["Content-Length"] == str(len(archive_data))

    def test_raises_501_when_s3_not_configured(self, admin_user):
        from app.api.v1.endpoints.archives import download_archive

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=False),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(
                download_archive(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert exc_info.value.status_code == 501

    def test_raises_404_when_archive_not_found(self, admin_user):
        from app.api.v1.endpoints.archives import download_archive

        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=None)

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(
                download_archive(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert exc_info.value.status_code == 404

    def test_raises_500_when_s3_download_fails(self, admin_user):
        from app.api.v1.endpoints.archives import download_archive

        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch(f"{MODULE}.download_bytes", new_callable=AsyncMock, side_effect=Exception("S3 error")),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(
                download_archive(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert exc_info.value.status_code == 500

    def test_raises_404_when_archive_belongs_to_different_project(self, admin_user):
        from app.api.v1.endpoints.archives import download_archive

        metadata = _make_archive_metadata(project_id="other-project")
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(
                download_archive(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert exc_info.value.status_code == 404
