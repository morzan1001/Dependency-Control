"""Tests for archive API endpoints.

Tests list, restore, download, pin/unpin, branches, admin list,
and permission enforcement with mocked dependencies.
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
        "findings_count": 5,
        "critical_findings_count": 1,
        "high_findings_count": 2,
        "dependencies_count": 10,
        "sbom_filenames": ["sbom.json"],
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

    def test_returns_extended_metadata_fields(self, admin_user):
        from app.api.v1.endpoints.archives import list_archives

        archives = [_make_archive_metadata(
            findings_count=10,
            critical_findings_count=3,
            high_findings_count=4,
            dependencies_count=25,
            sbom_filenames=["sbom-a.json", "sbom-b.json"],
        )]

        mock_repo = MagicMock()
        mock_repo.count_by_project = AsyncMock(return_value=1)
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

        item = result.items[0]
        assert item.findings_count == 10
        assert item.critical_findings_count == 3
        assert item.high_findings_count == 4
        assert item.dependencies_count == 25
        assert item.sbom_filenames == ["sbom-a.json", "sbom-b.json"]

    def test_passes_filters_to_repository(self, admin_user):
        from app.api.v1.endpoints.archives import list_archives

        mock_repo = MagicMock()
        mock_repo.count_by_project = AsyncMock(return_value=0)
        mock_repo.find_by_project = AsyncMock(return_value=[])

        date_from = datetime(2025, 1, 1, tzinfo=timezone.utc)
        date_to = datetime(2025, 6, 1, tzinfo=timezone.utc)

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
        ):
            asyncio.run(
                list_archives(
                    project_id="proj-1",
                    current_user=admin_user,
                    db=MagicMock(),
                    page=1,
                    size=20,
                    branch="develop",
                    date_from=date_from,
                    date_to=date_to,
                )
            )

        # Verify filters were passed to repo methods
        count_kwargs = mock_repo.count_by_project.call_args
        assert count_kwargs[1]["branch"] == "develop" or count_kwargs[0][1] == "develop"
        find_kwargs = mock_repo.find_by_project.call_args
        assert "branch" in str(find_kwargs)

    def test_raises_403_without_archive_read_permission(self, no_perms_user):
        from app.api.v1.endpoints.archives import list_archives

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                list_archives(
                    project_id="proj-1",
                    current_user=no_perms_user,
                    db=MagicMock(),
                    page=1,
                    size=20,
                )
            )

        assert exc_info.value.status_code == 403

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
        from app.schemas.archive import ArchiveRestoreResponse

        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)

        restore_result = ArchiveRestoreResponse(
            scan_id="scan-1",
            project_id="proj-1",
            collections_restored=["scans", "findings"],
        )

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

    def test_raises_403_without_archive_download_permission(self, no_perms_user):
        from app.api.v1.endpoints.archives import download_archive

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                download_archive(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=no_perms_user,
                    db=MagicMock(),
                )
            )

        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# list_archive_branches
# ---------------------------------------------------------------------------

class TestListArchiveBranches:
    def test_returns_branch_list(self, admin_user):
        from app.api.v1.endpoints.archives import list_archive_branches

        mock_repo = MagicMock()
        mock_repo.get_distinct_branches = AsyncMock(return_value=["main", "develop", "feature/test"])

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
        ):
            result = asyncio.run(
                list_archive_branches(
                    project_id="proj-1",
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert result == ["main", "develop", "feature/test"]

    def test_raises_403_without_archive_read_permission(self, no_perms_user):
        from app.api.v1.endpoints.archives import list_archive_branches

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                list_archive_branches(
                    project_id="proj-1",
                    current_user=no_perms_user,
                    db=MagicMock(),
                )
            )

        assert exc_info.value.status_code == 403

    def test_raises_501_when_s3_not_configured(self, admin_user):
        from app.api.v1.endpoints.archives import list_archive_branches

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=False),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(
                list_archive_branches(
                    project_id="proj-1",
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert exc_info.value.status_code == 501


# ---------------------------------------------------------------------------
# pin_scan / unpin_scan
# ---------------------------------------------------------------------------

class TestPinScan:
    def test_pins_scan_successfully(self, admin_user):
        from app.api.v1.endpoints.archives import pin_scan

        mock_db = MagicMock()
        mock_db.scans.find_one = AsyncMock(return_value={"_id": "scan-1", "project_id": "proj-1"})
        mock_db.scans.update_one = AsyncMock()

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
        ):
            result = asyncio.run(
                pin_scan(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=mock_db,
                )
            )

        assert result.scan_id == "scan-1"
        assert result.pinned is True
        mock_db.scans.update_one.assert_called_once_with(
            {"_id": "scan-1"}, {"$set": {"pinned": True}}
        )

    def test_raises_404_when_scan_not_found(self, admin_user):
        from app.api.v1.endpoints.archives import pin_scan

        mock_db = MagicMock()
        mock_db.scans.find_one = AsyncMock(return_value=None)

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(
                pin_scan(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=mock_db,
                )
            )

        assert exc_info.value.status_code == 404

    def test_raises_403_without_archive_restore_permission(self, no_perms_user):
        from app.api.v1.endpoints.archives import pin_scan

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                pin_scan(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=no_perms_user,
                    db=MagicMock(),
                )
            )

        assert exc_info.value.status_code == 403


class TestUnpinScan:
    def test_unpins_scan_successfully(self, admin_user):
        from app.api.v1.endpoints.archives import unpin_scan

        mock_db = MagicMock()
        mock_db.scans.find_one = AsyncMock(return_value={"_id": "scan-1", "project_id": "proj-1"})
        mock_db.scans.update_one = AsyncMock()

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
        ):
            result = asyncio.run(
                unpin_scan(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=mock_db,
                )
            )

        assert result.scan_id == "scan-1"
        assert result.pinned is False
        mock_db.scans.update_one.assert_called_once_with(
            {"_id": "scan-1"}, {"$set": {"pinned": False}}
        )

    def test_raises_404_when_scan_not_found(self, admin_user):
        from app.api.v1.endpoints.archives import unpin_scan

        mock_db = MagicMock()
        mock_db.scans.find_one = AsyncMock(return_value=None)

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(
                unpin_scan(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=mock_db,
                )
            )

        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# list_all_archives (admin endpoint)
# ---------------------------------------------------------------------------

class TestListAllArchives:
    def test_returns_archives_with_project_names(self, admin_user):
        from app.api.v1.endpoints.archives import list_all_archives

        archives = [
            _make_archive_metadata(scan_id="scan-1", project_id="proj-1"),
            _make_archive_metadata(id="archive-2", scan_id="scan-2", project_id="proj-2"),
        ]

        mock_repo = MagicMock()
        mock_repo.count_all = AsyncMock(return_value=2)
        mock_repo.find_all = AsyncMock(return_value=archives)

        # Mock DB for project name lookup
        mock_db = MagicMock()
        project_docs = [
            {"_id": "proj-1", "name": "Project Alpha"},
            {"_id": "proj-2", "name": "Project Beta"},
        ]

        async def async_iter():
            for doc in project_docs:
                yield doc

        mock_cursor = MagicMock()
        mock_cursor.__aiter__ = lambda self: async_iter()
        mock_db.projects.find = MagicMock(return_value=mock_cursor)

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
        ):
            result = asyncio.run(
                list_all_archives(
                    current_user=admin_user,
                    db=mock_db,
                    page=1,
                    size=20,
                )
            )

        assert result.total == 2
        assert len(result.items) == 2
        assert result.items[0].project_id == "proj-1"
        assert result.items[0].project_name == "Project Alpha"
        assert result.items[1].project_name == "Project Beta"

    def test_raises_403_without_archive_read_all_permission(self, regular_user):
        from app.api.v1.endpoints.archives import list_all_archives

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                list_all_archives(
                    current_user=regular_user,
                    db=MagicMock(),
                    page=1,
                    size=20,
                )
            )

        assert exc_info.value.status_code == 403

    def test_passes_filters_including_project_id(self, admin_user):
        from app.api.v1.endpoints.archives import list_all_archives

        mock_repo = MagicMock()
        mock_repo.count_all = AsyncMock(return_value=0)
        mock_repo.find_all = AsyncMock(return_value=[])

        mock_db = MagicMock()
        mock_db.projects.find = MagicMock(return_value=MagicMock(__aiter__=lambda self: aiter([])))

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
        ):
            asyncio.run(
                list_all_archives(
                    current_user=admin_user,
                    db=mock_db,
                    page=1,
                    size=20,
                    project_id="proj-1",
                    branch="main",
                )
            )

        # Verify project_id and branch were passed to count_all
        count_kwargs = mock_repo.count_all.call_args[1]
        assert count_kwargs.get("project_id") == "proj-1"
        assert count_kwargs.get("branch") == "main"


# ---------------------------------------------------------------------------
# Permission enforcement on restore
# ---------------------------------------------------------------------------

class TestRestoreArchivePermissions:
    def test_raises_403_without_archive_restore_permission(self, no_perms_user):
        from app.api.v1.endpoints.archives import restore_archive

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                restore_archive(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=no_perms_user,
                    db=MagicMock(),
                )
            )

        assert exc_info.value.status_code == 403
