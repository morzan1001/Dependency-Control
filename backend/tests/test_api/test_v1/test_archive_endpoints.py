"""Tests for archive API endpoints (list, restore, download, pin/unpin, branches, admin list, permissions)."""

import asyncio
import hashlib
import zlib
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.models.archive import ArchiveMetadata
from tests.helpers.fake_s3 import FakeS3Client, fake_get_s3_client
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.api.v1.endpoints.archives"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_archive_metadata(**overrides):
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


def _assert_501_without_s3(endpoint, **call_kwargs):
    with (
        patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
        patch(f"{MODULE}.is_archive_enabled", return_value=False),
        pytest.raises(HTTPException) as exc_info,
    ):
        asyncio.run(endpoint(**call_kwargs))

    assert exc_info.value.status_code == 501


def _assert_404_when_archive_missing(endpoint, *, metadata, **call_kwargs):
    mock_repo = MagicMock()
    mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)

    with (
        patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
        patch(f"{MODULE}.is_archive_enabled", return_value=True),
        patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
        pytest.raises(HTTPException) as exc_info,
    ):
        asyncio.run(endpoint(**call_kwargs))

    assert exc_info.value.status_code == 404


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
        mock_repo.count_all = AsyncMock(return_value=2)
        mock_repo.find_all = AsyncMock(return_value=archives)

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

        archives = [
            _make_archive_metadata(
                findings_count=10,
                critical_findings_count=3,
                high_findings_count=4,
                dependencies_count=25,
                sbom_filenames=["sbom-a.json", "sbom-b.json"],
            )
        ]

        mock_repo = MagicMock()
        mock_repo.count_all = AsyncMock(return_value=1)
        mock_repo.find_all = AsyncMock(return_value=archives)

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
        mock_repo.count_all = AsyncMock(return_value=0)
        mock_repo.find_all = AsyncMock(return_value=[])

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

        count_kwargs = mock_repo.count_all.call_args
        assert count_kwargs.kwargs["branch"] == "develop"
        find_kwargs = mock_repo.find_all.call_args
        assert "branch" in str(find_kwargs)

    def test_page_number_skips_whole_pages_starting_at_zero(self, admin_user):
        """A skip off by one page would hide the newest archives while total keeps counting them."""
        from app.api.v1.endpoints.archives import list_archives

        mock_repo = MagicMock()
        mock_repo.count_all = AsyncMock(return_value=0)
        mock_repo.find_all = AsyncMock(return_value=[])

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
        ):
            for page, expected_skip in ((1, 0), (2, 5), (3, 10)):
                asyncio.run(
                    list_archives(
                        project_id="proj-1",
                        current_user=admin_user,
                        db=MagicMock(),
                        page=page,
                        size=5,
                    )
                )
                assert mock_repo.find_all.call_args.kwargs["skip"] == expected_skip

    def test_raises_501_when_s3_not_configured(self, admin_user):
        from app.api.v1.endpoints.archives import list_archives

        _assert_501_without_s3(
            list_archives,
            project_id="proj-1",
            current_user=admin_user,
            db=MagicMock(),
            page=1,
            size=20,
        )

    def test_empty_archives(self, admin_user):
        from app.api.v1.endpoints.archives import list_archives

        mock_repo = MagicMock()
        mock_repo.count_all = AsyncMock(return_value=0)
        mock_repo.find_all = AsyncMock(return_value=[])

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
        mock_repo.count_all = AsyncMock(return_value=45)
        mock_repo.find_all = AsyncMock(return_value=[])

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

        _assert_501_without_s3(
            restore_archive,
            project_id="proj-1",
            scan_id="scan-1",
            current_user=admin_user,
            db=MagicMock(),
        )

    def test_raises_404_when_archive_not_found(self, admin_user):
        from app.api.v1.endpoints.archives import restore_archive

        _assert_404_when_archive_missing(
            restore_archive,
            metadata=None,
            project_id="proj-1",
            scan_id="scan-1",
            current_user=admin_user,
            db=MagicMock(),
        )

    def test_raises_404_when_archive_belongs_to_different_project(self, admin_user):
        from app.api.v1.endpoints.archives import restore_archive

        _assert_404_when_archive_missing(
            restore_archive,
            metadata=_make_archive_metadata(project_id="other-project"),
            project_id="proj-1",
            scan_id="scan-1",
            current_user=admin_user,
            db=MagicMock(),
        )

    def test_raises_500_when_restore_fails(self, admin_user):
        from app.api.v1.endpoints.archives import restore_archive

        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)

        # find_one None so the endpoint maps to 500, not 409
        mock_db = MagicMock()
        mock_db.scans.find_one = AsyncMock(return_value=None)

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
                    db=mock_db,
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

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
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

    def test_raises_501_when_s3_not_configured(self, admin_user):
        from app.api.v1.endpoints.archives import download_archive

        _assert_501_without_s3(
            download_archive,
            project_id="proj-1",
            scan_id="scan-1",
            current_user=admin_user,
            db=MagicMock(),
        )

    def test_raises_404_when_archive_not_found(self, admin_user):
        from app.api.v1.endpoints.archives import download_archive

        _assert_404_when_archive_missing(
            download_archive,
            metadata=None,
            project_id="proj-1",
            scan_id="scan-1",
            current_user=admin_user,
            db=MagicMock(),
        )

    def test_raises_404_when_archive_belongs_to_different_project(self, admin_user):
        from app.api.v1.endpoints.archives import download_archive

        _assert_404_when_archive_missing(
            download_archive,
            metadata=_make_archive_metadata(project_id="other-project"),
            project_id="proj-1",
            scan_id="scan-1",
            current_user=admin_user,
            db=MagicMock(),
        )


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

    def test_raises_501_when_s3_not_configured(self, admin_user):
        from app.api.v1.endpoints.archives import list_archive_branches

        _assert_501_without_s3(
            list_archive_branches,
            project_id="proj-1",
            current_user=admin_user,
            db=MagicMock(),
        )


# ---------------------------------------------------------------------------
# pin_scan / unpin_scan
# ---------------------------------------------------------------------------


class TestPinScan:
    def test_pins_scan_successfully(self, admin_user):
        from app.api.v1.endpoints.archives import pin_scan

        mock_db = MagicMock()
        mock_db.scans.update_one = AsyncMock(return_value=MagicMock(matched_count=1))

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
            {"_id": "scan-1", "project_id": "proj-1"}, {"$set": {"pinned": True}}
        )

    def test_raises_404_when_scan_not_found(self, admin_user):
        from app.api.v1.endpoints.archives import pin_scan

        mock_db = MagicMock()
        mock_db.scans.update_one = AsyncMock(return_value=MagicMock(matched_count=0))

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

    @pytest.mark.asyncio
    async def test_a_scan_of_another_project_is_not_pinnable(self, admin_user):
        """FakeDatabase-backed: a mock that answers every find_one the same way cannot tell
        whether the lookup is scoped to the project in the path."""
        from app.api.v1.endpoints.archives import pin_scan

        db = FakeDatabase()
        await db.scans.insert_one({"_id": "scan-1", "project_id": "other-proj"})

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            pytest.raises(HTTPException) as exc_info,
        ):
            await pin_scan(project_id="proj-1", scan_id="scan-1", current_user=admin_user, db=db)

        assert exc_info.value.status_code == 404
        assert (await db.scans.find_one({"_id": "scan-1"})).get("pinned") is None


class TestUnpinScan:
    def test_unpins_scan_successfully(self, admin_user):
        from app.api.v1.endpoints.archives import unpin_scan

        mock_db = MagicMock()
        mock_db.scans.update_one = AsyncMock(return_value=MagicMock(matched_count=1))

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
            {"_id": "scan-1", "project_id": "proj-1"}, {"$set": {"pinned": False}}
        )

    def test_raises_404_when_scan_not_found(self, admin_user):
        from app.api.v1.endpoints.archives import unpin_scan

        mock_db = MagicMock()
        mock_db.scans.update_one = AsyncMock(return_value=MagicMock(matched_count=0))

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

        db = FakeDatabase()
        asyncio.run(db.projects.insert_one({"_id": "proj-1", "name": "Project Alpha"}))
        asyncio.run(db.projects.insert_one({"_id": "proj-2", "name": "Project Beta"}))

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
        ):
            result = asyncio.run(
                list_all_archives(
                    current_user=admin_user,
                    db=db,
                    page=1,
                    size=20,
                )
            )

        assert result.total == 2
        assert len(result.items) == 2
        assert result.items[0].project_id == "proj-1"
        assert result.items[0].project_name == "Project Alpha"
        assert result.items[1].project_name == "Project Beta"

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

        count_kwargs = mock_repo.count_all.call_args[1]
        assert count_kwargs.get("project_id") == "proj-1"
        assert count_kwargs.get("branch") == "main"


# ---------------------------------------------------------------------------
# Permission enforcement on restore
# ---------------------------------------------------------------------------


class TestRestoreArchivePermissions:
    def test_project_viewer_holding_archive_restore_is_still_denied(self):
        """archive:restore is a global grant; writing the scan back still takes the project-admin role."""
        from app.api.v1.endpoints.archives import restore_archive
        from app.core.permissions import Permissions
        from app.models.project import Project, ProjectMember
        from app.models.user import User

        viewer = User(
            id="arch-viewer-1",
            username="archviewer",
            email="archviewer@test.com",
            permissions=[Permissions.PROJECT_READ, Permissions.ARCHIVE_RESTORE],
        )

        async def _run():
            db = FakeDatabase()
            project = Project(
                id="proj-1",
                name="proj-1",
                members=[ProjectMember(user_id="arch-viewer-1", role="viewer")],
            )
            await db.projects.insert_one(project.model_dump(by_alias=True))
            return await restore_archive(
                project_id="proj-1",
                scan_id="scan-1",
                current_user=viewer,
                db=db,
            )

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(_run())

        assert exc_info.value.status_code == 403

    def test_read_all_superuser_without_a_project_role_may_not_restore(self):
        """project:read_all is read-only; it must not open the restore write path."""
        from app.api.v1.endpoints.archives import restore_archive
        from app.core.permissions import Permissions
        from app.models.project import Project
        from app.models.user import User

        reader = User(
            id="arch-readall-1",
            username="archreadall",
            email="archreadall@test.com",
            permissions=[Permissions.PROJECT_READ_ALL, Permissions.ARCHIVE_RESTORE],
        )

        async def _run():
            db = FakeDatabase()
            await db.projects.insert_one(Project(id="proj-1", name="proj-1").model_dump(by_alias=True))
            return await restore_archive(
                project_id="proj-1",
                scan_id="scan-1",
                current_user=reader,
                db=db,
            )

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(_run())

        assert exc_info.value.status_code == 403


_LEGACY_SECRET = "AKIAIOSFODNN7EXAMPLE"
_LEGACY_RAW_HASH = hashlib.md5(_LEGACY_SECRET.encode()).hexdigest()[:8]


async def _aiter(items):
    for item in items:
        yield item


async def _legacy_bundle(*, encrypted: bool) -> bytes:
    """A bundle as archived before ingest hashed TruffleHog's Raw."""
    from app.core.encryption import EncryptionStreamWriter
    from app.services.archive import _gzip_compress_stream
    from app.services.archive_bundle import BundleFrames, BundleStats

    frames = BundleFrames.write(
        scan_doc={"_id": "scan-1", "project_id": "proj-1"},
        collections={
            "findings": _aiter([{"_id": f"SECRET-2-{_LEGACY_RAW_HASH}", "scan_id": "scan-1", "severity": "HIGH"}]),
            "analysis_results": _aiter(
                [
                    {
                        "_id": "r1",
                        "scan_id": "scan-1",
                        "analyzer_name": "trufflehog",
                        "result": {"findings": [{"DetectorType": "2", "Raw": _LEGACY_SECRET}]},
                    }
                ]
            ),
        },
        stats=BundleStats(),
    )
    gzipped = b"".join([chunk async for chunk in _gzip_compress_stream(frames)])
    if not encrypted:
        return gzipped
    collected: list[bytes] = []

    async def sink(chunk: bytes) -> None:
        collected.append(chunk)

    writer = EncryptionStreamWriter(sink)
    await writer.start()
    await writer.write(gzipped)
    await writer.aclose()
    return b"".join(collected)


class _BucketRecordingS3(FakeS3Client):
    def __init__(self) -> None:
        super().__init__()
        self.buckets_read: list[str] = []

    async def get_object(self, Bucket: str, Key: str) -> dict[str, Any]:
        self.buckets_read.append(Bucket)
        return await super().get_object(Bucket, Key)


class TestDownloadStripsPlaintextSecrets:
    @pytest.mark.parametrize("encrypted", [False, True])
    def test_legacy_bundle_downloads_hashed_and_still_restores(self, admin_user, encrypted):
        from app.api.v1.endpoints.archives import download_archive
        from app.services.archive import _replay_bundle

        metadata = _make_archive_metadata(s3_key="proj-1/scan-1-1.bundle", s3_bucket="dc-archives")
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)
        s3 = _BucketRecordingS3()

        async def run_download_and_restore():
            s3.objects["proj-1/scan-1-1.bundle"] = await _legacy_bundle(encrypted=encrypted)
            response = await download_archive(
                project_id="proj-1",
                scan_id="scan-1",
                current_user=admin_user,
                db=MagicMock(),
            )
            body = b"".join([chunk async for chunk in response.body_iterator])
            bundle = zlib.decompress(body, wbits=31)
            db = MagicMock()
            db.scans.insert_one = AsyncMock()
            db.findings.insert_many = AsyncMock()
            db.analysis_results.insert_many = AsyncMock()
            reason, _ = await _replay_bundle(db, "scan-1", _aiter([bundle]))
            return response, bundle, reason, db

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.ArchiveMetadataRepository", return_value=mock_repo),
            patch("app.core.s3.get_s3_client", lambda: fake_get_s3_client(s3)),
            patch("app.core.encryption.settings") as encryption_settings,
        ):
            encryption_settings.ARCHIVE_ENCRYPTION_KEY = "0" * 64
            response, bundle, reason, db = asyncio.run(run_download_and_restore())

        assert response.media_type == "application/gzip"
        assert response.headers["Content-Disposition"] == 'attachment; filename="scan-1.json.gz"'
        assert s3.buckets_read == ["dc-archives"]
        assert _LEGACY_SECRET.encode() not in bundle
        assert reason is None
        (restored_finding,) = db.findings.insert_many.await_args.args[0]
        assert restored_finding["_id"] == f"SECRET-2-{_LEGACY_RAW_HASH}"
        (restored_result,) = db.analysis_results.insert_many.await_args.args[0]
        assert restored_result["result"]["findings"][0]["RawHash"] == _LEGACY_RAW_HASH


class TestRestoreReturns409WhenScanAlreadyExists:
    def test_returns_409_when_scan_already_exists_in_mongo(self, admin_user):
        from app.api.v1.endpoints.archives import restore_archive

        metadata = _make_archive_metadata()
        mock_repo = MagicMock()
        mock_repo.find_by_scan_id = AsyncMock(return_value=metadata)

        mock_db = MagicMock()
        mock_db.scans.find_one = AsyncMock(return_value={"_id": "scan-1"})

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
                    db=mock_db,
                )
            )

        assert exc_info.value.status_code == 409
        assert "already exists" in exc_info.value.detail


class TestPinEmitsAuditLog:
    def test_pin_emits_structured_audit_log(self, admin_user, caplog):
        import logging

        from app.api.v1.endpoints.archives import pin_scan

        mock_db = MagicMock()
        mock_db.scans.update_one = AsyncMock(return_value=MagicMock(matched_count=1))

        with (
            patch(f"{MODULE}.check_project_access", new_callable=AsyncMock),
            caplog.at_level(logging.INFO, logger="app.api.v1.endpoints.archives"),
        ):
            result = asyncio.run(
                pin_scan(
                    project_id="proj-1",
                    scan_id="scan-1",
                    current_user=admin_user,
                    db=mock_db,
                )
            )

        assert result.pinned is True

        audit_records = [r for r in caplog.records if r.message == "archive.pin"]
        assert len(audit_records) == 1
        rec = audit_records[0]
        assert getattr(rec, "scan_id", None) == "scan-1"
        assert getattr(rec, "project_id", None) == "proj-1"
