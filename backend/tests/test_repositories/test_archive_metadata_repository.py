"""ArchiveMetadataRepository queries and CRUD, driven through FakeDatabase."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.archive import ArchiveMetadata
from app.repositories.archive_metadata import ArchiveMetadataRepository
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT = "proj-1"
_OTHER_PROJECT = "proj-2"
_MAIN = "main"
_FEATURE = "feature"
_OTHER_BRANCH = "release"
_T0 = datetime(2025, 6, 1, tzinfo=timezone.utc)
_DAY = timedelta(days=1)
_ARCHIVE_COUNT = 3


def _archive_doc(archive_id, project_id=_PROJECT, branch=_MAIN, archived_at=_T0, scan_created_at=_T0):
    return {
        "_id": archive_id,
        "project_id": project_id,
        "scan_id": f"scan-{archive_id}",
        "s3_key": f"{project_id}/{archive_id}.json.gz",
        "s3_bucket": "dc-archives",
        "archived_at": archived_at,
        "scan_created_at": scan_created_at,
        "branch": branch,
        "commit_hash": "abc123",
        "original_size_bytes": 5000,
        "compressed_size_bytes": 1000,
    }


@pytest.fixture
def db():
    database = FakeDatabase()
    for index in range(_ARCHIVE_COUNT):
        database.archive_metadata._docs[f"a-{index}"] = _archive_doc(
            f"a-{index}", archived_at=_T0 + index * _DAY, scan_created_at=_T0 + index * _DAY
        )
    # Distinct timestamps throughout: a tie on archived_at would make the sort order insertion order.
    database.archive_metadata._docs["a-feature"] = _archive_doc(
        "a-feature", branch=_FEATURE, archived_at=_T0 - _DAY, scan_created_at=_T0 - _DAY
    )
    database.archive_metadata._docs["b-0"] = _archive_doc(
        "b-0", project_id=_OTHER_PROJECT, branch=_OTHER_BRANCH
    )
    return database


class TestFindByProject:
    @pytest.mark.asyncio
    async def test_newest_archive_first_and_this_project_only(self, db):
        repo = ArchiveMetadataRepository(db)

        found = await repo.find_by_project(_PROJECT)

        assert [archive.id for archive in found] == ["a-2", "a-1", "a-0", "a-feature"]

    @pytest.mark.asyncio
    async def test_pages_from_the_requested_offset(self, db):
        repo = ArchiveMetadataRepository(db)

        page = await repo.find_by_project(_PROJECT, skip=1, limit=2)

        assert [archive.id for archive in page] == ["a-1", "a-0"]

    @pytest.mark.asyncio
    async def test_the_branch_and_date_window_narrow_the_result(self, db):
        repo = ArchiveMetadataRepository(db)

        assert [a.id for a in await repo.find_by_project(_PROJECT, branch=_FEATURE)] == ["a-feature"]
        windowed = await repo.find_by_project(_PROJECT, date_from=_T0 + _DAY, date_to=_T0 + _DAY)
        assert [a.id for a in windowed] == ["a-1"]

    @pytest.mark.asyncio
    async def test_a_project_with_no_archives_returns_an_empty_list(self, db):
        repo = ArchiveMetadataRepository(db)

        assert await repo.find_by_project("absent") == []


class TestCountByProject:
    @pytest.mark.asyncio
    async def test_counts_this_project_under_the_same_filters(self, db):
        repo = ArchiveMetadataRepository(db)

        assert await repo.count_by_project(_PROJECT) == _ARCHIVE_COUNT + 1
        assert await repo.count_by_project(_PROJECT, branch=_FEATURE) == 1
        assert await repo.count_by_project("absent") == 0


class TestFindAndDeleteByScanId:
    @pytest.mark.asyncio
    async def test_the_archive_of_a_known_scan_is_found_and_deleted_once(self, db):
        repo = ArchiveMetadataRepository(db)

        found = await repo.find_by_scan_id("scan-a-0")
        assert found is not None
        assert found.s3_key == f"{_PROJECT}/a-0.json.gz"

        assert await repo.delete_by_scan_id("scan-a-0") is True
        assert await repo.find_by_scan_id("scan-a-0") is None
        assert await repo.delete_by_scan_id("scan-a-0") is False

    @pytest.mark.asyncio
    async def test_an_unknown_scan_resolves_to_nothing(self, db):
        repo = ArchiveMetadataRepository(db)

        assert await repo.find_by_scan_id("nonexistent") is None


class TestDistinctBranches:
    @pytest.mark.asyncio
    async def test_the_branches_of_this_project_are_listed_once_and_sorted(self, db):
        repo = ArchiveMetadataRepository(db)

        assert await repo.get_distinct_branches(_PROJECT) == [_FEATURE, _MAIN]


class TestCRUD:
    @pytest.mark.asyncio
    async def test_a_created_archive_is_readable_by_id(self, db):
        repo = ArchiveMetadataRepository(db)
        metadata = ArchiveMetadata(
            project_id=_PROJECT,
            scan_id="scan-new",
            s3_key=f"{_PROJECT}/scan-new.json.gz",
            s3_bucket="dc-archives",
        )

        created = await repo.create(metadata)

        assert (await repo.get_by_id(created.id)).scan_id == "scan-new"

    @pytest.mark.asyncio
    async def test_an_unknown_id_resolves_to_nothing(self, db):
        repo = ArchiveMetadataRepository(db)

        assert await repo.get_by_id("nonexistent") is None
