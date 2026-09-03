"""Release scope must never read as a small healthy fleet: the counters say how many projects
contributed and how many were silently omitted."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.api.v1.endpoints.analytics.search import search_dependencies_advanced, search_vulnerabilities
from app.api.v1.endpoints.analytics.summary import get_analytics_summary
from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT, SCAN_STATUS_COMPLETED
from app.core.permissions import Permissions
from app.models.release import Release
from app.models.user import User
from app.repositories.releases import ReleaseRepository
from tests.mocks.fake_mongo import FakeDatabase

_SUMMARY = "app.api.v1.endpoints.analytics.summary"
_SEARCH = "app.api.v1.endpoints.analytics.search"

_ONE_PROJECT = ["p1"]
_TWO_PROJECTS = ["p1", "p2"]
_THREE_PROJECTS = ["p1", "p2", "p3"]
_NO_PROJECTS: list[str] = []
_ONE_SCAN = ["s1"]
_TWO_SCANS = ["s1", "s2"]
_NO_SCANS: list[str] = []
_NO_NAMES: dict[str, str] = {}
_SEARCH_TERM = "log4j"
_PAGE_SIZE = 50

_RELEASED_PROJECTS = ["p1", "p2"]
_ROLLED_BACK_PROJECT = "p1"
_SUPERSEDED_SCAN = "scan-p1-superseded"
_EXPECTED_RESOLVED = 2
_EXPECTED_WITHOUT_RELEASE = 1
_RELEASED_AT = datetime(2026, 9, 1, tzinfo=timezone.utc)
_SUPERSEDED_AT = datetime(2026, 8, 1, tzinfo=timezone.utc)


def _user():
    return User(
        id="u1",
        username="u1",
        email="u1@test.com",
        permissions=[Permissions.ANALYTICS_READ],
        is_active=True,
    )


@pytest.mark.asyncio
async def test_summary_reports_how_many_projects_had_no_release():
    db = FakeDatabase()
    with (
        patch(f"{_SUMMARY}.get_user_project_ids", new=AsyncMock(return_value=_THREE_PROJECTS)),
        patch(f"{_SUMMARY}.get_latest_scan_ids", new=AsyncMock(return_value=_ONE_SCAN)) as scan_ids,
    ):
        result = await get_analytics_summary(
            current_user=_user(), db=db, release_environment=DEFAULT_RELEASE_ENVIRONMENT
        )

    assert result.resolved_projects == len(_ONE_SCAN)
    assert result.projects_without_release == len(_THREE_PROJECTS) - len(_ONE_SCAN)
    assert scan_ids.await_args.kwargs["release_environment"] == DEFAULT_RELEASE_ENVIRONMENT


async def _seed_scan(db: FakeDatabase, scan_id: str, project_id: str) -> None:
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": project_id,
            "status": SCAN_STATUS_COMPLETED,
            "created_at": _RELEASED_AT,
        }
    )


async def _seed_release(db: FakeDatabase, project_id: str, scan_id: str, released_at: datetime) -> None:
    await ReleaseRepository(db).record(
        Release(
            project_id=project_id,
            environment=DEFAULT_RELEASE_ENVIRONMENT,
            scan_id=scan_id,
            released_at=released_at,
        )
    )


async def _seed_mixed_release_scope(db: FakeDatabase) -> None:
    """Every project has a usable scan; only _RELEASED_PROJECTS run one in the requested environment.
    One of them was rolled back onto its current scan, so it owns two records for that environment and
    a resolver that stopped collapsing per project would over-count the contributing projects."""
    for project_id in _THREE_PROJECTS:
        await db.projects.insert_one({"_id": project_id, "name": project_id})
        await _seed_scan(db, f"scan-{project_id}", project_id)
    for project_id in _RELEASED_PROJECTS:
        await _seed_release(db, project_id, f"scan-{project_id}", _RELEASED_AT)

    await _seed_scan(db, _SUPERSEDED_SCAN, _ROLLED_BACK_PROJECT)
    await _seed_release(db, _ROLLED_BACK_PROJECT, _SUPERSEDED_SCAN, _SUPERSEDED_AT)


@pytest.mark.asyncio
async def test_summary_counts_a_mixed_scope_through_the_real_resolver():
    """The patched counter tests state their expectation in the implementation's own terms and hold
    for a resolver returning any number of scans per project. This one walks a seeded scope."""
    db = FakeDatabase()
    await _seed_mixed_release_scope(db)

    with patch(f"{_SUMMARY}.get_user_project_ids", new=AsyncMock(return_value=_THREE_PROJECTS)):
        result = await get_analytics_summary(
            current_user=_user(), db=db, release_environment=DEFAULT_RELEASE_ENVIRONMENT
        )

    assert result.resolved_projects == _EXPECTED_RESOLVED
    assert result.projects_without_release == _EXPECTED_WITHOUT_RELEASE


@pytest.mark.asyncio
async def test_summary_reports_the_same_counters_without_a_release_filter():
    db = FakeDatabase()
    with (
        patch(f"{_SUMMARY}.get_user_project_ids", new=AsyncMock(return_value=_TWO_PROJECTS)),
        patch(f"{_SUMMARY}.get_latest_scan_ids", new=AsyncMock(return_value=_TWO_SCANS)) as scan_ids,
    ):
        result = await get_analytics_summary(current_user=_user(), db=db, release_environment=None)

    assert result.resolved_projects == len(_TWO_PROJECTS)
    assert result.projects_without_release == 0
    assert scan_ids.await_args.kwargs["release_environment"] is None


@pytest.mark.asyncio
async def test_summary_with_no_accessible_projects_reports_zeroes():
    db = FakeDatabase()
    with patch(f"{_SUMMARY}.get_user_project_ids", new=AsyncMock(return_value=_NO_PROJECTS)):
        result = await get_analytics_summary(
            current_user=_user(), db=db, release_environment=DEFAULT_RELEASE_ENVIRONMENT
        )

    assert result.resolved_projects == 0
    assert result.projects_without_release == 0


@pytest.mark.asyncio
async def test_summary_with_no_resolvable_scan_still_names_the_scope():
    """The empty-scan short circuit returns before the counters are read anywhere else, so it has
    to carry them itself or a fully uncovered environment reports an empty, uncounted fleet."""
    db = FakeDatabase()
    with (
        patch(f"{_SUMMARY}.get_user_project_ids", new=AsyncMock(return_value=_TWO_PROJECTS)),
        patch(f"{_SUMMARY}.get_latest_scan_ids", new=AsyncMock(return_value=_NO_SCANS)),
    ):
        result = await get_analytics_summary(
            current_user=_user(), db=db, release_environment=DEFAULT_RELEASE_ENVIRONMENT
        )

    assert result.total_dependencies == 0
    assert result.resolved_projects == 0
    assert result.projects_without_release == len(_TWO_PROJECTS)


@pytest.mark.asyncio
async def test_dependency_search_counts_the_projects_without_a_release():
    db = FakeDatabase()
    with (
        patch(f"{_SEARCH}.get_user_project_ids", new=AsyncMock(return_value=_THREE_PROJECTS)),
        patch(
            f"{_SEARCH}.get_projects_with_scans", new=AsyncMock(return_value=(_NO_NAMES, _ONE_SCAN))
        ) as resolve,
    ):
        result = await search_dependencies_advanced(
            current_user=_user(), db=db, q=_SEARCH_TERM, release_environment=DEFAULT_RELEASE_ENVIRONMENT
        )

    assert result.resolved_projects == len(_ONE_SCAN)
    assert result.projects_without_release == len(_THREE_PROJECTS) - len(_ONE_SCAN)
    assert resolve.await_args.kwargs["release_environment"] == DEFAULT_RELEASE_ENVIRONMENT


@pytest.mark.asyncio
async def test_dependency_search_with_no_resolvable_scan_still_names_the_scope():
    db = FakeDatabase()
    with (
        patch(f"{_SEARCH}.get_user_project_ids", new=AsyncMock(return_value=_TWO_PROJECTS)),
        patch(f"{_SEARCH}.get_projects_with_scans", new=AsyncMock(return_value=(_NO_NAMES, _NO_SCANS))),
    ):
        result = await search_dependencies_advanced(
            current_user=_user(), db=db, q=_SEARCH_TERM, release_environment=DEFAULT_RELEASE_ENVIRONMENT
        )

    assert result.items == []
    assert result.resolved_projects == 0
    assert result.projects_without_release == len(_TWO_PROJECTS)


@pytest.mark.asyncio
async def test_dependency_search_with_no_accessible_projects_reports_zeroes():
    db = FakeDatabase()
    with patch(f"{_SEARCH}.get_user_project_ids", new=AsyncMock(return_value=_NO_PROJECTS)):
        result = await search_dependencies_advanced(
            current_user=_user(), db=db, q=_SEARCH_TERM, release_environment=DEFAULT_RELEASE_ENVIRONMENT
        )

    assert result.resolved_projects == 0
    assert result.projects_without_release == 0
    assert result.size == _PAGE_SIZE


@pytest.mark.asyncio
async def test_vulnerability_search_counts_the_projects_without_a_release():
    db = FakeDatabase()
    with (
        patch(f"{_SEARCH}.get_user_project_ids", new=AsyncMock(return_value=_THREE_PROJECTS)),
        patch(
            f"{_SEARCH}.get_projects_with_scans", new=AsyncMock(return_value=(_NO_NAMES, _ONE_SCAN))
        ) as resolve,
    ):
        result = await search_vulnerabilities(
            current_user=_user(), db=db, q=_SEARCH_TERM, release_environment=DEFAULT_RELEASE_ENVIRONMENT
        )

    assert result.resolved_projects == len(_ONE_SCAN)
    assert result.projects_without_release == len(_THREE_PROJECTS) - len(_ONE_SCAN)
    assert resolve.await_args.kwargs["release_environment"] == DEFAULT_RELEASE_ENVIRONMENT


@pytest.mark.asyncio
async def test_vulnerability_search_with_no_resolvable_scan_still_names_the_scope():
    db = FakeDatabase()
    with (
        patch(f"{_SEARCH}.get_user_project_ids", new=AsyncMock(return_value=_TWO_PROJECTS)),
        patch(f"{_SEARCH}.get_projects_with_scans", new=AsyncMock(return_value=(_NO_NAMES, _NO_SCANS))),
    ):
        result = await search_vulnerabilities(
            current_user=_user(), db=db, q=_SEARCH_TERM, release_environment=DEFAULT_RELEASE_ENVIRONMENT
        )

    assert result.items == []
    assert result.resolved_projects == 0
    assert result.projects_without_release == len(_TWO_PROJECTS)


@pytest.mark.asyncio
async def test_vulnerability_search_with_no_accessible_projects_reports_zeroes():
    db = FakeDatabase()
    with patch(f"{_SEARCH}.get_user_project_ids", new=AsyncMock(return_value=_NO_PROJECTS)):
        result = await search_vulnerabilities(
            current_user=_user(), db=db, q=_SEARCH_TERM, release_environment=DEFAULT_RELEASE_ENVIRONMENT
        )

    assert result.resolved_projects == 0
    assert result.projects_without_release == 0
    assert result.size == _PAGE_SIZE


@pytest.mark.asyncio
async def test_both_searches_default_to_the_branch_tip():
    db = FakeDatabase()
    for endpoint in (search_dependencies_advanced, search_vulnerabilities):
        with (
            patch(f"{_SEARCH}.get_user_project_ids", new=AsyncMock(return_value=_ONE_PROJECT)),
            patch(f"{_SEARCH}.get_projects_with_scans", new=AsyncMock(return_value=(_NO_NAMES, _NO_SCANS))) as resolve,
        ):
            await endpoint(current_user=_user(), db=db, q=_SEARCH_TERM)

        assert resolve.await_args.kwargs["release_environment"] is None
