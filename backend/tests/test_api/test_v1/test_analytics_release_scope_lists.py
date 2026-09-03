"""The four list endpoints resolve the release of an environment when asked; they keep
returning bare lists, so the scope counters live on /summary alone."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.v1.endpoints.analytics.risk import get_impact_analysis, get_vulnerability_hotspots
from app.api.v1.endpoints.analytics.summary import get_dependency_types, get_top_dependencies
from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT
from app.core.permissions import ALL_PERMISSIONS
from app.models.user import User

_SUMMARY = "app.api.v1.endpoints.analytics.summary"
_RISK = "app.api.v1.endpoints.analytics.risk"

_STAGING = "staging"
_CANARY = "canary"
_PROJECT_IDS = ["p1"]
_PROJECT_NAMES = {"p1": "P1"}
_NO_NAMES: dict[str, str] = {}
_NO_SCANS: list[str] = []
_HEAD_SCANS = ["scan-head"]
_RELEASE_SCANS = ["scan-released"]
_LIMIT = 20
_SKIP = 0
_SORT_BY = "finding_count"
_SORT_ORDER = "desc"


def _user():
    return User(id="u1", username="u1", email="u1@test.com", permissions=list(ALL_PERMISSIONS), is_active=True)


@pytest.mark.asyncio
async def test_top_dependencies_forwards_the_environment():
    with (
        patch(f"{_SUMMARY}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
        patch(f"{_SUMMARY}.get_latest_scan_ids", new=AsyncMock(return_value=_NO_SCANS)) as scan_ids,
    ):
        result = await get_top_dependencies(
            current_user=_user(), db=MagicMock(), limit=_LIMIT, type=None, release_environment=_STAGING
        )

    assert result == []
    assert scan_ids.await_args.kwargs["release_environment"] == _STAGING


@pytest.mark.asyncio
async def test_dependency_types_forwards_the_environment():
    with (
        patch(f"{_SUMMARY}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
        patch(f"{_SUMMARY}.get_projects_with_scans", new=AsyncMock(return_value=(_NO_NAMES, _NO_SCANS))) as resolve,
    ):
        result = await get_dependency_types(
            current_user=_user(), db=MagicMock(), release_environment=DEFAULT_RELEASE_ENVIRONMENT
        )

    assert result == []
    assert resolve.await_args.kwargs["release_environment"] == DEFAULT_RELEASE_ENVIRONMENT


@pytest.mark.asyncio
async def test_impact_forwards_the_environment():
    with (
        patch(f"{_RISK}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
        patch(f"{_RISK}.get_projects_with_scans", new=AsyncMock(return_value=(_NO_NAMES, _NO_SCANS))) as resolve,
    ):
        result = await get_impact_analysis(
            current_user=_user(), db=MagicMock(), limit=_LIMIT, release_environment=_CANARY
        )

    assert result == []
    assert resolve.await_args.kwargs["release_environment"] == _CANARY


@pytest.mark.asyncio
async def test_hotspots_forwards_the_environment():
    with (
        patch(f"{_RISK}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
        patch(f"{_RISK}.get_projects_with_scans", new=AsyncMock(return_value=(_NO_NAMES, _NO_SCANS))) as resolve,
    ):
        result = await get_vulnerability_hotspots(
            current_user=_user(),
            db=MagicMock(),
            skip=_SKIP,
            limit=_LIMIT,
            sort_by=_SORT_BY,
            sort_order=_SORT_ORDER,
            release_environment=DEFAULT_RELEASE_ENVIRONMENT,
        )

    assert result == []
    assert resolve.await_args.kwargs["release_environment"] == DEFAULT_RELEASE_ENVIRONMENT


@pytest.mark.asyncio
async def test_the_default_stays_the_branch_tip():
    with (
        patch(f"{_SUMMARY}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
        patch(f"{_SUMMARY}.get_latest_scan_ids", new=AsyncMock(return_value=_NO_SCANS)) as scan_ids,
        patch(f"{_SUMMARY}.get_projects_with_scans", new=AsyncMock(return_value=(_NO_NAMES, _NO_SCANS))) as resolve,
    ):
        await get_top_dependencies(current_user=_user(), db=MagicMock(), limit=_LIMIT, type=None)
        await get_dependency_types(current_user=_user(), db=MagicMock())

    assert scan_ids.await_args.kwargs["release_environment"] is None
    assert resolve.await_args.kwargs["release_environment"] is None


@pytest.mark.asyncio
async def test_the_risk_endpoints_default_to_the_branch_tip():
    with (
        patch(f"{_RISK}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
        patch(f"{_RISK}.get_projects_with_scans", new=AsyncMock(return_value=(_NO_NAMES, _NO_SCANS))) as resolve,
    ):
        await get_impact_analysis(current_user=_user(), db=MagicMock(), limit=_LIMIT)
        assert resolve.await_args.kwargs["release_environment"] is None

        await get_vulnerability_hotspots(
            current_user=_user(), db=MagicMock(), skip=_SKIP, limit=_LIMIT, sort_by=_SORT_BY, sort_order=_SORT_ORDER
        )

    assert resolve.await_args.kwargs["release_environment"] is None


def _resolver_per_environment():
    """Head and release resolve to different scans, the case a shared cache entry would confuse."""

    async def _fake(_project_ids, _db, *, release_environment=None):
        return _PROJECT_NAMES, (_HEAD_SCANS if release_environment is None else _RELEASE_SCANS)

    return _fake


def _matched_scan_ids(pipeline: list[dict[str, Any]]) -> list[str] | None:
    """The scan set the main grouping aggregation read, or None for any other pipeline."""
    if not any("details_list" in (stage.get("$group") or {}) for stage in pipeline):
        return None
    return pipeline[0]["$match"]["scan_id"]["$in"]


@pytest.mark.asyncio
async def test_the_impact_cache_does_not_serve_head_results_to_a_release_request():
    read: list[list[str]] = []

    async def _fake_aggregate(pipeline, **_kw):
        matched = _matched_scan_ids(pipeline)
        if matched is not None:
            read.append(matched)
        return []

    finding_repo = MagicMock()
    finding_repo.aggregate = _fake_aggregate

    with (
        patch(f"{_RISK}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
        patch(f"{_RISK}.get_projects_with_scans", new=_resolver_per_environment()),
        patch(f"{_RISK}.FindingRepository", return_value=finding_repo),
    ):
        await get_impact_analysis(current_user=_user(), db=MagicMock(), limit=_LIMIT)
        await get_impact_analysis(
            current_user=_user(), db=MagicMock(), limit=_LIMIT, release_environment=DEFAULT_RELEASE_ENVIRONMENT
        )

    assert read == [_HEAD_SCANS, _RELEASE_SCANS]


@pytest.mark.asyncio
async def test_the_hotspot_cache_does_not_serve_head_results_to_a_release_request():
    read: list[list[str]] = []

    async def _fake_aggregate(pipeline, **_kw):
        matched = _matched_scan_ids(pipeline)
        if matched is not None:
            read.append(matched)
        return []

    finding_repo = MagicMock()
    finding_repo.aggregate = _fake_aggregate
    dep_repo = MagicMock()
    dep_repo.aggregate = AsyncMock(return_value=[])

    with (
        patch(f"{_RISK}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
        patch(f"{_RISK}.get_projects_with_scans", new=_resolver_per_environment()),
        patch(f"{_RISK}.FindingRepository", return_value=finding_repo),
        patch(f"{_RISK}.DependencyRepository", return_value=dep_repo),
    ):
        for environment in (None, DEFAULT_RELEASE_ENVIRONMENT):
            await get_vulnerability_hotspots(
                current_user=_user(),
                db=MagicMock(),
                skip=_SKIP,
                limit=_LIMIT,
                sort_by=_SORT_BY,
                sort_order=_SORT_ORDER,
                release_environment=environment,
            )

    assert read == [_HEAD_SCANS, _RELEASE_SCANS]
