"""The top-dependencies row lists a sample of versions beside a truthful total_occurrences, so it
has to carry the distinct-version total too: the table's "+N" badge is computed from it, and
$addToSet has no order to sample along."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.v1.endpoints.analytics.summary import _VERSION_SAMPLE, get_top_dependencies
from app.core.permissions import ALL_PERMISSIONS
from app.models.user import User

_SUMMARY = "app.api.v1.endpoints.analytics.summary"
_PROJECT_IDS = ["p1"]
_SCANS = ["s1"]
_LIMIT = 20
_DISTINCT_VERSIONS = 40


def _user():
    return User(id="u1", username="u1", email="u1@test.com", permissions=list(ALL_PERMISSIONS), is_active=True)


def _aggregated_row() -> dict:
    """What Mongo returns for one component: the whole distinct-version set plus its size."""
    versions = [f"1.{minor}.0" for minor in range(_DISTINCT_VERSIONS)]
    return {
        "_id": "leftpad",
        "name": "leftpad",
        "type": "npm",
        # $addToSet returns the set in no particular order; oldest-first is one such order.
        "versions": versions,
        "version_count": len(versions),
        "project_count": 1,
        "total_occurrences": _DISTINCT_VERSIONS,
    }


async def _top_dependencies() -> list:
    dep_repo = MagicMock()
    dep_repo.aggregate = AsyncMock(return_value=[_aggregated_row()])
    finding_repo = MagicMock()
    finding_repo.get_vuln_counts_by_components = AsyncMock(return_value={})
    with (
        patch(f"{_SUMMARY}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
        patch(f"{_SUMMARY}.get_latest_scan_ids", new=AsyncMock(return_value=_SCANS)),
        patch(f"{_SUMMARY}.DependencyRepository", return_value=dep_repo),
        patch(f"{_SUMMARY}.FindingRepository", return_value=finding_repo),
    ):
        return await get_top_dependencies(current_user=_user(), db=MagicMock(), limit=_LIMIT, type=None)


@pytest.mark.asyncio
async def test_the_row_reports_every_distinct_version_not_the_sample_size():
    rows = await _top_dependencies()

    assert len(rows[0].versions) == _VERSION_SAMPLE
    assert rows[0].version_count == _DISTINCT_VERSIONS


@pytest.mark.asyncio
async def test_the_sample_is_the_newest_versions_rather_than_an_arbitrary_ten():
    rows = await _top_dependencies()

    assert rows[0].versions[0] == f"1.{_DISTINCT_VERSIONS - 1}.0"
    assert rows[0].versions == sorted(rows[0].versions, key=lambda v: int(v.split(".")[1]), reverse=True)
