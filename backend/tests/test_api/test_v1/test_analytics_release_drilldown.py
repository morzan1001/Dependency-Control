"""A drill-down answers for the scan the table above it ranked.

Hotspots and the impact list resolve the release of an environment; the component drill-downs they
link to resolved the branch tip whatever was asked, so a component the release ranked as a critical
came back with no findings and no metadata at all.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.api.v1.endpoints.analytics.dependencies import (
    get_component_findings,
    get_dependency_metadata_endpoint,
)
from app.api.v1.endpoints.analytics.risk import get_vulnerability_hotspots
from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT, SCAN_STATUS_COMPLETED
from app.core.permissions import Permissions
from app.models.release import Release
from app.models.user import User
from app.repositories.releases import ReleaseRepository
from app.services.analytics.cache import reset_analytics_cache_for_tests
from tests.mocks.fake_mongo import FakeDatabase

_DEPENDENCIES = "app.api.v1.endpoints.analytics.dependencies"
_RISK = "app.api.v1.endpoints.analytics.risk"

_PROJECT_ID = "p1"
_PROJECT_IDS = [_PROJECT_ID]
_PROJECT_NAME = "P1"
_RELEASE_SCAN = "s-release"
_HEAD_SCAN = "s-head"
_NO_NAMES: dict[str, str] = {}
_NO_SCANS: list[str] = []
_STAGING = "staging"
_CANARY = "canary"

_RELEASED_COMPONENT = "log4j-core"
_RELEASED_VERSION = "2.14.1"
_RELEASED_CVE = "CVE-2021-44228"
_HEAD_VERSION = "2.17.1"
_HEAD_CVE = "CVE-2023-1111"
_PACKAGE_TYPE = "maven"

_RELEASED_AT = datetime(2026, 9, 1, tzinfo=timezone.utc)
_SCANNED_AT = datetime(2026, 8, 1, tzinfo=timezone.utc)

_SKIP = 0
_LIMIT = 20
_SORT_BY = "finding_count"
_SORT_ORDER = "desc"
_ONE = 1


def _user() -> User:
    return User(
        id="u1",
        username="u1",
        email="u1@test.com",
        permissions=[Permissions.ANALYTICS_READ],
        is_active=True,
    )


def _finding(scan_id: str, version: str, cve: str, severity: str) -> dict:
    return {
        "_id": f"f-{scan_id}",
        "id": f"f-{scan_id}",
        "finding_id": f"f-{scan_id}",
        "project_id": _PROJECT_ID,
        "scan_id": scan_id,
        "type": "vulnerability",
        "severity": severity,
        "component": _RELEASED_COMPONENT,
        "version": version,
        "description": f"{cve} in {_RELEASED_COMPONENT}",
        "scanners": ["trivy"],
        "found_in": [],
        "aliases": [],
        "related_findings": [],
        "waived": False,
        "scan_created_at": _SCANNED_AT,
        "details": {"vulnerabilities": [{"id": cve, "severity": severity}]},
    }


def _dependency(scan_id: str, version: str) -> dict:
    return {
        "_id": f"d-{scan_id}",
        "project_id": _PROJECT_ID,
        "scan_id": scan_id,
        "name": _RELEASED_COMPONENT,
        "version": version,
        "purl": f"pkg:{_PACKAGE_TYPE}/{_RELEASED_COMPONENT}@{version}",
        "type": _PACKAGE_TYPE,
        "direct": True,
    }


async def _seed(db: FakeDatabase) -> None:
    await db.projects.insert_one(
        {
            "_id": _PROJECT_ID,
            "name": _PROJECT_NAME,
            "default_branch": "main",
            "deleted_branches": [],
            "latest_scan_id": _HEAD_SCAN,
        }
    )
    for scan_id, created_at in ((_RELEASE_SCAN, _SCANNED_AT), (_HEAD_SCAN, _RELEASED_AT)):
        await db.scans.insert_one(
            {
                "_id": scan_id,
                "project_id": _PROJECT_ID,
                "branch": "main",
                "status": SCAN_STATUS_COMPLETED,
                "created_at": created_at,
            }
        )
    await ReleaseRepository(db).record(
        Release(
            project_id=_PROJECT_ID,
            environment=DEFAULT_RELEASE_ENVIRONMENT,
            scan_id=_RELEASE_SCAN,
            released_at=_RELEASED_AT,
        )
    )
    await db.findings.insert_one(_finding(_RELEASE_SCAN, _RELEASED_VERSION, _RELEASED_CVE, "CRITICAL"))
    await db.findings.insert_one(_finding(_HEAD_SCAN, _HEAD_VERSION, _HEAD_CVE, "MEDIUM"))
    await db.dependencies.insert_one(_dependency(_RELEASE_SCAN, _RELEASED_VERSION))
    await db.dependencies.insert_one(_dependency(_HEAD_SCAN, _HEAD_VERSION))


@pytest.fixture(autouse=True)
def _fresh_cache():
    reset_analytics_cache_for_tests()
    yield
    reset_analytics_cache_for_tests()


@pytest.mark.asyncio
async def test_the_drill_down_finds_what_release_mode_hotspots_ranked():
    """Both surfaces resolve the same scope, so a critical the ranking surfaces has a finding list."""
    db = FakeDatabase()
    await _seed(db)

    with (
        patch(f"{_RISK}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
        patch(f"{_DEPENDENCIES}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
    ):
        hotspots = await get_vulnerability_hotspots(
            current_user=_user(),
            db=db,
            skip=_SKIP,
            limit=_LIMIT,
            sort_by=_SORT_BY,
            sort_order=_SORT_ORDER,
            release_environment=DEFAULT_RELEASE_ENVIRONMENT,
        )
        findings = await get_component_findings(
            current_user=_user(),
            db=db,
            component=_RELEASED_COMPONENT,
            version=_RELEASED_VERSION,
            release_environment=DEFAULT_RELEASE_ENVIRONMENT,
        )
        metadata = await get_dependency_metadata_endpoint(
            current_user=_user(),
            db=db,
            component=_RELEASED_COMPONENT,
            version=_RELEASED_VERSION,
            type=None,
            release_environment=DEFAULT_RELEASE_ENVIRONMENT,
        )

    assert [(h.component, h.version) for h in hotspots] == [(_RELEASED_COMPONENT, _RELEASED_VERSION)]
    assert [f["version"] for f in findings] == [_RELEASED_VERSION]
    assert metadata is not None
    assert metadata.version == _RELEASED_VERSION


@pytest.mark.asyncio
async def test_the_drill_down_still_reports_the_branch_tip_when_no_environment_is_named():
    db = FakeDatabase()
    await _seed(db)

    with patch(f"{_DEPENDENCIES}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)):
        findings = await get_component_findings(
            current_user=_user(), db=db, component=_RELEASED_COMPONENT, version=_HEAD_VERSION
        )
        metadata = await get_dependency_metadata_endpoint(
            current_user=_user(), db=db, component=_RELEASED_COMPONENT, version=_HEAD_VERSION, type=None
        )

    assert [f["version"] for f in findings] == [_HEAD_VERSION]
    assert metadata is not None
    assert metadata.version == _HEAD_VERSION


@pytest.mark.asyncio
async def test_component_findings_forwards_the_environment():
    with (
        patch(f"{_DEPENDENCIES}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
        patch(
            f"{_DEPENDENCIES}.get_projects_with_scans",
            new=AsyncMock(return_value=(_NO_NAMES, _NO_SCANS)),
        ) as resolve,
    ):
        result = await get_component_findings(
            current_user=_user(),
            db=FakeDatabase(),
            component=_RELEASED_COMPONENT,
            version=None,
            release_environment=_STAGING,
        )

    assert result == []
    assert resolve.await_args.kwargs["release_environment"] == _STAGING


@pytest.mark.asyncio
async def test_dependency_metadata_forwards_the_environment():
    with (
        patch(f"{_DEPENDENCIES}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
        patch(f"{_DEPENDENCIES}.get_latest_scan_ids", new=AsyncMock(return_value=_NO_SCANS)) as scan_ids,
    ):
        result = await get_dependency_metadata_endpoint(
            current_user=_user(),
            db=FakeDatabase(),
            component=_RELEASED_COMPONENT,
            version=None,
            type=None,
            release_environment=_CANARY,
        )

    assert result is None
    assert scan_ids.await_args.kwargs["release_environment"] == _CANARY


@pytest.mark.asyncio
async def test_the_drill_down_defaults_to_the_branch_tip():
    with (
        patch(f"{_DEPENDENCIES}.get_user_project_ids", new=AsyncMock(return_value=_PROJECT_IDS)),
        patch(
            f"{_DEPENDENCIES}.get_projects_with_scans",
            new=AsyncMock(return_value=(_NO_NAMES, _NO_SCANS)),
        ) as resolve,
        patch(f"{_DEPENDENCIES}.get_latest_scan_ids", new=AsyncMock(return_value=_NO_SCANS)) as scan_ids,
    ):
        await get_component_findings(
            current_user=_user(), db=FakeDatabase(), component=_RELEASED_COMPONENT, version=None
        )
        await get_dependency_metadata_endpoint(
            current_user=_user(), db=FakeDatabase(), component=_RELEASED_COMPONENT, version=None, type=None
        )

    assert resolve.await_args.kwargs["release_environment"] is None
    assert scan_ids.await_args.kwargs["release_environment"] is None
