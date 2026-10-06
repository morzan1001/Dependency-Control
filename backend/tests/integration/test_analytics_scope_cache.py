"""Scope-wide analytics views are cached per caller scope, not per head scan, and concurrent misses share one run."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

from app.api.v1.helpers.analytics import get_latest_scan_ids, get_projects_with_scans
from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT
from tests.helpers.indexes import create_hinted_indexes

pytestmark = pytest.mark.live_mongo

_PROJECT = "p"
_FIRST_SCAN = "scan-first"
_NEXT_SCAN = "scan-next"
_RISK = "app.api.v1.endpoints.analytics.risk"
_SUMMARY = "app.api.v1.endpoints.analytics.summary"


def _scan(scan_id: str) -> dict:
    return {
        "_id": scan_id,
        "project_id": _PROJECT,
        "branch": "main",
        "status": "completed",
        "created_at": datetime.now(timezone.utc),
    }


def _vulnerability(scan_id: str, component: str, cve: str) -> dict:
    return {
        "_id": f"{scan_id}:{cve}",
        "id": cve,
        "finding_id": f"{component}:1.0.0",
        "scan_id": scan_id,
        "project_id": _PROJECT,
        "type": "vulnerability",
        "severity": "HIGH",
        "component": component,
        "version": "1.0.0",
        "description": "",
        "scanners": ["trivy"],
        "waived": False,
        "scan_created_at": datetime.now(timezone.utc),
        "details": {"vulnerabilities": [{"id": cve, "severity": "HIGH", "aliases": []}]},
    }


def _dependency(scan_id: str, name: str, purl_type: str) -> dict:
    return {
        "_id": f"{scan_id}:{name}",
        "scan_id": scan_id,
        "project_id": _PROJECT,
        "name": name,
        "version": "1.0.0",
        "purl": f"pkg:{purl_type}/{name}@1.0.0",
        "type": purl_type,
        "direct": True,
        "parent_components": [],
    }


@pytest_asyncio.fixture
async def scanned(db, owner_auth_headers_proj):
    await create_hinted_indexes(db)
    await db.scans.insert_one(_scan(_FIRST_SCAN))
    await db.projects.update_one({"_id": _PROJECT}, {"$set": {"latest_scan_id": _FIRST_SCAN}})
    await db.findings.insert_one(_vulnerability(_FIRST_SCAN, "lodash", "CVE-2026-0001"))
    await db.dependencies.insert_many(
        [
            _dependency(_FIRST_SCAN, "lodash", "npm"),
            _dependency(_FIRST_SCAN, "requests", "pypi"),
            _dependency(_FIRST_SCAN, "express", "npm"),
        ]
    )
    return owner_auth_headers_proj


async def _ingest_next_head(db) -> None:
    await db.scans.insert_one(_scan(_NEXT_SCAN))
    await db.findings.insert_one(_vulnerability(_NEXT_SCAN, "left-pad", "CVE-2026-0002"))
    await db.dependencies.insert_one(_dependency(_NEXT_SCAN, "left-pad", "npm"))
    await db.projects.update_one({"_id": _PROJECT}, {"$set": {"latest_scan_id": _NEXT_SCAN}})


def _resolution_spy() -> AsyncMock:
    return AsyncMock(side_effect=get_projects_with_scans)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/v1/analytics/impact", "/api/v1/analytics/hotspots"])
async def test_a_repeat_view_after_an_ingest_is_served_without_resolving_heads_again(client, db, scanned, path):
    spy = _resolution_spy()
    with patch(f"{_RISK}.get_projects_with_scans", new=spy):
        first = await client.get(path, headers=scanned)
        await _ingest_next_head(db)
        second = await client.get(path, headers=scanned)

    assert first.status_code == second.status_code == 200, second.text
    assert second.json() == first.json()
    assert spy.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/v1/analytics/impact", "/api/v1/analytics/hotspots"])
async def test_concurrent_views_of_one_scope_share_one_computation(client, scanned, path):
    spy = _resolution_spy()
    with patch(f"{_RISK}.get_projects_with_scans", new=spy):
        responses = await asyncio.gather(*(client.get(path, headers=scanned) for _ in range(3)))

    assert [r.status_code for r in responses] == [200, 200, 200]
    assert spy.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/v1/analytics/impact", "/api/v1/analytics/hotspots"])
async def test_each_release_environment_is_its_own_entry(client, scanned, path):
    spy = _resolution_spy()
    with patch(f"{_RISK}.get_projects_with_scans", new=spy):
        head = await client.get(path, headers=scanned)
        released = await client.get(path, params={"release_environment": DEFAULT_RELEASE_ENVIRONMENT}, headers=scanned)

    assert head.status_code == released.status_code == 200, released.text
    assert [c.kwargs["release_environment"] for c in spy.await_args_list] == [None, DEFAULT_RELEASE_ENVIRONMENT]


def _head_spy() -> AsyncMock:
    return AsyncMock(side_effect=get_latest_scan_ids)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path", ["/api/v1/analytics/summary", "/api/v1/analytics/dependencies/top", "/api/v1/analytics/dependency-types"]
)
async def test_a_repeat_overview_call_after_an_ingest_is_served_from_the_cache(client, db, scanned, path):
    spy = _head_spy()
    with patch(f"{_SUMMARY}.get_latest_scan_ids", new=spy):
        first = await client.get(path, headers=scanned)
        await _ingest_next_head(db)
        second = await client.get(path, headers=scanned)

    assert first.status_code == second.status_code == 200, second.text
    assert second.json() == first.json()
    assert spy.await_count == 1


@pytest.mark.asyncio
async def test_concurrent_top_dependency_views_share_one_computation(client, scanned):
    spy = _head_spy()
    with patch(f"{_SUMMARY}.get_latest_scan_ids", new=spy):
        responses = await asyncio.gather(
            *(client.get("/api/v1/analytics/dependencies/top", headers=scanned) for _ in range(3))
        )

    assert [r.status_code for r in responses] == [200, 200, 200]
    assert spy.await_count == 1


@pytest.mark.asyncio
async def test_the_summary_and_the_type_filter_share_one_type_distribution(client, scanned):
    spy = _head_spy()
    with patch(f"{_SUMMARY}.get_latest_scan_ids", new=spy):
        summary = await client.get("/api/v1/analytics/summary", headers=scanned)
        types = await client.get("/api/v1/analytics/dependency-types", headers=scanned)

    assert summary.status_code == types.status_code == 200, types.text
    assert spy.await_count == 1
    assert types.json() == ["npm", "pypi"]
    assert summary.json()["total_dependencies"] == 3
    assert {t["type"]: t["count"] for t in summary.json()["dependency_types"]} == {"npm": 2, "pypi": 1}
