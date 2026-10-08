"""Hotspots page through one total order, and only by the fields they can order by."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

pytestmark = pytest.mark.live_mongo

_PROJECT = "p"
_HEAD = "scan-head"
_PATH = "/api/v1/analytics/hotspots"


@pytest.fixture(autouse=True)
def _no_live_enrichment(monkeypatch):
    from app.api.v1.endpoints.analytics import risk

    monkeypatch.setattr(risk.vulnerability_enrichment_service, "enrich_cves", AsyncMock(return_value={}))


async def _seed_groups(db, count: int) -> None:
    """``count`` component@version groups, two versions per component, tied on every other sort key."""
    now = datetime.now(timezone.utc)
    await db.scans.insert_one(
        {"_id": _HEAD, "project_id": _PROJECT, "branch": "main", "status": "completed", "created_at": now}
    )
    await db.projects.update_one({"_id": _PROJECT}, {"$set": {"latest_scan_id": _HEAD}})
    await db.findings.insert_many(
        [
            {
                "_id": f"f-{index}",
                "finding_id": f"lib-{index // 2}:1.0.{index % 2}",
                "scan_id": _HEAD,
                "project_id": _PROJECT,
                "type": "vulnerability",
                "severity": "HIGH",
                "component": f"lib-{index // 2:03d}",
                "version": f"1.0.{index % 2}",
                "waived": False,
                "scan_created_at": now,
                "details": {"vulnerabilities": [{"id": f"CVE-2026-{index:04d}", "severity": "HIGH"}]},
            }
            for index in range(count)
        ]
    )


@pytest.mark.asyncio
async def test_a_sort_field_hotspots_cannot_order_by_is_refused(client, db, owner_auth_headers_proj):
    await _seed_groups(db, 25)

    response = await client.get(_PATH, params={"sort_by": "severity", "limit": 20}, headers=owner_auth_headers_proj)

    assert response.status_code == 422, f"{len(response.json())} rows served"
    assert [error["loc"] for error in response.json()["detail"]] == [["query", "sort_by"]]


@pytest.mark.asyncio
@pytest.mark.parametrize("sort_by", ["finding_count", "component", "first_seen"])
async def test_infinite_scroll_shows_every_group_exactly_once(client, db, owner_auth_headers_proj, sort_by):
    # Odd, so many page boundaries split a component's two versions.
    groups, page = 300, 13
    await _seed_groups(db, groups)

    seen: list[tuple[str, str]] = []
    for skip in range(0, groups, page):
        response = await client.get(
            _PATH, params={"sort_by": sort_by, "skip": skip, "limit": page}, headers=owner_auth_headers_proj
        )
        assert response.status_code == 200, response.text
        seen += [(row["component"], row["version"]) for row in response.json()]

    assert len(seen) == len(set(seen)) == groups
