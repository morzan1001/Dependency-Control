"""Hotspots page through one total order, and only by the fields they can order by."""

from datetime import datetime, timezone

import pytest

pytestmark = pytest.mark.live_mongo

_PROJECT = "p"
_HEAD = "scan-head"
_PATH = "/api/v1/analytics/hotspots"


async def _seed_groups(db, count: int) -> None:
    now = datetime.now(timezone.utc)
    await db.scans.insert_one(
        {"_id": _HEAD, "project_id": _PROJECT, "branch": "main", "status": "completed", "created_at": now}
    )
    await db.projects.update_one({"_id": _PROJECT}, {"$set": {"latest_scan_id": _HEAD}})
    await db.findings.insert_many(
        [
            {
                "_id": f"f-{index}",
                "finding_id": f"lib-{index}:1.0.0",
                "scan_id": _HEAD,
                "project_id": _PROJECT,
                "type": "vulnerability",
                "severity": "HIGH",
                "component": f"lib-{index:03d}",
                "version": "1.0.0",
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
