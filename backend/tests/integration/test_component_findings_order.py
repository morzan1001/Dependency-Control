"""The dependency modal shows a bounded list of a component's findings, so the list must hold the
most severe ones and the response must count all of them."""

from datetime import datetime, timezone

import pytest

SCAN_ID = "scan-busy"
COMPONENT = "busy-pkg"
LOW_COUNT = 104
SEVERE = ["MEDIUM", "CRITICAL", "HIGH"]


def _finding(index: int, severity: str) -> dict:
    return {
        "_id": f"f-{index:03d}",
        "id": f"{COMPONENT}:1.0.0:{index}",
        "finding_id": f"{COMPONENT}:1.0.0:{index}",
        "description": "",
        "scanners": ["trivy"],
        "scan_id": SCAN_ID,
        "project_id": "p",
        "type": "vulnerability",
        "severity": severity,
        "component": COMPONENT,
        "version": "1.0.0",
        "waived": False,
        "details": {},
    }


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_component_findings_list_the_most_severe_first(client, db, owner_auth_headers_proj):
    await db.scans.insert_one(
        {"_id": SCAN_ID, "project_id": "p", "status": "completed", "created_at": datetime.now(timezone.utc)}
    )
    await db.projects.update_one({"_id": "p"}, {"$set": {"latest_scan_id": SCAN_ID}})
    # The severe findings sort last by _id, so a list in storage order would cut them off.
    severities = ["LOW"] * LOW_COUNT + SEVERE
    await db.findings.insert_many([_finding(index, severity) for index, severity in enumerate(severities)])

    resp = await client.get(
        "/api/v1/analytics/component-findings", params={"component": COMPONENT}, headers=owner_auth_headers_proj
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body) == 100
    assert [finding["severity"] for finding in body[:4]] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert resp.headers["x-total-count"] == str(len(severities))
