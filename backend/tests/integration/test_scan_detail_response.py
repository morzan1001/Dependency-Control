"""The scan detail page reads its counters straight from GET /projects/scans/{scan_id}."""

from datetime import datetime, timezone

import pytest

_PROJECT = "test-project-id"
_SCAN = "scan-with-waivers"
_IGNORED_COUNT = 3
_FINDINGS_COUNT = 9


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_scan_response_carries_the_ignored_count_and_no_stored_findings_summary(
    client, db, member_auth_headers
):
    """Stored scans in prod may still hold a findings_summary list of up to 500 entries."""
    await db.scans.insert_one(
        {
            "_id": _SCAN,
            "project_id": _PROJECT,
            "branch": "main",
            "status": "completed",
            "created_at": datetime(2026, 9, 1, tzinfo=timezone.utc),
            "findings_count": _FINDINGS_COUNT,
            "ignored_count": _IGNORED_COUNT,
            "findings_summary": [
                {
                    "id": "CVE-2026-0001",
                    "type": "vulnerability",
                    "severity": "HIGH",
                    "component": "lodash",
                    "version": "4.17.20",
                    "description": "Prototype pollution",
                    "scanners": ["osv"],
                    "details": {"cve_id": "CVE-2026-0001"},
                }
            ],
        }
    )

    resp = await client.get(f"/api/v1/projects/scans/{_SCAN}", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body.get("ignored_count"), "findings_summary" in body) == (_IGNORED_COUNT, False)
