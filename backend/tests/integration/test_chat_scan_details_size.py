"""get_scan_details answers with the scan's summary, which fits the tool result cap whatever the scan stores."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools._helpers import MAX_TOOL_RESULT_BYTES
from tests.helpers.databases import DATABASES
from tests.helpers.permission_presets import PRESET_ADMIN

pytestmark = pytest.mark.asyncio

_PROJECT = "p-scan-details"
_SCAN = "scan-details-head"
_CREATED = datetime(2026, 9, 30, 8, 0, tzinfo=timezone.utc)
_COMPLETED = _CREATED + timedelta(minutes=4)
_STATS = {"critical": 3, "high": 41, "medium": 220, "low": 236, "risk_score": 512.5}
_FAILED_ANALYZERS = ["trivy"]
_ENRICHMENT_FAILURES = ["epss_kev"]
_ERROR = "trivy: analyzer timed out after 600s"
_FINDINGS_COUNT = 500
# The engine persists up to this many vulnerability summaries on the scan document.
_FINDINGS_SUMMARY_ENTRIES = 500


def _summary_entry(i: int) -> dict:
    return {
        "id": f"pkg-{i}:1.0.{i}",
        "type": "vulnerability",
        "severity": "MEDIUM",
        "component": f"pkg-{i}",
        "version": f"1.0.{i}",
        "description": "Uncontrolled resource consumption in request parsing " * 3,
        "scanners": ["grype", "trivy"],
        "details": {"cve_id": f"CVE-2026-{10000 + i}"},
    }


async def _seed(db) -> None:
    await db.projects.insert_one(
        {"_id": _PROJECT, "name": "scan-details-project", "default_branch": "main", "latest_scan_id": _SCAN}
    )
    await db.scans.insert_one(
        {
            "_id": _SCAN,
            "project_id": _PROJECT,
            "branch": "main",
            "commit_hash": "4f2a9c1",
            "status": SCAN_STATUS_COMPLETED,
            "created_at": _CREATED,
            "completed_at": _COMPLETED,
            "error": _ERROR,
            "failed_analyzers": _FAILED_ANALYZERS,
            "enrichment_failures": _ENRICHMENT_FAILURES,
            "findings_count": _FINDINGS_COUNT,
            "stats": _STATS,
            "findings_summary": [_summary_entry(i) for i in range(_FINDINGS_SUMMARY_ENTRIES)],
            "sbom_refs": [{"storage": "gridfs", "gridfs_id": f"sbom-{i}"} for i in range(40)],
            "received_results": ["grype", "trivy", "osv", "epss_kev", "license_compliance"],
        }
    )


@pytest.mark.parametrize("database", DATABASES)
async def test_scan_details_fit_the_result_cap_and_carry_the_scan_summary(db, database):
    await _seed(db)
    admin = User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))

    result = await ChatToolRegistry().execute_tool("get_scan_details", {"project_id": _PROJECT}, admin, db)
    scan = result["scan"]

    assert len(json.dumps(result, default=str).encode()) <= MAX_TOOL_RESULT_BYTES
    assert set(scan) == {
        "id",
        "project_id",
        "branch",
        "commit_hash",
        "created_at",
        "status",
        "completed_at",
        "error",
        "failed_analyzers",
        "enrichment_failures",
        "findings_count",
        "stats",
        "is_head",
        "url",
    }
    assert (scan["id"], scan["project_id"], scan["branch"], scan["commit_hash"]) == (_SCAN, _PROJECT, "main", "4f2a9c1")
    assert (scan["status"], scan["error"], scan["is_head"]) == (SCAN_STATUS_COMPLETED, _ERROR, True)
    assert (scan["findings_count"], scan["stats"]) == (_FINDINGS_COUNT, _STATS)
    assert (scan["failed_analyzers"], scan["enrichment_failures"]) == (_FAILED_ANALYZERS, _ENRICHMENT_FAILURES)
    # Live Mongo hands datetimes back naive, the attrappe keeps the offset.
    assert scan["created_at"].startswith(_CREATED.strftime("%Y-%m-%dT%H:%M:%S"))
    assert scan["completed_at"].startswith(_COMPLETED.strftime("%Y-%m-%dT%H:%M:%S"))
