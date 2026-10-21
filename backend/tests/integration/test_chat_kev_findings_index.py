"""KEV advisories are rare, so a KEV list that walks every head finding to find them is the cost under test."""

from datetime import datetime, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.core.init_db import create_indexes
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.auth import make_admin
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_PROJECT = "p-kev"
_SCAN = "scan-kev"
_DECOYS = 40
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _finding(key: str, severity: str, *advisories: dict) -> dict:
    return {
        "_id": key,
        "finding_id": f"{key}:1.0.0",
        "scan_id": _SCAN,
        "project_id": _PROJECT,
        "type": "vulnerability",
        "severity": severity,
        "component": key,
        "version": "1.0.0",
        "description": "",
        "waived": False,
        "details": {"vulnerabilities": list(advisories)},
    }


async def _seed(db) -> None:
    await create_indexes(db)
    await db.projects.insert_one(
        {"_id": _PROJECT, "name": "kev-project", "default_branch": "main", "latest_scan_id": _SCAN}
    )
    await db.scans.insert_one(
        {
            "_id": _SCAN,
            "project_id": _PROJECT,
            "branch": "main",
            "status": SCAN_STATUS_COMPLETED,
            "created_at": datetime.now(timezone.utc),
        }
    )
    decoys = [
        _finding(f"plain-{i}", _SEVERITIES[i % len(_SEVERITIES)], {"id": f"CVE-2026-{i:04d}", "in_kev": False})
        for i in range(_DECOYS)
    ]
    await db.findings.insert_many(
        [
            *decoys,
            _finding("kev-low", "LOW", {"id": "CVE-2021-0001", "in_kev": True}),
            _finding("kev-critical", "CRITICAL", {"id": "CVE-2021-0002"}, {"id": "CVE-2021-44228", "in_kev": True}),
            _finding("kev-waived", "HIGH", {"id": "CVE-2021-0003", "in_kev": True, "waived": True}),
        ]
    )


async def test_the_kev_list_reads_only_findings_with_a_kev_advisory(db):
    await _seed(db)

    result, entries = await profiled(db, ChatToolRegistry().execute_tool("get_kev_findings", {}, make_admin(), db))

    assert [f["component"] for f in result["findings"]] == ["kev-critical", "kev-low"]
    reads = [e for e in entries if e["ns"].endswith(".findings") and e["op"] == "query"]
    assert sum(e["docsExamined"] for e in reads) <= 3
