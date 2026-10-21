"""No index holds an advisory id, so a CVE question reads head findings; only vulnerability findings hold advisories."""

from datetime import datetime, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.core.init_db import create_indexes
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.auth import make_admin
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_PROJECT = "p-cve"
_SCAN = "scan-cve"
_CVE = "CVE-2021-44228"
_VULNERABILITY_FINDINGS = 5
_OTHER_FINDINGS = 40


def _finding(key: str, finding_type: str, details: dict) -> dict:
    return {
        "_id": key,
        "finding_id": f"{key}:1.0.0",
        "scan_id": _SCAN,
        "project_id": _PROJECT,
        "type": finding_type,
        "severity": "HIGH",
        "component": key,
        "version": "1.0.0",
        "description": "",
        "waived": False,
        "details": details,
    }


async def _seed(db) -> None:
    await create_indexes(db)
    await db.projects.insert_one({"_id": _PROJECT, "name": "cve", "default_branch": "main", "latest_scan_id": _SCAN})
    await db.scans.insert_one(
        {
            "_id": _SCAN,
            "project_id": _PROJECT,
            "branch": "main",
            "status": SCAN_STATUS_COMPLETED,
            "created_at": datetime.now(timezone.utc),
        }
    )
    vulnerable = [
        _finding(f"vuln-{i}", "vulnerability", {"vulnerabilities": [{"id": _CVE if i == 0 else f"CVE-2026-{i:04d}"}]})
        for i in range(_VULNERABILITY_FINDINGS)
    ]
    others = [_finding(f"other-{i}", "outdated", {"latest_version": "2.0.0"}) for i in range(_OTHER_FINDINGS)]
    await db.findings.insert_many([*others, *vulnerable])


def _findings_docs_examined(entries: list[dict]) -> int:
    return sum(e.get("docsExamined", 0) for e in entries if e["ns"].endswith(".findings"))


async def test_the_findings_by_cve_read_only_the_head_s_vulnerability_findings(db):
    await _seed(db)

    result, entries = await profiled(
        db, ChatToolRegistry().execute_tool("get_findings_by_cve", {"cve_id": _CVE}, make_admin(), db)
    )

    assert result["total_occurrences"] == 1
    # The occurrence count and the sample each read the vulnerability findings once.
    assert _findings_docs_examined(entries) <= 2 * _VULNERABILITY_FINDINGS


async def test_a_cve_no_finding_names_reads_only_the_head_s_vulnerability_findings(db):
    await _seed(db)

    result, entries = await profiled(
        db, ChatToolRegistry().execute_tool("get_cve_details", {"cve_id": "CVE-1999-0001"}, make_admin(), db)
    )

    assert "error" in result
    assert _findings_docs_examined(entries) <= _VULNERABILITY_FINDINGS
