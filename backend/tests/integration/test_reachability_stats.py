"""K6: reachability verdicts must reach ``scan.stats``.

The stats pipeline reads top-level ``reachable``/``reachability_level``; the enrichment only
ever wrote ``details.reachability``, so every reachability counter stayed at zero. The deferred
path (callgraph uploaded after the scan finished) additionally never recomputed the stats.
"""

from datetime import datetime, timezone

import pytest

from app.services.analysis.stats import calculate_comprehensive_stats
from app.services.reachability_enrichment import (
    enrich_findings_with_reachability,
    run_pending_reachability_for_scan,
)

_PROJECT_ID = "proj-reach"
_SCAN_ID = "scan-reach"


def _finding(finding_id: str, component: str, severity: str = "HIGH") -> dict:
    return {
        "_id": f"f-{finding_id}",
        "id": finding_id,
        "finding_id": finding_id,
        "scan_id": _SCAN_ID,
        "project_id": _PROJECT_ID,
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": "1.0.0",
        "description": f"{finding_id} in {component}",
        "scanners": ["osv"],
        "waived": False,
        "details": {"risk_score": 40.0, "vulnerabilities": [{"id": finding_id, "severity": severity}]},
    }


async def _seed_callgraph(db) -> None:
    await db.callgraphs.insert_one(
        {
            "_id": "cg-1",
            "project_id": _PROJECT_ID,
            "scan_id": _SCAN_ID,
            "language": "python",
            "tool": "pyan",
            "module_usage": {
                "requests": {
                    "module": "requests",
                    "import_count": 2,
                    "call_count": 3,
                    "import_locations": ["app/client.py"],
                    "used_symbols": ["get"],
                }
            },
            "import_map": {"app/client.py": ["requests"]},
            "created_at": datetime.now(timezone.utc),
        }
    )


async def _seed_dependencies(db) -> None:
    for name in ("requests", "urllib3"):
        await db.dependencies.insert_one(
            {
                "_id": f"dep-{name}",
                "scan_id": _SCAN_ID,
                "name": name,
                "version": "1.0.0",
                "purl": f"pkg:pypi/{name}@1.0.0",
            }
        )


@pytest.mark.asyncio
async def test_inline_enrichment_reaches_the_stats_pipeline(db):
    await _seed_callgraph(db)
    await _seed_dependencies(db)
    findings = [_finding("CVE-1", "requests"), _finding("CVE-2", "urllib3")]

    enriched = await enrich_findings_with_reachability(
        findings=findings, project_id=_PROJECT_ID, db=db, scan_id=_SCAN_ID
    )
    assert enriched == 2

    # The engine inserts these very dicts, so whatever they carry is what the pipeline sees.
    for finding in findings:
        await db.findings.insert_one(finding)

    stats = await calculate_comprehensive_stats(db, _SCAN_ID)
    assert stats.reachability.analyzed_count == 2
    assert stats.reachability.reachable_count == 1
    assert stats.reachability.unreachable_count == 1
    assert stats.reachability.unknown_count == 0


@pytest.mark.asyncio
async def test_deferred_run_recomputes_and_persists_scan_stats(db):
    await _seed_callgraph(db)
    await _seed_dependencies(db)
    for finding in (_finding("CVE-1", "requests"), _finding("CVE-2", "urllib3")):
        await db.findings.insert_one(finding)
    await db.scans.insert_one(
        {
            "_id": _SCAN_ID,
            "project_id": _PROJECT_ID,
            "branch": "main",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
            "reachability_pending": True,
            "stats": {"critical": 0, "high": 2, "reachability": {"analyzed_count": 0, "reachable_count": 0}},
        }
    )
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": "p", "latest_scan_id": _SCAN_ID, "stats": {"high": 2}})

    result = await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)
    assert result["error"] is None
    assert result["findings_enriched"] == 2

    scan = await db.scans.find_one({"_id": _SCAN_ID})
    assert scan["stats"]["reachability"]["analyzed_count"] == 2
    assert scan["stats"]["reachability"]["reachable_count"] == 1

    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert project["stats"]["reachability"]["analyzed_count"] == 2


@pytest.mark.asyncio
async def test_deferred_run_leaves_a_superseded_project_alone(db):
    await _seed_callgraph(db)
    await _seed_dependencies(db)
    await db.findings.insert_one(_finding("CVE-1", "requests"))
    await db.scans.insert_one(
        {
            "_id": _SCAN_ID,
            "project_id": _PROJECT_ID,
            "branch": "main",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
            "reachability_pending": True,
        }
    )
    await db.projects.insert_one(
        {"_id": _PROJECT_ID, "name": "p", "latest_scan_id": "a-newer-scan", "stats": {"high": 7}}
    )

    await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)

    scan = await db.scans.find_one({"_id": _SCAN_ID})
    assert scan["stats"]["reachability"]["analyzed_count"] == 1

    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert project["stats"] == {"high": 7}
