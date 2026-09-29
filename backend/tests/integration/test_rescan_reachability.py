"""A rescan analyses the original pipeline scan's inputs under a fresh scan id with no pipeline id;
callgraphs stay stored under the pipeline scan, so reachability has to look them up there."""

from datetime import datetime, timezone

import pytest

from app.repositories import AnalysisResultRepository, ScanRepository
from app.services.analysis.engine import _run_reachability_enrichment

_PROJECT_ID = "proj-rescan"
_ROOT_ID = "scan-pipeline"
_RESCAN_ID = "scan-rescan"


async def _seed(db) -> list[dict]:
    now = datetime.now(timezone.utc)
    await db.scans.insert_one(
        {"_id": _ROOT_ID, "project_id": _PROJECT_ID, "branch": "main", "status": "completed", "created_at": now}
    )
    await db.scans.insert_one(
        {
            "_id": _RESCAN_ID,
            "project_id": _PROJECT_ID,
            "branch": "main",
            "status": "processing",
            "created_at": now,
            "is_rescan": True,
            "original_scan_id": _ROOT_ID,
            "pipeline_id": None,
        }
    )
    await db.callgraphs.insert_one(
        {
            "_id": "cg-root",
            "project_id": _PROJECT_ID,
            "scan_id": _ROOT_ID,
            "language": "python",
            "analyzed_modules": ["requests"],
            "module_usage": {"requests": {"module": "requests", "import_locations": ["app/client.py"]}},
            "created_at": now,
        }
    )
    await db.dependencies.insert_one(
        {
            "_id": "dep-requests",
            "scan_id": _RESCAN_ID,
            "name": "requests",
            "version": "1.0.0",
            "purl": "pkg:pypi/requests@1.0.0",
        }
    )
    return [
        {
            "id": "CVE-1",
            "scan_id": _RESCAN_ID,
            "type": "vulnerability",
            "severity": "HIGH",
            "component": "requests",
            "version": "1.0.0",
            "details": {"risk_score": 40.0, "vulnerabilities": [{"id": "CVE-1", "severity": "HIGH"}]},
        }
    ]


@pytest.mark.asyncio
async def test_a_rescan_is_enriched_from_its_pipeline_scan_s_callgraph(db):
    findings = await _seed(db)
    summary: list[str] = []

    await _run_reachability_enrichment(
        vulnerability_findings=findings,
        scan_id=_RESCAN_ID,
        project_id=_PROJECT_ID,
        db=db,
        result_repo=AnalysisResultRepository(db),
        scan_repo=ScanRepository(db),
        results_summary=summary,
    )

    assert findings[0]["reachable"] is True
    assert not (await db.scans.find_one({"_id": _RESCAN_ID})).get("reachability_pending")
