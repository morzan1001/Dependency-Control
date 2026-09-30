"""The scan findings table joins each finding to its dependency; the join must cost a page, not the scan."""

import pytest
import pytest_asyncio

from app.api.v1.endpoints.projects import _build_scan_findings_pipeline

_SCAN = "scan-1"
_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SORTS = ["severity", "component", "type", "finding_id", "scanner", "unknown"]


def _finding(i: int, component: str) -> dict:
    return {
        "_id": f"f{i:02}",
        "finding_id": f"CVE-2026-{i % 7}",
        "scan_id": _SCAN,
        "type": "vulnerability" if i % 3 else "license",
        "severity": _SEVERITIES[i % len(_SEVERITIES)],
        "component": component,
        "version": "1.0",
        "scanners": [["trivy"], ["grype", "osv"], []][i % 3],
        "waived": False,
    }


def _dependency(i: int) -> dict:
    return {
        "scan_id": _SCAN,
        "name": f"lib{i}",
        "version": "1.0",
        "purl": f"pkg:maven/org.example/lib{i}@1.0",
        "direct": True if i % 2 else None,
        "direct_inferred": bool(i % 3),
        "source_type": ["file-system", "image"][i % 2],
        "source_target": "app.jar",
        "found_by": "java-archive-cataloger",
        "locations": [f"/app/lib{i}.jar"],
    }


@pytest_asyncio.fixture
async def seeded(db):
    await db.dependencies.insert_many([_dependency(i) for i in range(30)])
    findings = [_finding(i, f"lib{i}") for i in range(24)]
    findings += [_finding(24, "org.example:lib3"), _finding(25, "not-in-the-inventory")]
    await db.findings.insert_many(findings)
    return db


async def _page(db, pipeline):
    [bucket] = await db.findings.aggregate(pipeline).to_list(None)
    return bucket["metadata"], [list(row.items()) for row in bucket["data"]]


def _joined_rows(stages: list[dict]) -> int:
    rows = 0
    for stage in stages:
        if "$lookup" in stage:
            rows += stage["nReturned"]
        for branch in stage.get("$facet", {}).values():
            rows += _joined_rows(branch)
    return rows


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_dependency_join_reads_only_the_requested_page(seeded):
    pipeline = _build_scan_findings_pipeline({"scan_id": _SCAN}, sort_by="severity", sort_dir=-1, skip=10, limit=5)
    explain = await seeded.command(
        "explain", {"aggregate": "findings", "pipeline": pipeline, "cursor": {}}, verbosity="executionStats"
    )
    assert _joined_rows(explain["stages"]) == 5


@pytest.mark.live_mongo
@pytest.mark.asyncio
@pytest.mark.parametrize("sort_by", _SORTS)
@pytest.mark.parametrize("sort_dir", [1, -1])
async def test_joining_the_page_returns_what_joining_every_finding_returns(seeded, sort_by, sort_dir):
    for skip, limit in [(0, 5), (5, 5), (20, 50)]:
        paged = _build_scan_findings_pipeline(
            {"scan_id": _SCAN}, sort_by=sort_by, sort_dir=sort_dir, skip=skip, limit=limit
        )
        # No dependency here is transitive, so direct_only only moves the join ahead of the sort.
        joined_first = _build_scan_findings_pipeline(
            {"scan_id": _SCAN}, sort_by=sort_by, sort_dir=sort_dir, skip=skip, limit=limit, direct_only=True
        )
        metadata, rows = await _page(seeded, paged)
        assert any(dict(row).get("purl") for row in rows)
        assert (metadata, rows) == await _page(seeded, joined_first)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_source_type_sort_orders_by_the_joined_dependency(seeded):
    pipeline = _build_scan_findings_pipeline({"scan_id": _SCAN}, sort_by="source_type", sort_dir=-1, skip=0, limit=50)
    _, rows = await _page(seeded, pipeline)
    source_types = [dict(row).get("source_type", "") for row in rows]
    assert source_types == sorted(source_types, reverse=True)
    assert source_types[0] == "image"
