"""Reachability verdicts must reach ``scan.stats``, inline and on the deferred path.

The stats pipeline reads the top-level ``reachable``/``reachability_level`` mirrors, so a
verdict written only under ``details.reachability`` leaves every counter at zero.
"""

from datetime import datetime, timezone

import pytest
from prometheus_client import REGISTRY

from app.core.init_db import create_indexes
from app.repositories.distributed_locks import DistributedLocksRepository
from app.services import reachability_enrichment
from app.services.analysis.stats import calculate_comprehensive_stats
from app.services.reachability_enrichment import (
    build_component_language_map,
    enrich_findings_with_reachability,
    fetch_callgraphs,
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
            "tool": "ast",
            "analyzed_modules": ["requests", "urllib3"],
            "module_usage": {
                "requests": {
                    "module": "requests",
                    "import_count": 2,
                    "call_count": 3,
                    "import_locations": ["app/client.py"],
                    "used_symbols": ["get"],
                }
            },
            "total_imports": 2,
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

    enriched = enrich_findings_with_reachability(
        findings,
        await fetch_callgraphs(_PROJECT_ID, _SCAN_ID, db),
        await build_component_language_map(db, _SCAN_ID),
    )
    assert enriched == 2

    # The engine inserts these very dicts, so whatever they carry is what the pipeline sees.
    for finding in findings:
        await db.findings.insert_one(finding)

    stats = (await calculate_comprehensive_stats(db, _SCAN_ID)).stats
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

    await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)

    scan = await db.scans.find_one({"_id": _SCAN_ID})
    assert scan["stats"]["reachability"]["analyzed_count"] == 2
    assert scan["stats"]["reachability"]["reachable_count"] == 1

    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert project["stats"]["reachability"]["analyzed_count"] == 2

    # The persisted summary is built from the minimal projection, which carries every field it shows.
    info = (await db.analysis_results.find_one({"scan_id": _SCAN_ID}))["result"]["callgraph_info"][0]
    assert (info["coverage_modules"], info["total_imports"]) == (2, 2)
    assert info["generated_at"] is not None


async def _pending_scan(db, scan_id: str = _SCAN_ID, branch: str = "main", **fields) -> None:
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": _PROJECT_ID,
            "branch": branch,
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
            "reachability_pending": True,
            **fields,
        }
    )


@pytest.mark.asyncio
async def test_a_deferred_run_reads_the_dependency_inventory_once(db, monkeypatch):
    await _seed_callgraph(db)
    await _seed_dependencies(db)
    await db.findings.insert_one(_finding("CVE-1", "requests"))
    await _pending_scan(db)
    reads: list[dict] = []
    real_find = db.dependencies.find

    def _counting_find(query, *args, **kwargs):
        reads.append(query)
        return real_find(query, *args, **kwargs)

    monkeypatch.setattr(db.dependencies, "find", _counting_find)

    await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)

    assert (await db.findings.find_one({"_id": "f-CVE-1"}))["reachable"] is True
    assert reads == [{"scan_id": _SCAN_ID}]


@pytest.mark.asyncio
async def test_deferred_run_leaves_a_superseded_project_alone(db):
    await _seed_callgraph(db)
    await _seed_dependencies(db)
    await db.findings.insert_one(_finding("CVE-1", "requests"))
    await _pending_scan(db, created_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    await db.scans.insert_one(
        {
            "_id": "a-newer-scan",
            "project_id": _PROJECT_ID,
            "branch": "main",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
            "stats": {"high": 7},
        }
    )
    await db.projects.insert_one(
        {"_id": _PROJECT_ID, "name": "p", "latest_scan_id": "a-newer-scan", "stats": {"high": 7}}
    )

    await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)

    scan = await db.scans.find_one({"_id": _SCAN_ID})
    assert scan["stats"]["reachability"]["analyzed_count"] == 1

    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert (project["latest_scan_id"], project["stats"]) == ("a-newer-scan", {"high": 7})


@pytest.mark.asyncio
async def test_deferred_run_on_a_scan_the_pointer_still_names_caches_the_derived_head(db):
    """The default branch moved off the pointer's branch, so the pointer no longer names head."""
    await _seed_callgraph(db)
    await _seed_dependencies(db)
    await db.findings.insert_one(_finding("CVE-1", "requests"))
    await _pending_scan(db, branch="develop")
    await db.scans.insert_one(
        {
            "_id": "main-tip",
            "project_id": _PROJECT_ID,
            "branch": "main",
            "status": "completed",
            "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "stats": {"high": 7},
        }
    )
    await db.projects.insert_one(
        {"_id": _PROJECT_ID, "name": "p", "default_branch": "main", "latest_scan_id": _SCAN_ID, "stats": {"high": 1}}
    )

    await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)

    assert (await db.scans.find_one({"_id": _SCAN_ID}))["stats"]["reachability"]["analyzed_count"] == 1
    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert (project["latest_scan_id"], project["stats"]) == ("main-tip", {"high": 7})


@pytest.mark.asyncio
async def test_deferred_run_writes_no_stats_while_a_recalculation_holds_the_stats_lock(db, monkeypatch):
    """A recalculation resets every waiver flag before re-applying them, so stats read in between count none."""
    await _seed_callgraph(db)
    await _seed_dependencies(db)
    await db.findings.insert_one(_finding("CVE-1", "requests"))
    await _pending_scan(db, stats={"high": 1})
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": "p", "latest_scan_id": _SCAN_ID, "stats": {"high": 1}})
    await DistributedLocksRepository(db).acquire_lock(f"stats_recalc:{_PROJECT_ID}", "a-running-recalc", 300)
    monkeypatch.setattr("app.services.stats._LOCK_RETRY_BASE_DELAY", 0)

    await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)

    scan = await db.scans.find_one({"_id": _SCAN_ID})
    assert (scan["stats"], scan.get("reachability_pending")) == ({"high": 1}, None)
    assert (await db.findings.find_one({"_id": "f-CVE-1"}))["reachable"] is True
    assert (await db.projects.find_one({"_id": _PROJECT_ID}))["stats"] == {"high": 1}


@pytest.mark.asyncio
async def test_deferred_run_on_a_rescan_summarises_the_callgraph_of_its_build(db):
    """CI uploads the callgraph under the original build's id; the summary must describe the one enrichment used."""
    rescan_id = "rescan-reach"
    await _seed_callgraph(db)
    await db.dependencies.insert_one(
        {"_id": "rescan-dep", "scan_id": rescan_id, "name": "requests", "purl": "pkg:pypi/requests@1.0.0"}
    )
    await db.findings.insert_one({**_finding("CVE-1", "requests"), "scan_id": rescan_id})
    await _pending_scan(db, scan_id=rescan_id, is_rescan=True, original_scan_id=_SCAN_ID)

    await run_pending_reachability_for_scan(rescan_id, _PROJECT_ID, db)

    assert (await db.findings.find_one({"_id": "f-CVE-1"}))["reachable"] is True
    summary = await db.analysis_results.find_one({"scan_id": rescan_id, "analyzer_name": "reachability"})
    assert summary is not None
    assert summary["result"]["languages"] == ["python"]


@pytest.mark.asyncio
async def test_deferred_run_without_a_callgraph_keeps_the_scan_pending(db):
    await db.findings.insert_one(_finding("CVE-1", "requests"))
    await _pending_scan(db)

    await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)

    assert "reachable" not in await db.findings.find_one({"_id": "f-CVE-1"})
    assert (await db.scans.find_one({"_id": _SCAN_ID}))["reachability_pending"] is True


@pytest.mark.asyncio
async def test_a_second_language_supersedes_the_first_summary(db):
    """Each callgraph re-runs enrichment, so the scan must keep exactly one, current summary."""
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
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": "p", "latest_scan_id": _SCAN_ID})

    await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)

    await db.callgraphs.insert_one(
        {
            "_id": "cg-2",
            "project_id": _PROJECT_ID,
            "scan_id": _SCAN_ID,
            "language": "javascript",
            "tool": "madge",
            "analyzed_modules": ["lodash"],
            "module_usage": {},
            "created_at": datetime.now(timezone.utc),
        }
    )
    await db.scans.update_one({"_id": _SCAN_ID}, {"$set": {"reachability_pending": True}})
    await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)

    results = await db.analysis_results.find({"scan_id": _SCAN_ID, "analyzer_name": "reachability"}).to_list(None)
    assert len(results) == 1, "a stale duplicate would render twice in the raw-data view"
    assert sorted(results[0]["result"]["languages"]) == ["javascript", "python"]


@pytest.mark.asyncio
async def test_coverable_count_excludes_os_packages(db):
    """Container scans are almost all OS packages, which no callgraph tool can ever cover.

    Without this figure a team cannot tell "reachability found nothing yet" from "reachability
    can never say anything here", and enables callgraph jobs that cannot help them.
    """
    await db.dependencies.insert_many(
        [
            {"scan_id": _SCAN_ID, "name": "libssl3", "type": "deb", "purl": "pkg:deb/debian/libssl3@3.5.5"},
            {"scan_id": _SCAN_ID, "name": "sqlite-libs", "type": "apk", "purl": "pkg:apk/alpine/sqlite-libs@3.40"},
            {"scan_id": _SCAN_ID, "name": "org.json:json", "type": "maven", "purl": "pkg:maven/org.json/json@2023"},
            {"scan_id": _SCAN_ID, "name": "lodash", "type": "npm", "purl": "pkg:npm/lodash@4.17.21"},
        ]
    )
    for finding_id, component in (
        ("CVE-1", "libssl3"),
        ("CVE-2", "sqlite-libs"),
        ("CVE-3", "org.json:json"),
        ("CVE-4", "lodash"),
    ):
        await db.findings.insert_one(_finding(finding_id, component))

    stats = (await calculate_comprehensive_stats(db, _SCAN_ID)).stats
    # A Java callgraph covers the Maven package; only the two OS packages stay out of reach.
    assert stats.reachability.coverable_count == 2


@pytest.mark.asyncio
async def test_coverable_count_is_zero_without_dependencies(db):
    await db.findings.insert_one(_finding("CVE-1", "libssl3"))
    stats = (await calculate_comprehensive_stats(db, _SCAN_ID)).stats
    assert stats.reachability.coverable_count == 0


@pytest.mark.asyncio
async def test_a_rescan_is_enriched_from_the_callgraph_of_the_build_it_re_analyses(db):
    """CI uploads the callgraph under the original build's id; a rescan carries a fresh id."""
    from app.repositories.scans import ScanRepository
    from app.services.analysis.engine import _run_reachability_enrichment

    rescan_id = "rescan-reach"
    await _seed_callgraph(db)
    for name in ("requests", "urllib3"):
        await db.dependencies.insert_one(
            {"_id": f"rescan-dep-{name}", "scan_id": rescan_id, "name": name, "purl": f"pkg:pypi/{name}@1.0.0"}
        )
    await db.scans.insert_one(
        {
            "_id": rescan_id,
            "project_id": _PROJECT_ID,
            "branch": "main",
            "status": "processing",
            "created_at": datetime.now(timezone.utc),
            "is_rescan": True,
            "original_scan_id": _SCAN_ID,
        }
    )
    findings = [{**_finding("CVE-1", "requests"), "scan_id": rescan_id}]
    summary: list[str] = []

    await _run_reachability_enrichment(findings, rescan_id, _PROJECT_ID, db, ScanRepository(db), summary)

    assert summary == ["reachability: Success (1 enriched)"]
    assert findings[0]["reachable"] is True
    assert not (await db.scans.find_one({"_id": rescan_id})).get("reachability_pending")


@pytest.mark.asyncio
async def test_rescans_pointing_at_each_other_find_no_callgraph_instead_of_recursing(db):
    for scan_id, parent in (("rescan-a", "rescan-b"), ("rescan-b", "rescan-a")):
        await db.scans.insert_one(
            {"_id": scan_id, "project_id": _PROJECT_ID, "status": "completed", "original_scan_id": parent}
        )

    assert await fetch_callgraphs(_PROJECT_ID, "rescan-a", db) == []


@pytest.mark.asyncio
async def test_the_stored_inventory_keeps_a_transitive_dependency_unfalsified(db):
    await _seed_callgraph(db)
    await _seed_dependencies(db)
    await db.dependencies.update_one({"_id": "dep-urllib3"}, {"$set": {"direct": False, "direct_inferred": False}})
    findings = [_finding("CVE-2", "urllib3")]

    enrich_findings_with_reachability(
        findings,
        await fetch_callgraphs(_PROJECT_ID, _SCAN_ID, db),
        await build_component_language_map(db, _SCAN_ID),
    )

    assert findings[0]["reachable"] is None


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_run_that_finds_the_scan_locked_leaves_it_to_the_holder(db):
    await create_indexes(db)
    await _seed_callgraph(db)
    await _seed_dependencies(db)
    await db.findings.insert_one(_finding("CVE-1", "requests"))
    await _pending_scan(db)
    await DistributedLocksRepository(db).acquire_lock(f"reachability:{_SCAN_ID}", "a-running-pass", 300)

    await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)

    assert "reachable" not in await db.findings.find_one({"_id": "f-CVE-1"})
    assert (await db.scans.find_one({"_id": _SCAN_ID}))["reachability_pending"] is True


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_callgraph_uploaded_during_a_pass_is_applied_before_the_pass_ends(db, monkeypatch):
    """Parallel CI jobs upload one callgraph per language; the pass that lacks one must not write last."""
    await create_indexes(db)
    await _seed_callgraph(db)
    await _seed_dependencies(db)
    await db.dependencies.insert_one(
        {"_id": "dep-lodash", "scan_id": _SCAN_ID, "name": "lodash", "purl": "pkg:npm/lodash@4.17.21"}
    )
    await db.findings.insert_one(_finding("CVE-1", "requests"))
    await db.findings.insert_one(_finding("CVE-JS", "lodash"))
    await _pending_scan(db)
    real_language_map = reachability_enrichment.build_component_language_map
    uploaded: list[str] = []

    async def _upload_mid_pass(database, scan_id):
        if not uploaded:
            uploaded.append("javascript")
            await db.callgraphs.insert_one(
                {
                    "_id": "cg-js",
                    "project_id": _PROJECT_ID,
                    "scan_id": _SCAN_ID,
                    "language": "javascript",
                    "analyzed_modules": ["lodash"],
                    "module_usage": {"lodash": {"module": "lodash", "import_locations": ["src/app.js"]}},
                    "created_at": datetime.now(timezone.utc),
                }
            )
            await db.scans.update_one({"_id": _SCAN_ID}, {"$set": {"reachability_pending": True}})
            await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)
        return await real_language_map(database, scan_id)

    monkeypatch.setattr(reachability_enrichment, "build_component_language_map", _upload_mid_pass)

    await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)

    assert (await db.findings.find_one({"_id": "f-CVE-JS"}))["reachable"] is True
    summary = await db.analysis_results.find_one({"scan_id": _SCAN_ID, "analyzer_name": "reachability"})
    assert sorted(summary["result"]["languages"]) == ["javascript", "python"]
    assert not (await db.scans.find_one({"_id": _SCAN_ID})).get("reachability_pending")


@pytest.mark.asyncio
async def test_a_deferred_run_leaves_a_scan_under_analysis_to_that_analysis(db):
    """Its findings are about to be replaced, so the engine applies the callgraphs once it is final."""
    await _seed_callgraph(db)
    await _seed_dependencies(db)
    await db.findings.insert_one(_finding("CVE-1", "requests"))
    await _pending_scan(db, status="processing")

    await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)

    assert "reachable" not in await db.findings.find_one({"_id": "f-CVE-1"})
    assert (await db.scans.find_one({"_id": _SCAN_ID}))["reachability_pending"] is True


def _reachability_counters() -> tuple[float, float]:
    return (
        REGISTRY.get_sample_value("analysis_enrichment_total", {"type": "reachability"}) or 0.0,
        REGISTRY.get_sample_value("analysis_reachable_vulnerabilities_total", {"reachability_level": "import"}) or 0.0,
    )


@pytest.mark.asyncio
async def test_a_deferred_run_counts_its_verdicts_in_the_reachability_metrics(db):
    await _seed_callgraph(db)
    await _seed_dependencies(db)
    await db.findings.insert_one(_finding("CVE-1", "requests"))
    await _pending_scan(db)
    enriched_before, reachable_before = _reachability_counters()

    await run_pending_reachability_for_scan(_SCAN_ID, _PROJECT_ID, db)

    enriched_after, reachable_after = _reachability_counters()
    assert (enriched_after - enriched_before, reachable_after - reachable_before) == (1, 1)
