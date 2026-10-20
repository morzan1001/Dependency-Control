import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from bson import ObjectId
from prometheus_client import REGISTRY

from app.core import cache
from app.core.constants import DETAILS_KEY_IN_KEV, SCAN_STATUS_COMPLETED, SCAN_STATUS_PENDING
from app.core.worker import AnalysisWorkerManager
from app.db import mongodb
from app.models.finding import Finding, FindingType, Severity
from app.models.project import Scan
from app.services.aggregation import ResultAggregator
from app.services.analysis import engine
from app.services.analysis.runner import AnalyzerInput
from tests.helpers.analyzers import analyse_scan, run_context, serve_analyzer
from tests.mocks.fake_mongo import FakeDatabase

_WORKER = "pod-a/worker-0"


def _sample(name: str, **labels: str) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def _deltas(series: list[tuple[str, dict[str, str]]]):
    before = [_sample(name, **labels) for name, labels in series]
    return lambda: [_sample(name, **labels) - start for (name, labels), start in zip(series, before, strict=True)]


@pytest.mark.asyncio
async def test_cache_get_counts_a_stored_key_as_a_hit_and_an_absent_key_as_a_miss(fake_cache):
    await fake_cache.set("present", 1)
    await fake_cache._client.set(fake_cache._make_key("corrupt"), "{not json")
    moved = _deltas([("cache_hits_total", {}), ("cache_misses_total", {})])
    await fake_cache.get("present")
    await fake_cache.get("corrupt")
    await fake_cache.get("absent")
    assert moved() == [2, 1]


@pytest.mark.asyncio
async def test_cache_mget_counts_each_requested_key_as_a_hit_or_a_miss(fake_cache):
    await fake_cache.set("present", 1)
    await fake_cache._client.set(fake_cache._make_key("corrupt"), "{not json")
    moved = _deltas([("cache_hits_total", {}), ("cache_misses_total", {})])
    await fake_cache.mget(["present", "present", "corrupt", "absent"])
    assert moved() == [3, 1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation, call",
    [
        ("get", lambda c: c.get("k")),
        ("set", lambda c: c.set("k", 1)),
        ("mget", lambda c: c.mget(["k"])),
        ("mset", lambda c: c.mset({"k": 1})),
        ("incr", lambda c: c.incr("n", 60)),
        ("pop", lambda c: c.pop("k")),
    ],
)
async def test_every_cache_operation_is_timed(fake_cache, operation, call):
    moved = _deltas([("cache_operation_duration_seconds_count", {"operation": operation})])
    await call(fake_cache)
    assert moved() == [1]


@pytest.mark.asyncio
async def test_the_stats_refresh_sets_the_cache_gauges_and_a_health_check_leaves_them(fake_cache, monkeypatch):
    # INFO lists connected_clients under "clients" only, on Redis and Dragonfly alike.
    sections = {
        "memory": {"used_memory": 2048, "used_memory_human": "2.00K"},
        "stats": {"keyspace_hits": 3, "keyspace_misses": 1},
        "clients": {"connected_clients": 4},
    }
    fake_cache._client = MagicMock(info=AsyncMock(side_effect=lambda section: sections[section]))
    fake_cache._client.dbsize = AsyncMock(side_effect=[9, 7])
    monkeypatch.setattr(cache, "cache_service", fake_cache)

    await cache.update_cache_stats()
    health = await fake_cache.health_check()

    assert [_sample(name) for name in ("cache_keys_total", "cache_connected_clients", "cache_size_bytes")] == [
        9,
        4,
        2048,
    ]
    assert (health["connected_clients"], health["total_keys"]) == (4, 7)


@pytest.mark.asyncio
async def test_the_queue_gauge_follows_the_queue(monkeypatch):
    monkeypatch.setattr("app.core.worker.get_database", AsyncMock(return_value=FakeDatabase()))
    queued = AnalysisWorkerManager(num_workers=3)
    await queued.add_job("a")
    await queued.add_job("b")
    assert _sample("worker_queue_size") == 2
    await queued._process(queued.queue.get_nowait(), "worker-0")
    assert _sample("worker_queue_size") == 1
    await queued.stop()
    assert _sample("worker_queue_size") == 0


@pytest.mark.asyncio
async def test_the_active_worker_gauge_counts_the_workers_busy_with_a_job(monkeypatch):
    db = FakeDatabase()
    await db.projects.insert_one({"_id": "proj-1", "active_analyzers": []})
    await db.scans.insert_one({"_id": "scan-1", "project_id": "proj-1", "status": "pending", "sbom_refs": []})
    started, release = asyncio.Event(), asyncio.Event()

    async def _held_analysis(**_kwargs):
        started.set()
        await release.wait()
        return SCAN_STATUS_COMPLETED

    monkeypatch.setattr("app.core.worker.housekeeping_loop", AsyncMock())
    monkeypatch.setattr("app.core.worker.stale_scan_loop", AsyncMock())
    monkeypatch.setattr("app.core.worker.get_database", AsyncMock(return_value=db))
    monkeypatch.setattr("app.core.worker.run_analysis", _held_analysis)
    manager = AnalysisWorkerManager(num_workers=3)
    await manager.start()
    try:
        assert _sample("worker_active_count") == 0
        await manager.add_job("scan-1")
        await asyncio.wait_for(started.wait(), timeout=5)
        assert _sample("worker_active_count") == 1
        release.set()
        await asyncio.wait_for(manager.queue.join(), timeout=5)
        assert _sample("worker_active_count") == 0
    finally:
        release.set()
        await manager.stop()


@pytest.mark.asyncio
async def test_the_connection_gauge_follows_connect_and_close(monkeypatch):
    client = MagicMock()
    client.admin.command = AsyncMock()
    monkeypatch.setattr(mongodb, "AsyncIOMotorClient", lambda *_args, **_kwargs: client)

    await mongodb.connect_to_mongo()
    assert _sample("db_connections_active") == 1
    await mongodb.close_mongo_connection()
    assert _sample("db_connections_active") == 0


@pytest.mark.asyncio
async def test_an_analyzer_run_counts_its_scan_its_duration_and_its_failures(monkeypatch):
    monkeypatch.setattr(engine, "AnalysisResultRepository", lambda _db: MagicMock(save_result=AsyncMock()))
    labels = {"analyzer": "metric-probe"}
    moved = _deltas(
        [
            ("analysis_scans_total", labels),
            ("analysis_duration_seconds_count", labels),
            ("analysis_errors_total", labels),
        ]
    )
    analyzer = serve_analyzer(
        monkeypatch, "metric-probe", SimpleNamespace(analyze=AsyncMock(return_value={"error": "exit 1"}))
    )
    ctx = run_context(None, "scan")

    await engine.process_analyzer(ctx, ResultAggregator(), "metric-probe", AnalyzerInput(1, []))
    analyzer.analyze.side_effect = RuntimeError("boom")
    await engine.process_analyzer(ctx, ResultAggregator(), "metric-probe", AnalyzerInput(1, []))

    assert moved() == [2, 1, 2]


def test_crypto_evaluators_are_counted_and_timed(monkeypatch):
    monkeypatch.setattr(engine, "crypto_evaluators", lambda _catalog: {"crypto-probe": lambda _a, _p: {"findings": []}})
    labels = {"analyzer": "crypto-probe"}
    moved = _deltas([("analysis_scans_total", labels), ("analysis_duration_seconds_count", labels)])
    engine._evaluate_crypto([], None, {})
    assert moved() == [1, 1]


def test_sbom_parsing_counts_the_sbom_its_components_and_a_parse_error():
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1"}],
    }
    moved = _deltas(
        [
            ("analysis_sbom_processed_total", {"format": "cyclonedx"}),
            ("analysis_components_parsed_total", {}),
            ("analysis_sbom_parse_errors_total", {}),
        ]
    )
    engine._parse_and_track_sbom(document)
    engine._parse_and_track_sbom("not a document")
    assert moved() == [1, 1, 1]


@pytest.mark.asyncio
async def test_sbom_downloads_count_their_attempt_success_and_failure(monkeypatch):
    stream = MagicMock(read=AsyncMock(return_value=b'{"bomFormat": "CycloneDX", "specVersion": "1.5"}'))
    monkeypatch.setattr(engine, "open_gridfs_download_with_retry", AsyncMock(return_value=stream))
    moved = _deltas(
        [
            ("analysis_gridfs_operations_total", {"operation": "download", "status": s})
            for s in ("attempt", "success", "error")
        ]
    )
    await engine._load_sbom(None, str(ObjectId()), 1, write_file=False)
    engine._sbom_load_failed(ResultAggregator(), "gone")
    assert moved() == [1, 1, 1]


def test_findings_are_counted_by_type_and_by_scanner():
    def finding(finding_id, finding_type, severity, *scanners):
        return Finding(
            id=finding_id, type=finding_type, severity=severity, component="c", description="d", scanners=list(scanners)
        )

    moved = _deltas(
        [
            ("analysis_findings_by_type_total", {"type": "vulnerability", "severity": "HIGH"}),
            ("analysis_findings_by_type_total", {"type": "license", "severity": "MEDIUM"}),
            ("analysis_findings_total", {"analyzer": "trivy", "severity": "HIGH"}),
            ("analysis_findings_total", {"analyzer": "grype", "severity": "HIGH"}),
            ("analysis_findings_total", {"analyzer": "license_compliance", "severity": "MEDIUM"}),
        ]
    )
    engine._track_findings_metrics(
        [
            finding("CVE-1", FindingType.VULNERABILITY, Severity.HIGH, "trivy", "grype"),
            finding("CVE-2", FindingType.VULNERABILITY, Severity.HIGH, "trivy"),
            finding("LIC-GPL", FindingType.LICENSE, Severity.MEDIUM, "license_compliance"),
        ]
    )
    assert moved() == [2, 1, 2, 1, 1]


@pytest.mark.asyncio
async def test_epss_kev_enrichment_counts_the_enriched_findings_their_scores_and_kev_hits(monkeypatch):
    monkeypatch.setattr(
        engine.vulnerability_enrichment_service, "enrich_findings", AsyncMock(return_value=(None, None))
    )
    monkeypatch.setattr(engine, "AnalysisResultRepository", lambda _db: MagicMock(save_result=AsyncMock()))
    moved = _deltas(
        [
            ("analysis_enrichment_total", {"type": "epss_kev"}),
            ("analysis_epss_scores_count", {}),
            ("analysis_kev_vulnerabilities_total", {}),
        ]
    )
    findings = [{"details": {"epss_score": 0.5, DETAILS_KEY_IN_KEV: True}}, {"details": {}}]
    await engine._run_epss_kev_enrichment(run_context(None, "scan"), findings, [])
    assert moved() == [2, 1, 1]


@pytest.mark.asyncio
async def test_a_run_rescheduled_by_new_input_is_counted_as_a_race(db):
    await db.scans.insert_one({"_id": "s", "status": "processing", "worker_id": _WORKER, "sbom_generation": 1})
    moved = _deltas([("analysis_race_conditions_total", {})])
    status = await engine._write_final_state(
        run_context(db, "s", sbom_generation=2),
        SCAN_STATUS_COMPLETED,
        {"$set": {"status": SCAN_STATUS_COMPLETED}},
        datetime.now(timezone.utc),
    )
    assert status == SCAN_STATUS_PENDING
    assert moved() == [1]


@pytest.mark.asyncio
async def test_a_rescan_run_counts_the_rescan_and_its_aggregation_time(db, monkeypatch):
    monkeypatch.setattr(engine, "AsyncIOMotorGridFSBucket", lambda _db: None)
    monkeypatch.setattr(engine, "_send_integrations_and_notifications", AsyncMock())
    scan = Scan(project_id="p", branch="main", sbom_refs=[], status="processing", worker_id=_WORKER, is_rescan=True)
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    moved = _deltas([("analysis_rescan_operations_total", {}), ("analysis_aggregation_duration_seconds_count", {})])

    assert await analyse_scan(db, scan.id, [], [], worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    assert moved() == [1, 1]
