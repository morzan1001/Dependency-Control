"""Engine resilience: waived-finding filtering and post-processor result exclusion."""

import asyncio
from types import SimpleNamespace

from app.repositories.analysis_results import AnalysisResultRepository
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import (
    _aggregate_external_results,
    _carry_over_external_results,
    _filter_out_waived_findings,
)
from app.services.analysis.registry import CRYPTO_ANALYZERS
from app.services.analysis.stats import build_epss_kev_summary, build_reachability_summary
from tests.mocks.fake_mongo import FakeDatabase


async def _filter_against(stored: list[dict], findings: list[dict]) -> list[dict]:
    db = FakeDatabase()
    for doc in stored:
        await db.findings.insert_one(doc)
    return await _filter_out_waived_findings(findings, "scan-1", db)


class TestFilterOutWaivedFindings:
    def test_a_record_waived_in_this_scan_is_excluded(self):
        findings = [{"_id": "R1"}, {"_id": "R2"}, {"_id": "R3"}]
        stored = [
            {"_id": "R2", "scan_id": "scan-1", "waived": True},
            {"_id": "R3", "scan_id": "scan-2", "waived": True},
        ]

        result = asyncio.run(_filter_against(stored, findings))

        assert [f["_id"] for f in result] == ["R1", "R3"]

    def test_without_waivers_every_record_is_kept(self):
        findings = [{"_id": "R1"}]

        assert asyncio.run(_filter_against([{"_id": "R1", "scan_id": "scan-1", "waived": False}], findings)) == findings


class TestAggregateExternalSkipsEngineRows:
    def test_post_processor_and_crypto_rows_are_not_aggregated_again(self):
        aggregator = ResultAggregator()

        calls = []
        orig = aggregator.aggregate

        def spy(analyzer_name, result, source=None):
            calls.append(analyzer_name)
            return orig(analyzer_name, result, source=source)

        aggregator.aggregate = spy

        db = FakeDatabase()
        for analyzer_name, result in (
            ("epss_kev", build_epss_kev_summary([])),
            ("reachability", build_reachability_summary([], [])),
            *((name, {"findings": []}) for name in sorted(CRYPTO_ANALYZERS)),
        ):
            asyncio.run(
                db.analysis_results.insert_one({"scan_id": "scan-1", "analyzer_name": analyzer_name, "result": result})
            )
        results_summary: list = []

        asyncio.run(_aggregate_external_results(aggregator, AnalysisResultRepository(db), "scan-1", results_summary))

        assert calls == [], f"engine-written rows must not be aggregated; got {calls}"
        assert results_summary == [], f"no spurious Success lines expected; got {results_summary}"


class TestCarryOverExcludesPostProcessors:
    def test_nin_includes_post_processors(self, monkeypatch):
        captured = {}

        class _FakeRepo:
            def __init__(self, _db):
                pass

            async def carry_over(self, from_scan_id, to_scan_id, exclude_names):
                captured["exclude_names"] = exclude_names

        monkeypatch.setattr("app.services.analysis.engine.AnalysisResultRepository", _FakeRepo)

        scan_doc = SimpleNamespace(is_rescan=True, original_scan_id="orig-1")
        asyncio.run(_carry_over_external_results("scan-2", scan_doc, SimpleNamespace()))

        nin = captured["exclude_names"]
        assert "epss_kev" in nin
        assert "reachability" in nin
        assert CRYPTO_ANALYZERS.issubset(nin)
