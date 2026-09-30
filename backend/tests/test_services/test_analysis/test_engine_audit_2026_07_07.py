"""Engine resilience: waived-finding filtering and post-processor result exclusion."""

import asyncio
from types import SimpleNamespace

from app.repositories.analysis_results import AnalysisResultRepository
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import (
    _aggregate_external_results,
    _carry_over_external_results,
    _cleanup_analyzer_names,
    _filter_out_waived_findings,
)
from app.services.analysis.registry import CRYPTO_ANALYZERS
from app.services.analysis.stats import build_epss_kev_summary, build_reachability_summary
from tests.mocks.fake_mongo import FakeDatabase


class _AsyncIter:
    """Minimal async cursor stand-in for motor's find()."""

    def __init__(self, docs):
        self._docs = list(docs)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._docs:
            raise StopAsyncIteration
        return self._docs.pop(0)


class _FakeFindings:
    def __init__(self, waived_docs):
        self._waived_docs = waived_docs
        self.last_query = None

    def find(self, query, projection=None):
        self.last_query = query
        return _AsyncIter(self._waived_docs)


class TestFilterOutWaivedFindings:
    def test_waived_finding_is_excluded(self):
        findings = [SimpleNamespace(id="F1"), SimpleNamespace(id="F2"), SimpleNamespace(id="F3")]
        db = {"findings": _FakeFindings([{"finding_id": "F2"}])}

        result = asyncio.run(_filter_out_waived_findings(findings, "scan-1", db))

        ids = [f.id for f in result]
        assert ids == ["F1", "F3"], f"waived F2 must be dropped, got {ids}"

    def test_no_waivers_returns_original(self):
        findings = [SimpleNamespace(id="F1")]
        db = {"findings": _FakeFindings([])}

        result = asyncio.run(_filter_out_waived_findings(findings, "scan-1", db))

        assert result is findings  # same object: no filtering performed

    def test_query_filters_on_scan_and_waived(self):
        db = {"findings": _FakeFindings([{"finding_id": "F1"}])}
        asyncio.run(_filter_out_waived_findings([SimpleNamespace(id="F1")], "scan-9", db))
        assert db["findings"].last_query == {"scan_id": "scan-9", "waived": True}


class TestCleanupAnalyzerNames:
    def test_includes_post_processors_and_crypto(self):
        names = set(_cleanup_analyzer_names([]))
        assert "epss_kev" in names
        assert "reachability" in names
        assert CRYPTO_ANALYZERS.issubset(names)


class TestAggregateExternalSkipsPostProcessors:
    def test_epss_kev_and_reachability_not_aggregated(self, monkeypatch):
        # No registered analyzer -> only _POST_PROCESSOR_ANALYZERS membership can exclude these.
        monkeypatch.setattr("app.services.analysis.engine.analyzer_factories", {})
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
        ):
            asyncio.run(AnalysisResultRepository(db).save_result("scan-1", analyzer_name, result))
        results_summary: list = []

        asyncio.run(_aggregate_external_results(aggregator, AnalysisResultRepository(db), "scan-1", results_summary))

        assert calls == [], f"post-processor rows must not be aggregated; got {calls}"
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
