"""Finding 6: _aggregate_external_results must skip malformed results and keep the rest."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import _aggregate_external_results


class FakeResult:
    """Minimal stand-in for an AnalysisResult document."""

    def __init__(self, analyzer_name: str, result: dict):
        self.analyzer_name = analyzer_name
        self.result = result


class TestAggregateExternalResultsResilience:
    """_aggregate_external_results must be per-result isolated."""

    def _make_aggregator(self):
        return ResultAggregator()

    def test_good_results_aggregated_when_one_malformed(self, monkeypatch):
        """Finding 6: a malformed stored result must be skipped; the rest must aggregate."""
        aggregator = self._make_aggregator()
        results_summary: list = []

        # Patch analyzers so the 'trivy' key is NOT in it (external results path)
        monkeypatch.setattr("app.services.analysis.engine.analyzers", {})

        # Arrange: good trivy result + one that will raise when aggregate() is called
        good_result = FakeResult(
            "trivy",
            {
                "Results": [
                    {
                        "Target": "test",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2023-GOOD",
                                "PkgName": "requests",
                                "InstalledVersion": "2.28.0",
                                "Severity": "HIGH",
                                "Description": "Good finding",
                            }
                        ],
                    }
                ]
            },
        )

        # A result whose aggregation will explode (simulates corrupt stored data)
        class BoomResult:
            analyzer_name = "bad_analyzer"
            result = {"corrupt": object()}  # not JSON-serialisable, triggers normaliser errors

        bad_result = BoomResult()

        # Make result_repo return [bad_result, good_result] to test both orderings
        result_repo = SimpleNamespace(
            find_by_scan=AsyncMock(return_value=[bad_result, good_result])
        )

        # Force the bad result to raise during aggregate by monkeypatching aggregate
        original_aggregate = aggregator.aggregate

        def patched_aggregate(analyzer_name, result, source=None):
            if analyzer_name == "bad_analyzer":
                raise ValueError("Simulated corrupt result")
            return original_aggregate(analyzer_name, result, source=source)

        aggregator.aggregate = patched_aggregate

        asyncio.run(
            _aggregate_external_results(aggregator, result_repo, "scan-1", results_summary)
        )

        findings = aggregator.get_findings()

        # Good finding must survive
        components = [f.component for f in findings]
        assert "requests" in components or any("CVE-2023-GOOD" in str(f.details) for f in findings), (
            f"Expected 'requests' finding to survive; got components={components}"
        )
        # Scan must not have completely failed
        assert len(findings) >= 1

    def test_results_summary_still_populated_after_bad_result(self, monkeypatch):
        """A skipped malformed result must not prevent good results from being logged."""
        aggregator = self._make_aggregator()
        results_summary: list = []

        monkeypatch.setattr("app.services.analysis.engine.analyzers", {})

        good_result = FakeResult(
            "trivy",
            {
                "Results": [
                    {
                        "Target": "test",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2023-GOOD",
                                "PkgName": "lodash",
                                "InstalledVersion": "4.17.0",
                                "Severity": "MEDIUM",
                                "Description": "Test finding",
                            }
                        ],
                    }
                ]
            },
        )

        class BoomResult:
            analyzer_name = "bad_analyzer"
            result = {}

        bad_result = BoomResult()

        result_repo = SimpleNamespace(
            find_by_scan=AsyncMock(return_value=[bad_result, good_result])
        )

        original_aggregate = aggregator.aggregate

        def patched_aggregate(analyzer_name, result, source=None):
            if analyzer_name == "bad_analyzer":
                raise RuntimeError("Simulated crash")
            return original_aggregate(analyzer_name, result, source=source)

        aggregator.aggregate = patched_aggregate

        asyncio.run(
            _aggregate_external_results(aggregator, result_repo, "scan-2", results_summary)
        )

        # Good result should be in summary
        assert any("trivy" in s for s in results_summary), (
            f"Expected trivy in results_summary; got {results_summary}"
        )
