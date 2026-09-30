"""_aggregate_external_results skips malformed results and emits a SYSTEM_WARNING when one fails to aggregate."""

import asyncio
from types import SimpleNamespace

from app.models.finding import FindingType
from app.repositories.analysis_results import AnalysisResultRepository
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import _aggregate_external_results


def _row(analyzer_name: str, result: dict) -> dict:
    return {"analyzer_name": analyzer_name, "result": result}


def _repo_yielding(*rows: dict) -> SimpleNamespace:
    async def iterate_raw(_query, _projection):
        for row in rows:
            yield row

    return SimpleNamespace(
        iterate_raw=iterate_raw, load_result=lambda row: AnalysisResultRepository.load_result(None, row)
    )


class TestAggregateExternalResultsResilience:
    """_aggregate_external_results is isolated per result."""

    def _make_aggregator(self):
        return ResultAggregator()

    def test_good_results_aggregated_when_one_malformed(self, monkeypatch):
        aggregator = self._make_aggregator()
        results_summary: list = []

        # 'trivy' absent from analyzers -> external results path
        monkeypatch.setattr("app.services.analysis.engine._ENGINE_RESULT_NAMES", frozenset())

        good_result = _row(
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

        # simulates corrupt stored data
        bad_result = _row("bad_analyzer", {"corrupt": object()})

        result_repo = _repo_yielding(bad_result, good_result)

        original_aggregate = aggregator.aggregate

        def patched_aggregate(analyzer_name, result, source=None):
            if analyzer_name == "bad_analyzer":
                raise ValueError("Simulated corrupt result")
            return original_aggregate(analyzer_name, result, source=source)

        aggregator.aggregate = patched_aggregate

        asyncio.run(_aggregate_external_results(aggregator, result_repo, "scan-1", results_summary))

        findings = aggregator.get_findings()

        components = [f.component for f in findings]
        assert "requests" in components or any("CVE-2023-GOOD" in str(f.details) for f in findings), (
            f"Expected 'requests' finding to survive; got components={components}"
        )
        assert len(findings) >= 1

        # a SYSTEM_WARNING gives a user-visible signal that a result was dropped
        warning_findings = [f for f in findings if f.type == FindingType.SYSTEM_WARNING]
        assert len(warning_findings) >= 1, (
            "Expected at least one SYSTEM_WARNING finding when a result fails to aggregate; "
            f"got finding types: {[f.type for f in findings]}"
        )
        assert any("bad_analyzer" in f.description for f in warning_findings), (
            f"Expected SYSTEM_WARNING to mention the failed analyzer; "
            f"got descriptions: {[f.description for f in warning_findings]}"
        )

    def test_results_summary_still_populated_after_bad_result(self, monkeypatch):
        aggregator = self._make_aggregator()
        results_summary: list = []

        monkeypatch.setattr("app.services.analysis.engine._ENGINE_RESULT_NAMES", frozenset())

        good_result = _row(
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

        bad_result = _row("bad_analyzer", {})

        result_repo = _repo_yielding(bad_result, good_result)

        original_aggregate = aggregator.aggregate

        def patched_aggregate(analyzer_name, result, source=None):
            if analyzer_name == "bad_analyzer":
                raise RuntimeError("Simulated crash")
            return original_aggregate(analyzer_name, result, source=source)

        aggregator.aggregate = patched_aggregate

        asyncio.run(_aggregate_external_results(aggregator, result_repo, "scan-2", results_summary))

        assert any("trivy" in s for s in results_summary), f"Expected trivy in results_summary; got {results_summary}"
