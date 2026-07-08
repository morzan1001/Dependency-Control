"""Tests that scorecard severity thresholds are threaded per call, never stored on the shared analyzer instance."""

from typing import Any, Dict

import pytest

from app.models.finding import Severity
from app.services.analyzers.deps_dev import DepsDevAnalyzer


def _scorecard(score: float) -> Dict[str, Any]:
    """Scorecard payload with no failing checks, so severity is score-driven."""
    return {"overallScore": score, "date": "2024-01-01", "checks": []}


class TestScorecardSeverityThreading:
    def setup_method(self):
        self.analyzer = DepsDevAnalyzer()

    def test_create_scorecard_issue_respects_passed_thresholds(self):
        # 3.0 falls in [medium, low) -> MEDIUM.
        issue_default = self.analyzer._create_scorecard_issue(
            "pkg",
            "1.0.0",
            "pkg:pypi/pkg@1.0.0",
            "github.com/o/r",
            _scorecard(3.0),
            {"high": 2.0, "medium": 4.0, "low": 5.0},
        )
        assert issue_default["severity"] == Severity.MEDIUM.value

        # Stricter thresholds: 3.0 now falls below high -> HIGH.
        issue_strict = self.analyzer._create_scorecard_issue(
            "pkg",
            "1.0.0",
            "pkg:pypi/pkg@1.0.0",
            "github.com/o/r",
            _scorecard(3.0),
            {"high": 4.0, "medium": 6.0, "low": 8.0},
        )
        assert issue_strict["severity"] == Severity.HIGH.value

    def test_no_state_leaks_between_calls_on_shared_instance(self):
        strict = self.analyzer._create_scorecard_issue(
            "a",
            "1",
            "pkg:pypi/a@1",
            "github.com/o/a",
            _scorecard(3.0),
            {"high": 4.0, "medium": 6.0, "low": 8.0},
        )
        lenient = self.analyzer._create_scorecard_issue(
            "b",
            "1",
            "pkg:pypi/b@1",
            "github.com/o/b",
            _scorecard(3.0),
            {"high": 1.0, "medium": 2.0, "low": 2.5},
        )
        assert strict["severity"] == Severity.HIGH.value
        # 3.0 is above every lenient threshold -> INFO.
        assert lenient["severity"] == Severity.INFO.value

    def test_defaults_used_when_thresholds_omitted(self):
        issue = self.analyzer._create_scorecard_issue(
            "pkg", "1.0.0", "pkg:pypi/pkg@1.0.0", "github.com/o/r", _scorecard(1.0)
        )
        assert issue["severity"] == Severity.HIGH.value

    @pytest.mark.asyncio
    async def test_analyze_does_not_stash_thresholds_on_instance(self):
        result = await self.analyzer.analyze(
            sbom={},
            settings={"scorecard_high_threshold": 3.0},
            parsed_components=[],
        )
        assert result == {"scorecard_issues": [], "package_metadata": {}}
        assert not hasattr(self.analyzer, "_severity_thresholds")
