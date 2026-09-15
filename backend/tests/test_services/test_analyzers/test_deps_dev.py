"""Tests that scorecard severity thresholds are threaded per call, never stored on the shared analyzer instance."""

from typing import Any

import pytest

from app.models.finding import Severity
from app.services.analyzers.deps_dev import DepsDevAnalyzer, _validated_threshold


def _scorecard(score: float) -> dict[str, Any]:
    """Scorecard payload with no failing checks, so severity is score-driven."""
    return {"overallScore": score, "date": "2024-01-01", "checks": []}


def _scorecard_failing(score: float, check_name: str) -> dict[str, Any]:
    return {
        "overallScore": score,
        "date": "2024-01-01",
        "checks": [{"name": check_name, "score": 0, "reason": "detected"}],
    }


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

    @pytest.mark.parametrize(
        "score,expected",
        [
            (2.0, Severity.MEDIUM.value),
            (4.0, Severity.LOW.value),
            (5.0, Severity.INFO.value),
        ],
    )
    def test_a_score_sitting_on_a_threshold_falls_into_the_gentler_band(self, score, expected):
        """Each threshold is the floor of the band above it, so a score reaching it has left the band below."""
        issue = self.analyzer._create_scorecard_issue(
            "pkg",
            "1.0.0",
            "pkg:pypi/pkg@1.0.0",
            "github.com/o/r",
            _scorecard(score),
            {"high": 2.0, "medium": 4.0, "low": 5.0},
        )
        assert issue["severity"] == expected

    def test_a_dangerous_workflow_outranks_the_generic_critical_issue_band(self):
        """A workflow that can be hijacked is graded like a known vulnerability, above an unmaintained project."""
        dangerous = self.analyzer._create_scorecard_issue(
            "pkg",
            "1.0.0",
            "pkg:pypi/pkg@1.0.0",
            "github.com/o/r",
            _scorecard_failing(8.0, "Dangerous-Workflow"),
            {"high": 2.0, "medium": 4.0, "low": 5.0},
        )
        unmaintained = self.analyzer._create_scorecard_issue(
            "pkg",
            "1.0.0",
            "pkg:pypi/pkg@1.0.0",
            "github.com/o/r",
            _scorecard_failing(8.0, "Maintained"),
            {"high": 2.0, "medium": 4.0, "low": 5.0},
        )
        assert dangerous["severity"] == Severity.HIGH.value
        assert unmaintained["severity"] == Severity.MEDIUM.value

    def test_a_threshold_configured_at_the_edge_of_the_allowed_range_still_grades(self):
        """0 and 10 are legal scorecard scores, so an operator may pin a band boundary to either end."""
        thresholds = {
            "high": _validated_threshold({"scorecard_high_threshold": 0.0}, "scorecard_high_threshold", 2.0),
            "medium": _validated_threshold({"scorecard_medium_threshold": 4.0}, "scorecard_medium_threshold", 4.0),
            "low": _validated_threshold({"scorecard_low_threshold": 10.0}, "scorecard_low_threshold", 5.0),
        }
        issue = self.analyzer._create_scorecard_issue(
            "pkg", "1.0.0", "pkg:pypi/pkg@1.0.0", "github.com/o/r", _scorecard(7.0), thresholds
        )
        assert issue["severity"] == Severity.LOW.value

    def test_a_threshold_outside_the_score_range_falls_back_to_the_default(self):
        assert _validated_threshold({"scorecard_low_threshold": 11.0}, "scorecard_low_threshold", 5.0) == 5.0
        assert _validated_threshold({"scorecard_low_threshold": -1.0}, "scorecard_low_threshold", 5.0) == 5.0

    @pytest.mark.asyncio
    async def test_analyze_does_not_stash_thresholds_on_instance(self):
        result = await self.analyzer.analyze(
            sbom={},
            settings={"scorecard_high_threshold": 3.0},
            parsed_components=[],
        )
        assert result == {"scorecard_issues": [], "package_metadata": {}}
        assert not hasattr(self.analyzer, "_severity_thresholds")
