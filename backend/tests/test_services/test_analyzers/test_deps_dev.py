"""Tests for the DepsDevAnalyzer scorecard severity handling.

Audit finding (bug/medium): analyzers are module-level singletons shared
across concurrent per-project scans, yet the old code stashed the resolved
per-project ``_severity_thresholds`` on ``self`` in ``analyze`` and read it
back — via ``getattr(self, ...)`` — inside ``_create_scorecard_issue`` after
several network awaits. Two scans with different configured thresholds running
on the same worker could therefore clobber each other's thresholds mid-flight,
producing nondeterministic severities. These tests pin that the thresholds are
threaded per-call and never leak through instance state.
"""

from typing import Any, Dict

import pytest

from app.models.finding import Severity
from app.services.analyzers.deps_dev import DepsDevAnalyzer


def _scorecard(score: float) -> Dict[str, Any]:
    """A scorecard payload with no failing checks, so severity is score-driven."""
    return {"overallScore": score, "date": "2024-01-01", "checks": []}


class TestScorecardSeverityThreading:
    def setup_method(self):
        self.analyzer = DepsDevAnalyzer()

    def test_create_scorecard_issue_respects_passed_thresholds(self):
        """A score of 3.0 (no critical issues) grades differently depending on
        the thresholds passed in — proving the value comes from the parameter,
        not from shared instance state."""
        # Default-ish thresholds: 3.0 falls in [medium, low) -> MEDIUM.
        issue_default = self.analyzer._create_scorecard_issue(
            "pkg", "1.0.0", "pkg:pypi/pkg@1.0.0", "github.com/o/r", _scorecard(3.0),
            {"high": 2.0, "medium": 4.0, "low": 5.0},
        )
        assert issue_default["severity"] == Severity.MEDIUM.value

        # Stricter thresholds: 3.0 now falls below high -> HIGH.
        issue_strict = self.analyzer._create_scorecard_issue(
            "pkg", "1.0.0", "pkg:pypi/pkg@1.0.0", "github.com/o/r", _scorecard(3.0),
            {"high": 4.0, "medium": 6.0, "low": 8.0},
        )
        assert issue_strict["severity"] == Severity.HIGH.value

    def test_no_state_leaks_between_calls_on_shared_instance(self):
        """Calling with strict thresholds then with lenient thresholds on the
        SAME instance must not let the first call's thresholds bleed into the
        second (the concurrency cross-contamination the audit flagged)."""
        strict = self.analyzer._create_scorecard_issue(
            "a", "1", "pkg:pypi/a@1", "github.com/o/a", _scorecard(3.0),
            {"high": 4.0, "medium": 6.0, "low": 8.0},
        )
        lenient = self.analyzer._create_scorecard_issue(
            "b", "1", "pkg:pypi/b@1", "github.com/o/b", _scorecard(3.0),
            {"high": 1.0, "medium": 2.0, "low": 2.5},
        )
        assert strict["severity"] == Severity.HIGH.value
        # 3.0 is above every lenient threshold -> INFO, unaffected by the
        # earlier strict call.
        assert lenient["severity"] == Severity.INFO.value

    def test_defaults_used_when_thresholds_omitted(self):
        """Backward-compat: omitting thresholds falls back to defaults."""
        issue = self.analyzer._create_scorecard_issue(
            "pkg", "1.0.0", "pkg:pypi/pkg@1.0.0", "github.com/o/r", _scorecard(1.0)
        )
        assert issue["severity"] == Severity.HIGH.value

    @pytest.mark.asyncio
    async def test_analyze_does_not_stash_thresholds_on_instance(self):
        """analyze() must resolve thresholds into a local, not onto ``self`` —
        otherwise a concurrent scan sharing this singleton would read them."""
        result = await self.analyzer.analyze(
            sbom={},
            settings={"scorecard_high_threshold": 3.0},
            parsed_components=[],
        )
        assert result == {"scorecard_issues": [], "package_metadata": {}}
        assert not hasattr(self.analyzer, "_severity_thresholds")
