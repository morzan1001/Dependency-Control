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


class _FakeCache:
    def __init__(self, stored: dict[str, Any], peer_payload: dict[str, Any] | None = None) -> None:
        self.stored = stored
        self.peer_payload = peer_payload
        self.looked_up: list[str] = []

    async def mget(self, keys: list[str]) -> dict[str, Any]:
        self.looked_up.extend(keys)
        return {key: self.stored.get(key) for key in keys}

    async def get_or_fetch_with_lock(self, key: str, fetch_fn: Any, **_kw: Any) -> Any:
        self.looked_up.append(key)
        return self.peer_payload


def _payload(name: str, version: str, purl: str, score: float) -> dict[str, Any]:
    """What another project's scan cached: its own component's spelling throughout."""
    return {
        "metadata": {"name": name, "version": version, "system": "npm", "purl": purl, "licenses": ["MIT"]},
        "scorecard_issue": {
            "component": name,
            "version": version,
            "purl": purl,
            "severity": Severity.MEDIUM.value,
            "scorecard": {"overallScore": score, "checks": []},
        },
    }


class TestIdentityOfCachedResults:
    @pytest.mark.asyncio
    async def test_same_named_packages_keep_their_own_metadata(self, monkeypatch):
        nx, nrwl = "pkg:npm/%40nx/devkit@16.5.0", "pkg:npm/%40nrwl/devkit@16.5.0"
        cache = _FakeCache(
            {
                "deps:npm:@nx/devkit:16.5.0": _payload("devkit", "16.5.0", nx, 9.0),
                "deps:npm:@nrwl/devkit:16.5.0": _payload("devkit", "16.5.0", nrwl, 9.0),
            }
        )
        monkeypatch.setattr("app.services.analyzers.deps_dev.cache_service", cache)
        components = [{"name": "devkit", "version": "16.5.0", "purl": purl} for purl in (nx, nrwl)]

        result = await DepsDevAnalyzer().analyze({}, parsed_components=components)

        assert sorted(meta["purl"] for meta in result["package_metadata"].values()) == sorted([nx, nrwl])

    @pytest.mark.asyncio
    async def test_a_cached_payload_is_named_after_the_scanning_component(self, monkeypatch):
        cached = _payload("core", "17.0.0", "pkg:npm/%40angular/core@17.0.0", 3.0)
        monkeypatch.setattr(
            "app.services.analyzers.deps_dev.cache_service", _FakeCache({"deps:npm:@angular/core:17.0.0": cached})
        )
        component = {"name": "@angular/core", "version": "17.0.0", "purl": "pkg:npm/@angular/core@17.0.0"}

        result = await DepsDevAnalyzer().analyze({}, parsed_components=[component])

        [metadata] = result["package_metadata"].values()
        [issue] = result["scorecard_issues"]
        assert (metadata["name"], metadata["purl"]) == ("@angular/core", "pkg:npm/@angular/core@17.0.0")
        assert (issue["component"], issue["purl"]) == ("@angular/core", "pkg:npm/@angular/core@17.0.0")

    @pytest.mark.asyncio
    async def test_a_payload_a_peer_fetched_is_named_after_the_scanning_component(self, monkeypatch):
        peer = _payload("Django", "4.2.0", "pkg:pypi/Django@4.2.0", 3.0)
        monkeypatch.setattr("app.services.analyzers.deps_dev.cache_service", _FakeCache({}, peer_payload=peer))
        monkeypatch.setattr("app.services.analyzers.deps_dev.InstrumentedAsyncClient", lambda *a, **k: _NoClient())
        component = {"name": "django", "version": "4.2.0", "purl": "pkg:pypi/django@4.2.0"}

        result = await DepsDevAnalyzer().analyze({}, parsed_components=[component])

        [metadata] = result["package_metadata"].values()
        [issue] = result["scorecard_issues"]
        assert (metadata["name"], issue["component"], issue["purl"]) == ("django", "django", "pkg:pypi/django@4.2.0")

    @pytest.mark.asyncio
    async def test_an_ecosystem_deps_dev_does_not_serve_is_never_looked_up(self, monkeypatch):
        cache = _FakeCache({})
        monkeypatch.setattr("app.services.analyzers.deps_dev.cache_service", cache)
        component = {"name": "framework", "version": "10.0.0", "purl": "pkg:composer/laravel/framework@10.0.0"}

        result = await DepsDevAnalyzer().analyze({}, parsed_components=[component])

        assert result == {"scorecard_issues": [], "package_metadata": {}}
        assert cache.looked_up == []


class _NoClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a: object) -> None:
        return None
