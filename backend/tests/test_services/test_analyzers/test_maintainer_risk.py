"""Tests for maintainer-risk signal correlation.

The two registry-side signals that historically produced the most
false-positives are ``stale_package`` (a mature library that's done
shipping features can look identical to an abandoned one) and
``free_email_maintainer`` (a personal address says nothing on its
own). These tests pin the rules that combine those signals with
their corroborating evidence before they become user-facing risks.
"""

from typing import Any, Dict, List, Optional

from app.services.analyzers.maintainer_risk import correlate_maintainer_risks


def _stale() -> Dict[str, Any]:
    return {"type": "stale_package", "severity_score": 3, "message": "stale"}


def _infrequent() -> Dict[str, Any]:
    return {"type": "infrequent_updates", "severity_score": 2, "message": "infrequent"}


def _inactive() -> Dict[str, Any]:
    return {"type": "inactive_repo", "severity_score": 3, "message": "inactive"}


def _archived() -> Dict[str, Any]:
    return {"type": "archived_repo", "severity_score": 4, "message": "archived"}


def _free_email() -> Dict[str, Any]:
    return {"type": "free_email_maintainer", "severity_score": 1, "message": "gmail"}


def _single_maintainer() -> Dict[str, Any]:
    return {"type": "single_maintainer", "severity_score": 2, "message": "solo"}


def _types(risks: List[Dict[str, Any]]) -> List[str]:
    return [r["type"] for r in risks]


class TestCorrelateMaintainerRisks:
    def test_stale_kept_when_repo_also_inactive(self):
        # Both registry and GitHub agree: real abandonment.
        risks = [_stale(), _inactive()]
        result = correlate_maintainer_risks(risks, github_active=False)
        assert "stale_package" in _types(result)
        assert "inactive_repo" in _types(result)

    def test_stale_suppressed_when_repo_active(self):
        # B6: registry says "no release in 2 years" but the repo is still
        # getting commits — that's a mature/finished package, not an
        # abandoned one. Drop the registry-only stale signal.
        risks = [_stale()]
        result = correlate_maintainer_risks(risks, github_active=True)
        assert "stale_package" not in _types(result)

    def test_infrequent_updates_suppressed_when_repo_active(self):
        # Same rule applies to the lower-severity sibling signal.
        risks = [_infrequent()]
        result = correlate_maintainer_risks(risks, github_active=True)
        assert "infrequent_updates" not in _types(result)

    def test_stale_kept_when_no_github_data(self):
        # No corroborating evidence either way -> keep the registry signal.
        risks = [_stale()]
        result = correlate_maintainer_risks(risks, github_active=None)
        assert "stale_package" in _types(result)

    def test_archived_overrides_active_repo_check(self):
        # Archived repos are unmaintained by definition; even if commits
        # were "recent" before archiving, the package is dead.
        risks = [_stale(), _archived()]
        result = correlate_maintainer_risks(risks, github_active=False)
        assert "archived_repo" in _types(result)
        assert "stale_package" in _types(result)

    def test_free_email_suppressed_when_alone(self):
        # B5: a maintainer using gmail is not a risk on its own — most
        # solo OSS maintainers do this. Only meaningful when paired with
        # the bus-factor signal.
        risks = [_free_email()]
        result = correlate_maintainer_risks(risks, github_active=None)
        assert "free_email_maintainer" not in _types(result)

    def test_free_email_kept_when_single_maintainer(self):
        # Free email + single maintainer is a real bus-factor concern:
        # if the maintainer disappears, there's no organizational fallback.
        risks = [_free_email(), _single_maintainer()]
        result = correlate_maintainer_risks(risks, github_active=None)
        assert "free_email_maintainer" in _types(result)
        assert "single_maintainer" in _types(result)

    def test_unrelated_risks_pass_through(self):
        # Correlation should never invent new risks or drop unrelated ones.
        custom = {"type": "unaddressed_issues", "severity_score": 2, "message": "x"}
        result = correlate_maintainer_risks([custom], github_active=True)
        assert result == [custom]

    def test_empty_list_returns_empty(self):
        assert correlate_maintainer_risks([], github_active=None) == []

    def test_active_repo_does_not_drop_unrelated_signals(self):
        # github_active=True should only affect stale-related signals, not
        # other registry findings.
        risks = [_single_maintainer(), _stale()]
        result = correlate_maintainer_risks(risks, github_active=True)
        types = _types(result)
        assert "single_maintainer" in types
        assert "stale_package" not in types
