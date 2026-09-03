"""Permanent pins for StatsAccumulator rules a differential corpus cannot express."""

from app.core.constants import DETAILS_KEY_IN_KEV
from app.services.analysis.stats import compute_stats


def _finding(ftype="vulnerability", severity="HIGH", **details):
    return {"type": ftype, "severity": severity, "component": "pkg", "details": dict(details), "waived": False}


class TestVulnerabilityGate:
    def test_non_vulnerability_findings_never_count_as_deprioritized(self):
        """Secrets and SAST carry no EPSS; without the type gate every one of them qualifies."""
        findings = [_finding(ftype="secret"), _finding(ftype="sast"), _finding(ftype="license")]
        stats = compute_stats(findings, {})
        assert stats.prioritized.deprioritized_count == 0
        assert stats.prioritized.total == 0

    def test_unreachable_kev_vulnerability_is_deprioritized(self):
        doc = _finding(**{DETAILS_KEY_IN_KEV: True, "epss_score": 0.9})
        doc["reachable"] = False
        stats = compute_stats([doc], {})
        assert stats.prioritized.deprioritized_count == 1
        assert stats.prioritized.actionable_total == 0

    def test_actionable_severity_split_only_counts_critical_and_high(self):
        findings = [
            _finding(severity="CRITICAL", **{DETAILS_KEY_IN_KEV: True}),
            _finding(severity="HIGH", **{DETAILS_KEY_IN_KEV: True}),
            _finding(severity="MEDIUM", **{DETAILS_KEY_IN_KEV: True}),
        ]
        stats = compute_stats(findings, {})
        assert (stats.prioritized.actionable_critical, stats.prioritized.actionable_high) == (1, 1)
        assert stats.prioritized.actionable_total == 3

    def test_waived_findings_are_skipped_before_any_counter(self):
        findings = [_finding(severity="CRITICAL"), {**_finding(severity="CRITICAL"), "waived": True}]
        stats = compute_stats(findings, {})
        assert stats.critical == 1
        assert stats.prioritized.total == 1


class TestSecretGate:
    def test_tree_state_buckets_are_mutually_exclusive(self):
        findings = [
            _finding(ftype="secret", verified=True, in_current_tree=True),
            _finding(ftype="secret", verified=False, in_current_tree=False),
            _finding(ftype="secret", verified=None, in_current_tree=None),
        ]
        s = compute_stats(findings, {}).secret_priority
        assert (s.in_current_tree_count, s.historical_only_count, s.unknown_tree_count) == (1, 1, 1)
        assert s.in_current_tree_count + s.historical_only_count + s.unknown_tree_count == s.total

    def test_absent_tree_key_counts_as_unknown_not_historical(self):
        s = compute_stats([_finding(ftype="secret", verified=True)], {}).secret_priority
        assert (s.unknown_tree_count, s.historical_only_count) == (1, 0)

    def test_a_junk_tree_value_lands_in_no_bucket(self):
        """Mongo's three $eq branches all miss a non-boolean; the fold must miss it too."""
        s = compute_stats([_finding(ftype="secret", verified=True, in_current_tree="maybe")], {}).secret_priority
        assert (s.in_current_tree_count, s.historical_only_count, s.unknown_tree_count) == (0, 0, 0)
        assert s.total == 1

    def test_vulnerabilities_never_enter_the_secret_counters(self):
        s = compute_stats([_finding(verified=True, in_current_tree=True)], {}).secret_priority
        assert s.total == 0
