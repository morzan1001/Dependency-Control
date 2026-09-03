"""Permanent pins for StatsAccumulator rules a differential corpus cannot express."""

import pytest

from app.core.constants import DETAILS_KEY_IN_KEV, DETAILS_KEY_KEV_RANSOMWARE
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


class TestEpssTyping:
    """Every persisted shape of epss_score: missing, null, 0.0, int, float, bool, string, list, dict.
    A non-numeric one is treated as absent — decided, not inherited: the pipeline ranks
    bool and string above every number and then dies at sum(epss_scores)."""

    @pytest.mark.parametrize("junk", ["0.9", True, False, [], {}, "n/a"])
    def test_non_numeric_epss_is_treated_as_missing(self, junk):
        t = compute_stats([_finding(epss_score=junk)], {}).threat_intel
        assert t.high_epss_count == 0
        assert t.medium_epss_count == 0
        assert t.avg_epss_score is None
        assert t.max_epss_score is None
        assert t.active_exploitation_count == 0

    def test_non_numeric_epss_leaves_the_finding_deprioritized(self):
        p = compute_stats([_finding(epss_score="0.9")], {}).prioritized
        assert p.deprioritized_count == 1
        assert p.actionable_total == 0

    @pytest.mark.parametrize("details", [{"epss_score": None}, {}])
    def test_an_explicit_null_epss_is_indistinguishable_from_an_absent_key(self, details):
        """Both shapes persist today; Mongo's $gte: [null, 0.1] is false, so neither may score."""
        stats = compute_stats([_finding(**details)], {})
        assert stats.threat_intel.avg_epss_score is None
        assert stats.threat_intel.max_epss_score is None
        assert (stats.threat_intel.high_epss_count, stats.threat_intel.medium_epss_count) == (0, 0)
        assert stats.threat_intel.active_exploitation_count == 0
        assert stats.prioritized.deprioritized_count == 1

    def test_zero_epss_is_a_real_value_not_a_missing_one(self):
        t = compute_stats([_finding(epss_score=0.0)], {}).threat_intel
        assert t.avg_epss_score == 0.0
        assert t.max_epss_score == 0.0

    def test_integer_epss_is_accepted(self):
        t = compute_stats([_finding(epss_score=1)], {}).threat_intel
        assert t.max_epss_score == 1.0
        assert t.high_epss_count == 1


class TestThreatIntelBoundaries:
    def test_epss_buckets_are_exclusive_at_the_high_edge(self):
        t = compute_stats([_finding(epss_score=0.1)], {}).threat_intel
        assert (t.high_epss_count, t.medium_epss_count) == (1, 0)

    def test_weaponized_needs_kev_alongside_very_high_epss(self):
        assert compute_stats([_finding(epss_score=0.9)], {}).threat_intel.weaponized_count == 0
        assert (
            compute_stats([_finding(epss_score=0.9, **{DETAILS_KEY_IN_KEV: True})], {}).threat_intel.weaponized_count
            == 1
        )

    def test_ransomware_alone_is_weaponized(self):
        t = compute_stats([_finding(**{DETAILS_KEY_KEV_RANSOMWARE: True})], {}).threat_intel
        assert t.weaponized_count == 1

    def test_kev_and_epss_counters_ignore_the_finding_type(self):
        t = compute_stats([_finding(ftype="secret", **{DETAILS_KEY_IN_KEV: True})], {}).threat_intel
        assert t.kev_count == 1
        assert t.active_exploitation_count == 1

    def test_in_kev_truthy_non_true_does_not_count(self):
        """in_kev must be True (not just truthy); matches Mongo where $eq [1, true] is false."""
        t = compute_stats([_finding(**{DETAILS_KEY_IN_KEV: 1})], {}).threat_intel
        assert t.kev_count == 0
        assert t.active_exploitation_count == 0

    def test_medium_epss_threshold_exactly_0_01_counts(self):
        """EPSS_MEDIUM_THRESHOLD = 0.01 is inclusive on the lower bound."""
        t = compute_stats([_finding(epss_score=0.01)], {}).threat_intel
        assert t.medium_epss_count == 1
        assert t.high_epss_count == 0

    def test_very_high_epss_threshold_exactly_0_5_counts_as_weaponized(self):
        """EPSS_VERY_HIGH_THRESHOLD = 0.5 is inclusive for weaponized (with KEV)."""
        t = compute_stats([_finding(epss_score=0.5, **{DETAILS_KEY_IN_KEV: True})], {}).threat_intel
        assert t.weaponized_count == 1

    def test_active_exploitation_threshold_exactly_0_7_counts(self):
        """EPSS_ACTIVE_EXPLOITATION_THRESHOLD = 0.7 is inclusive."""
        t = compute_stats([_finding(epss_score=0.7)], {}).threat_intel
        assert t.active_exploitation_count == 1
