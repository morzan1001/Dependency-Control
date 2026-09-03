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
