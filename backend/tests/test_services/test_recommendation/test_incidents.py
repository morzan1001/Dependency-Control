"""Tests for incident detection: malware, typosquatting, and known exploits."""

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.incidents import (
    detect_known_exploits,
    process_malware,
    process_typosquatting,
)


def _malware_finding(component):
    return {
        "type": "malware",
        "severity": "CRITICAL",
        "component": component,
        "details": {},
    }


def _typosquat_finding(component, similar_to=None):
    details = {}
    if similar_to is not None:
        details["similar_to"] = similar_to
    return {
        "type": "typosquatting",
        "severity": "HIGH",
        "component": component,
        "details": details,
    }


def _vuln(component, severity="CRITICAL", is_kev=False, kev_ransomware=False,
          epss_score=0.0, cve_id="CVE-2024-001"):
    return {
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "details": {
            "is_kev": is_kev,
            "kev_ransomware": kev_ransomware,
            "epss_score": epss_score,
            "cve_id": cve_id,
        },
        "id": cve_id,
        "aliases": [],
    }


class TestProcessMalwareEmpty:
    def test_empty_returns_empty(self):
        result = process_malware([])
        assert result == []


class TestProcessMalwareSingle:
    def test_single_malware_recommendation(self):
        result = process_malware([_malware_finding("evil-pkg")])
        assert len(result) == 1
        rec = result[0]
        assert rec.type == RecommendationType.MALWARE_DETECTED
        assert rec.priority == Priority.CRITICAL
        assert rec.impact["total"] == 1
        assert "evil-pkg" in rec.affected_components

    def test_malware_action_contains_steps(self):
        result = process_malware([_malware_finding("evil-pkg")])
        rec = result[0]
        assert rec.action["type"] == "remove_malware"
        assert rec.action["urgency"] == "immediate"
        assert len(rec.action["steps"]) > 0

    def test_malware_effort_is_low(self):
        result = process_malware([_malware_finding("evil-pkg")])
        assert result[0].effort == "low"


class TestProcessMalwareMultiple:
    def test_multiple_malware_produces_single_recommendation(self):
        findings = [
            _malware_finding("evil-1"),
            _malware_finding("evil-2"),
            _malware_finding("evil-3"),
        ]
        result = process_malware(findings)
        assert len(result) == 1
        rec = result[0]
        assert rec.impact["total"] == 3
        assert rec.impact["critical"] == 3

    def test_multiple_malware_lists_all_affected_packages(self):
        findings = [
            _malware_finding("evil-1"),
            _malware_finding("evil-2"),
        ]
        result = process_malware(findings)
        components = result[0].affected_components
        assert "evil-1" in components
        assert "evil-2" in components

    def test_description_includes_count(self):
        findings = [_malware_finding("evil-1"), _malware_finding("evil-2")]
        result = process_malware(findings)
        assert "2" in result[0].description


class TestProcessMalwareDeduplicate:
    def test_duplicate_component_deduplicated_in_affected(self):
        findings = [
            _malware_finding("evil-pkg"),
            _malware_finding("evil-pkg"),
        ]
        result = process_malware(findings)
        assert result[0].affected_components.count("evil-pkg") == 1


class TestProcessTyposquattingEmpty:
    def test_empty_returns_empty(self):
        result = process_typosquatting([])
        assert result == []


class TestProcessTyposquattingWithSimilarTo:
    def test_similar_to_shown_in_affected(self):
        findings = [_typosquat_finding("loadsh", similar_to="lodash")]
        result = process_typosquatting(findings)
        assert len(result) == 1
        rec = result[0]
        assert any("looks like: lodash" in c for c in rec.affected_components)

    def test_type_and_priority(self):
        findings = [_typosquat_finding("loadsh", similar_to="lodash")]
        result = process_typosquatting(findings)
        rec = result[0]
        assert rec.type == RecommendationType.TYPOSQUAT_DETECTED
        assert rec.priority == Priority.HIGH


class TestProcessTyposquattingWithoutSimilarTo:
    def test_package_name_only(self):
        findings = [_typosquat_finding("suspic-pkg")]
        result = process_typosquatting(findings)
        assert len(result) == 1
        rec = result[0]
        assert "suspic-pkg" in rec.affected_components
        assert not any("looks like" in c for c in rec.affected_components)


class TestProcessTyposquattingMultiple:
    def test_multiple_typosquats_single_recommendation(self):
        findings = [
            _typosquat_finding("loadsh", similar_to="lodash"),
            _typosquat_finding("reect", similar_to="react"),
        ]
        result = process_typosquatting(findings)
        assert len(result) == 1
        rec = result[0]
        assert rec.impact["total"] == 2
        assert rec.impact["high"] == 2
        assert len(rec.affected_components) == 2

    def test_description_includes_count(self):
        findings = [
            _typosquat_finding("loadsh", similar_to="lodash"),
            _typosquat_finding("reect", similar_to="react"),
        ]
        result = process_typosquatting(findings)
        assert "2" in result[0].description


class TestProcessTyposquattingAction:
    def test_action_steps_present(self):
        findings = [_typosquat_finding("loadsh", similar_to="lodash")]
        result = process_typosquatting(findings)
        assert result[0].action["type"] == "verify_packages"
        assert len(result[0].action["steps"]) > 0

    def test_effort_is_low(self):
        findings = [_typosquat_finding("loadsh")]
        result = process_typosquatting(findings)
        assert result[0].effort == "low"


class TestProcessTyposquattingEmptyComponent:
    def test_empty_component_excluded(self):
        findings = [
            {"type": "typosquatting", "severity": "HIGH", "component": "", "details": {}},
        ]
        result = process_typosquatting(findings)
        # The function still creates a recommendation (1 finding) but affected_components
        # will not include empty string (the loop skips empty pkg)
        if result:
            assert "" not in result[0].affected_components


class TestDetectKnownExploitsEmpty:
    def test_empty_returns_empty(self):
        result = detect_known_exploits([])
        assert result == []


class TestDetectKnownExploitsKEV:
    def test_kev_vuln_produces_known_exploit(self):
        findings = [_vuln("pkg", is_kev=True, kev_ransomware=False)]
        result = detect_known_exploits(findings)
        assert len(result) == 1
        rec = result[0]
        assert rec.type == RecommendationType.KNOWN_EXPLOIT
        assert rec.priority == Priority.CRITICAL
        assert "KEV" in rec.title or "CISA" in rec.title

    def test_kev_action_details(self):
        findings = [_vuln("pkg", is_kev=True, cve_id="CVE-2024-100")]
        result = detect_known_exploits(findings)
        rec = result[0]
        assert rec.action["type"] == "fix_kev_vulns"
        assert "CVE-2024-100" in rec.action["cves"]
        assert "pkg" in rec.action["packages"]


class TestDetectKnownExploitsRansomware:
    def test_kev_ransomware_produces_ransomware_risk(self):
        findings = [_vuln("pkg", is_kev=True, kev_ransomware=True)]
        result = detect_known_exploits(findings)
        # Should produce RANSOMWARE_RISK, not KNOWN_EXPLOIT
        ransomware_recs = [r for r in result if r.type == RecommendationType.RANSOMWARE_RISK]
        kev_recs = [r for r in result if r.type == RecommendationType.KNOWN_EXPLOIT]
        assert len(ransomware_recs) == 1
        assert len(kev_recs) == 0
        assert ransomware_recs[0].priority == Priority.CRITICAL
        assert "Ransomware" in ransomware_recs[0].title

    def test_ransomware_urgency_immediate(self):
        findings = [_vuln("pkg", is_kev=True, kev_ransomware=True)]
        result = detect_known_exploits(findings)
        ransomware_rec = [r for r in result if r.type == RecommendationType.RANSOMWARE_RISK][0]
        assert ransomware_rec.action["urgency"] == "immediate"


class TestDetectKnownExploitsHighEPSS:
    def test_high_epss_produces_actively_exploited(self):
        findings = [_vuln("pkg", is_kev=False, epss_score=0.8)]
        result = detect_known_exploits(findings)
        assert len(result) == 1
        rec = result[0]
        assert rec.type == RecommendationType.ACTIVELY_EXPLOITED
        assert rec.priority == Priority.CRITICAL

    def test_epss_exactly_0_5_triggers(self):
        findings = [_vuln("pkg", is_kev=False, epss_score=0.5)]
        result = detect_known_exploits(findings)
        assert len(result) == 1
        assert result[0].type == RecommendationType.ACTIVELY_EXPLOITED

    def test_epss_just_below_threshold_no_result(self):
        findings = [_vuln("pkg", is_kev=False, epss_score=0.49)]
        result = detect_known_exploits(findings)
        assert result == []

    def test_epss_max_displayed_correctly(self):
        findings = [
            _vuln("pkg-a", is_kev=False, epss_score=0.7, cve_id="CVE-2024-001"),
            _vuln("pkg-b", is_kev=False, epss_score=0.9, cve_id="CVE-2024-002"),
        ]
        result = detect_known_exploits(findings)
        assert len(result) == 1
        rec = result[0]
        assert rec.impact["max_epss"] == 0.9
        assert "90.0%" in rec.description


class TestDetectKnownExploitsNoKevLowEpss:
    def test_no_kev_low_epss_returns_empty(self):
        findings = [_vuln("pkg", is_kev=False, epss_score=0.01)]
        result = detect_known_exploits(findings)
        assert result == []

    def test_no_kev_zero_epss_returns_empty(self):
        findings = [_vuln("pkg", is_kev=False, epss_score=0.0)]
        result = detect_known_exploits(findings)
        assert result == []


class TestDetectKnownExploitsMix:
    def test_kev_plus_ransomware_plus_high_epss_gives_3_recommendations(self):
        findings = [
            _vuln("pkg-kev", is_kev=True, kev_ransomware=False, cve_id="CVE-2024-001"),
            _vuln("pkg-ransom", is_kev=True, kev_ransomware=True, cve_id="CVE-2024-002"),
            _vuln("pkg-epss", is_kev=False, epss_score=0.8, cve_id="CVE-2024-003"),
        ]
        result = detect_known_exploits(findings)
        types = {r.type for r in result}
        assert RecommendationType.KNOWN_EXPLOIT in types
        assert RecommendationType.RANSOMWARE_RISK in types
        assert RecommendationType.ACTIVELY_EXPLOITED in types
        assert len(result) == 3

    def test_all_three_have_critical_priority(self):
        findings = [
            _vuln("pkg-kev", is_kev=True, kev_ransomware=False, cve_id="CVE-2024-001"),
            _vuln("pkg-ransom", is_kev=True, kev_ransomware=True, cve_id="CVE-2024-002"),
            _vuln("pkg-epss", is_kev=False, epss_score=0.8, cve_id="CVE-2024-003"),
        ]
        result = detect_known_exploits(findings)
        for rec in result:
            assert rec.priority == Priority.CRITICAL


class TestDetectKnownExploitsMultipleSameType:
    def test_multiple_kev_grouped(self):
        findings = [
            _vuln("pkg-a", is_kev=True, cve_id="CVE-2024-001"),
            _vuln("pkg-b", is_kev=True, cve_id="CVE-2024-002"),
        ]
        result = detect_known_exploits(findings)
        kev_recs = [r for r in result if r.type == RecommendationType.KNOWN_EXPLOIT]
        assert len(kev_recs) == 1
        assert kev_recs[0].impact["total"] == 2

    def test_multiple_ransomware_grouped(self):
        findings = [
            _vuln("pkg-a", is_kev=True, kev_ransomware=True, cve_id="CVE-2024-001"),
            _vuln("pkg-b", is_kev=True, kev_ransomware=True, cve_id="CVE-2024-002"),
        ]
        result = detect_known_exploits(findings)
        ransom_recs = [r for r in result if r.type == RecommendationType.RANSOMWARE_RISK]
        assert len(ransom_recs) == 1
        assert ransom_recs[0].impact["total"] == 2


class TestDetectKnownExploitsImpactSeverityCounts:
    def test_kev_impact_counts_by_severity(self):
        findings = [
            _vuln("a", severity="CRITICAL", is_kev=True, cve_id="CVE-2024-001"),
            _vuln("b", severity="HIGH", is_kev=True, cve_id="CVE-2024-002"),
            _vuln("c", severity="MEDIUM", is_kev=True, cve_id="CVE-2024-003"),
        ]
        result = detect_known_exploits(findings)
        kev_rec = [r for r in result if r.type == RecommendationType.KNOWN_EXPLOIT][0]
        assert kev_rec.impact["critical"] == 1
        assert kev_rec.impact["high"] == 1
        assert kev_rec.impact["medium"] == 1
        assert kev_rec.impact["total"] == 3


class TestDetectKnownExploitsKevIsHighPriority:
    def test_kev_with_is_kev_false_not_included(self):
        findings = [_vuln("pkg", is_kev=False, epss_score=0.0)]
        result = detect_known_exploits(findings)
        assert result == []


class TestDetectKnownExploitsEffort:
    def test_all_recommendations_low_effort(self):
        findings = [
            _vuln("a", is_kev=True, kev_ransomware=True, cve_id="CVE-2024-001"),
            _vuln("b", is_kev=True, cve_id="CVE-2024-002"),
            _vuln("c", is_kev=False, epss_score=0.9, cve_id="CVE-2024-003"),
        ]
        result = detect_known_exploits(findings)
        for rec in result:
            assert rec.effort == "low"
