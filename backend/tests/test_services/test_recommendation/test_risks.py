"""Tests for risk detection: hotspots, toxic dependencies, and attack surface analysis."""

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.risks import (
    analyze_attack_surface,
    detect_critical_hotspots,
    detect_toxic_dependencies,
    get_hotspot_remediation_steps,
)


def _vuln(component, severity="HIGH", version="1.0", is_kev=False,
          epss_score=0.0, fixed_version=None, reachable=None,
          risk_score=None, finding_id="CVE-2024-001"):
    """Build a vulnerability finding dict."""
    details = {
        "is_kev": is_kev,
        "epss_score": epss_score,
    }
    if fixed_version is not None:
        details["fixed_version"] = fixed_version
    if risk_score is not None:
        details["risk_score"] = risk_score
    result = {
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": version,
        "details": details,
        "id": finding_id,
    }
    if reachable is not None:
        result["reachable"] = reachable
    return result


def _malware(component):
    return {"type": "malware", "severity": "CRITICAL", "component": component, "details": {}}


def _eol(component):
    return {"type": "eol", "severity": "HIGH", "component": component, "details": {}}


def _quality(component, scorecard_score=3.0):
    return {
        "type": "quality",
        "severity": "MEDIUM",
        "component": component,
        "details": {"scorecard_score": scorecard_score},
    }


def _license(component, severity="HIGH", license_name="GPL-3.0"):
    return {
        "type": "license",
        "severity": severity,
        "component": component,
        "details": {"license": license_name},
    }


def _dep(name, version="1.0", direct=True):
    return {"name": name, "version": version, "direct": direct}


class TestDetectCriticalHotspotsEmpty:
    def test_empty_findings_returns_empty(self):
        result = detect_critical_hotspots([], [])
        assert result == []


class TestDetectCriticalHotspotsMultiVulnCritical:
    def test_package_with_3_vulns_and_1_critical_is_hotspot(self):
        findings = [
            _vuln("pkg", "CRITICAL", finding_id="CVE-2024-001"),
            _vuln("pkg", "HIGH", finding_id="CVE-2024-002"),
            _vuln("pkg", "MEDIUM", finding_id="CVE-2024-003"),
        ]
        result = detect_critical_hotspots(findings, [])
        assert len(result) == 1
        assert result[0].type == RecommendationType.CRITICAL_HOTSPOT
        assert result[0].priority == Priority.CRITICAL
        assert "pkg" in result[0].title


class TestDetectCriticalHotspotsMalware:
    def test_malware_triggers_hotspot_with_reason(self):
        findings = [_malware("evil-pkg")]
        result = detect_critical_hotspots(findings, [])
        assert len(result) == 1
        rec = result[0]
        assert rec.type == RecommendationType.CRITICAL_HOTSPOT
        assert rec.priority == Priority.CRITICAL
        assert "Malware detected" in rec.description
        assert rec.action["is_malware"] is True


class TestDetectCriticalHotspotsKEV:
    def test_kev_triggers_hotspot_with_reason(self):
        findings = [
            _vuln("pkg", "CRITICAL", is_kev=True, finding_id="CVE-2024-001"),
        ]
        result = detect_critical_hotspots(findings, [])
        assert len(result) == 1
        rec = result[0]
        assert "KEV" in rec.description
        assert rec.action["is_kev"] is True


class TestDetectCriticalHotspotsHighEpssReachable:
    def test_high_epss_plus_reachable_is_hotspot(self):
        findings = [
            _vuln("pkg", "MEDIUM", epss_score=0.5, reachable=True, finding_id="CVE-2024-001"),
        ]
        result = detect_critical_hotspots(findings, [])
        assert len(result) == 1
        rec = result[0]
        assert "high-EPSS" in rec.description


class TestDetectCriticalHotspotsNotHotspot:
    def test_only_2_low_vulns_not_hotspot(self):
        findings = [
            _vuln("pkg", "LOW", finding_id="CVE-2024-001"),
            _vuln("pkg", "LOW", finding_id="CVE-2024-002"),
        ]
        result = detect_critical_hotspots(findings, [])
        assert result == []

    def test_3_low_vulns_without_critical_or_high_not_hotspot(self):
        """3 vulns but none CRITICAL/HIGH => critical_high==0 => NOT a hotspot via that path."""
        findings = [
            _vuln("pkg", "LOW", finding_id="CVE-2024-001"),
            _vuln("pkg", "LOW", finding_id="CVE-2024-002"),
            _vuln("pkg", "LOW", finding_id="CVE-2024-003"),
        ]
        result = detect_critical_hotspots(findings, [])
        # No KEV, no malware, no high-EPSS+reachable, vuln_count>=3 but critical_high==0
        assert result == []


class TestDetectCriticalHotspotsEolReason:
    def test_eol_noted_in_hotspot_reasons(self):
        findings = [
            _vuln("pkg", "CRITICAL", is_kev=True, finding_id="CVE-2024-001"),
            _eol("pkg"),
        ]
        result = detect_critical_hotspots(findings, [])
        assert len(result) == 1
        assert "End-of-Life" in result[0].description


class TestDetectCriticalHotspotsLowScorecard:
    def test_low_scorecard_noted_in_reasons(self):
        findings = [
            _vuln("pkg", "CRITICAL", is_kev=True, finding_id="CVE-2024-001"),
            _quality("pkg", scorecard_score=2.0),
        ]
        result = detect_critical_hotspots(findings, [])
        assert len(result) == 1
        assert "Scorecard" in result[0].description

    def test_high_scorecard_not_noted(self):
        findings = [
            _vuln("pkg", "CRITICAL", is_kev=True, finding_id="CVE-2024-001"),
            _quality("pkg", scorecard_score=8.0),
        ]
        result = detect_critical_hotspots(findings, [])
        assert len(result) == 1
        assert "Scorecard" not in result[0].description


class TestDetectCriticalHotspotsTop10Limit:
    def test_top_10_limit_respected(self):
        findings = []
        for i in range(12):
            pkg = f"pkg-{i}"
            findings.append(_vuln(pkg, "CRITICAL", is_kev=True, finding_id=f"CVE-2024-{i:03d}"))
        result = detect_critical_hotspots(findings, [])
        assert len(result) == 10


class TestDetectCriticalHotspotsSorting:
    def test_sorted_malware_first_then_kev_then_risk_score(self):
        findings = [
            # Package A: high risk_score only (KEV triggers hotspot)
            _vuln("pkg-risk", "CRITICAL", is_kev=True, risk_score=500, finding_id="CVE-2024-001"),
            # Package B: KEV
            _vuln("pkg-kev", "CRITICAL", is_kev=True, finding_id="CVE-2024-002"),
            # Package C: malware
            _malware("pkg-malware"),
        ]
        result = detect_critical_hotspots(findings, [])
        names = [r.action["package"] for r in result]
        assert names[0] == "pkg-malware"
        # pkg-risk and pkg-kev both have kev_count=1 so they sort by risk_score
        assert "pkg-risk" in names
        assert "pkg-kev" in names

    def test_malware_before_kev_before_epss(self):
        findings = [
            _vuln("pkg-epss", "MEDIUM", epss_score=0.5, reachable=True, finding_id="CVE-2024-010"),
            _vuln("pkg-kev", "CRITICAL", is_kev=True, finding_id="CVE-2024-011"),
            _malware("pkg-mal"),
        ]
        result = detect_critical_hotspots(findings, [])
        names = [r.action["package"] for r in result]
        assert names[0] == "pkg-mal"
        assert names[1] == "pkg-kev"
        assert names[2] == "pkg-epss"


class TestDetectCriticalHotspotsRemediation:
    def test_malware_remediation_steps(self):
        findings = [_malware("evil")]
        result = detect_critical_hotspots(findings, [])
        steps = result[0].action["steps"]
        assert any("malware" in s.lower() for s in steps)

    def test_kev_remediation_steps(self):
        findings = [_vuln("pkg", "CRITICAL", is_kev=True)]
        result = detect_critical_hotspots(findings, [])
        steps = result[0].action["steps"]
        assert any("exploited" in s.lower() for s in steps)

    def test_fixable_remediation_steps(self):
        # Need hotspot criteria: 3+ vulns with at least 1 critical
        findings = [
            _vuln("pkg", "CRITICAL", fixed_version="2.0", finding_id="CVE-2024-001"),
            _vuln("pkg", "HIGH", fixed_version="2.0", finding_id="CVE-2024-002"),
            _vuln("pkg", "MEDIUM", finding_id="CVE-2024-003"),
        ]
        result = detect_critical_hotspots(findings, [])
        steps = result[0].action["steps"]
        assert any("Update" in s or "update" in s.lower() for s in steps)

    def test_no_fix_remediation_steps(self):
        # 3 vulns with critical but no fixed_version
        findings = [
            _vuln("pkg", "CRITICAL", finding_id="CVE-2024-001"),
            _vuln("pkg", "HIGH", finding_id="CVE-2024-002"),
            _vuln("pkg", "MEDIUM", finding_id="CVE-2024-003"),
        ]
        result = detect_critical_hotspots(findings, [])
        steps = result[0].action["steps"]
        assert any("alternative" in s.lower() for s in steps)


class TestGetHotspotRemediationSteps:
    def test_malware_steps(self):
        hotspot = {"has_malware": True, "kev_count": 0, "fixed_versions": [], "package": "x"}
        steps = get_hotspot_remediation_steps(hotspot)
        assert any("malware" in s.lower() for s in steps)

    def test_kev_steps(self):
        hotspot = {"has_malware": False, "kev_count": 1, "fixed_versions": [], "package": "x"}
        steps = get_hotspot_remediation_steps(hotspot)
        assert any("exploited" in s.lower() for s in steps)

    def test_fixable_steps(self):
        hotspot = {"has_malware": False, "kev_count": 0, "fixed_versions": ["2.0"], "package": "x"}
        steps = get_hotspot_remediation_steps(hotspot)
        assert any("2.0" in s for s in steps)

    def test_no_fix_steps(self):
        hotspot = {"has_malware": False, "kev_count": 0, "fixed_versions": [], "package": "x"}
        steps = get_hotspot_remediation_steps(hotspot)
        assert any("alternative" in s.lower() for s in steps)


class TestDetectCriticalHotspotsVersionAndFixedVersion:
    def test_version_extracted_from_first_vuln(self):
        findings = [
            _vuln("pkg", "CRITICAL", version="3.1.0", is_kev=True, finding_id="CVE-2024-001"),
        ]
        result = detect_critical_hotspots(findings, [])
        assert "3.1.0" in result[0].affected_components[0]

    def test_fixed_version_shown_in_description(self):
        findings = [
            _vuln("pkg", "CRITICAL", is_kev=True, fixed_version="4.0.0", finding_id="CVE-2024-001"),
        ]
        result = detect_critical_hotspots(findings, [])
        assert "4.0.0" in result[0].description


class TestDetectCriticalHotspotsPriority:
    def test_critical_priority_for_malware(self):
        findings = [_malware("evil")]
        result = detect_critical_hotspots(findings, [])
        assert result[0].priority == Priority.CRITICAL

    def test_critical_priority_for_kev(self):
        findings = [_vuln("pkg", "MEDIUM", is_kev=True)]
        result = detect_critical_hotspots(findings, [])
        assert result[0].priority == Priority.CRITICAL

    def test_critical_priority_for_critical_vuln_in_hotspot(self):
        findings = [
            _vuln("pkg", "CRITICAL", finding_id="CVE-2024-001"),
            _vuln("pkg", "HIGH", finding_id="CVE-2024-002"),
            _vuln("pkg", "HIGH", finding_id="CVE-2024-003"),
        ]
        result = detect_critical_hotspots(findings, [])
        assert result[0].priority == Priority.CRITICAL

    def test_high_priority_when_no_critical_no_kev_no_malware(self):
        # hotspot via high-EPSS + reachable, no critical
        findings = [
            _vuln("pkg", "HIGH", epss_score=0.5, reachable=True, finding_id="CVE-2024-001"),
        ]
        result = detect_critical_hotspots(findings, [])
        assert result[0].priority == Priority.HIGH


class TestDetectCriticalHotspotsEffort:
    def test_effort_low_when_fix_available(self):
        findings = [_vuln("pkg", "CRITICAL", is_kev=True, fixed_version="2.0")]
        result = detect_critical_hotspots(findings, [])
        assert result[0].effort == "low"

    def test_effort_high_when_no_fix(self):
        findings = [_vuln("pkg", "CRITICAL", is_kev=True)]
        result = detect_critical_hotspots(findings, [])
        assert result[0].effort == "high"


class TestDetectCriticalHotspotsSkipsEmptyComponent:
    def test_finding_without_component_skipped(self):
        findings = [
            {"type": "vulnerability", "severity": "CRITICAL", "component": "",
             "details": {"is_kev": True}, "id": "CVE-2024-001"},
        ]
        result = detect_critical_hotspots(findings, [])
        assert result == []


class TestDetectToxicDependenciesEmpty:
    def test_empty_returns_empty(self):
        result = detect_toxic_dependencies([], [])
        assert result == []


class TestDetectToxicDependenciesMultipleFactors:
    def test_vulns_plus_low_scorecard_is_toxic(self):
        findings = [
            _vuln("pkg", "HIGH", finding_id="CVE-2024-001"),
            _quality("pkg", scorecard_score=2.0),
        ]
        result = detect_toxic_dependencies(findings, [])
        assert len(result) == 1
        rec = result[0]
        assert rec.type == RecommendationType.TOXIC_DEPENDENCY
        assert rec.priority == Priority.HIGH
        assert rec.impact["risk_factor_count"] >= 2

    def test_vulns_plus_eol_is_toxic(self):
        findings = [
            _vuln("pkg", "HIGH", finding_id="CVE-2024-001"),
            _eol("pkg"),
        ]
        result = detect_toxic_dependencies(findings, [])
        assert len(result) == 1
        rec = result[0]
        assert rec.type == RecommendationType.TOXIC_DEPENDENCY
        assert rec.impact["risk_factor_count"] >= 2


class TestDetectToxicDependenciesSingleFactor:
    def test_only_vulns_not_toxic(self):
        findings = [
            _vuln("pkg", "HIGH", finding_id="CVE-2024-001"),
        ]
        result = detect_toxic_dependencies(findings, [])
        assert result == []


class TestDetectToxicDependenciesMalwareScore:
    def test_malware_adds_100_to_score(self):
        findings = [
            _vuln("pkg", "LOW", finding_id="CVE-2024-001"),
            _malware("pkg"),
        ]
        result = detect_toxic_dependencies(findings, [])
        assert len(result) == 1
        rec = result[0]
        assert rec.impact["toxic_score"] >= 100


class TestDetectToxicDependenciesTop5Limit:
    def test_top_5_limit(self):
        findings = []
        for i in range(7):
            pkg = f"pkg-{i}"
            findings.append(_vuln(pkg, "HIGH", finding_id=f"CVE-2024-{i:03d}"))
            findings.append(_quality(pkg, scorecard_score=1.0))
        result = detect_toxic_dependencies(findings, [])
        assert len(result) == 5


class TestDetectToxicDependenciesSortedByScore:
    def test_sorted_by_total_score_descending(self):
        findings = [
            # Low-score package: 1 vuln + eol
            _vuln("pkg-low", "LOW", finding_id="CVE-2024-001"),
            _eol("pkg-low"),
            # High-score package: 1 vuln + malware (malware adds 100)
            _vuln("pkg-high", "CRITICAL", finding_id="CVE-2024-002"),
            _malware("pkg-high"),
        ]
        result = detect_toxic_dependencies(findings, [])
        assert len(result) == 2
        assert result[0].action["package"] == "pkg-high"
        assert result[1].action["package"] == "pkg-low"


class TestDetectToxicDependenciesLicenseRiskFactor:
    def test_high_severity_license_is_risk_factor(self):
        findings = [
            _vuln("pkg", "HIGH", finding_id="CVE-2024-001"),
            _license("pkg", severity="HIGH", license_name="GPL-3.0"),
        ]
        result = detect_toxic_dependencies(findings, [])
        assert len(result) == 1
        assert any("License" in d or "license" in d for d in result[0].description.split("|"))

    def test_low_severity_license_not_risk_factor(self):
        findings = [
            _vuln("pkg", "HIGH", finding_id="CVE-2024-001"),
            _license("pkg", severity="LOW"),
        ]
        result = detect_toxic_dependencies(findings, [])
        # Only 1 risk factor (vulns) -> not toxic
        assert result == []


class TestDetectToxicDependenciesVulnRiskSeverityLabel:
    def test_vuln_risk_factor_labels_critical_correctly(self):
        findings = [
            _vuln("pkg", "CRITICAL", finding_id="CVE-2024-001"),
            _quality("pkg", scorecard_score=1.0),
        ]
        result = detect_toxic_dependencies(findings, [])
        vuln_factor = [
            rf for rf in result[0].action["risk_factors"]
            if rf["type"] == "vulnerabilities"
        ]
        assert vuln_factor[0]["severity"] == "CRITICAL"

    def test_vuln_risk_factor_labels_high_correctly(self):
        findings = [
            _vuln("pkg", "HIGH", finding_id="CVE-2024-001"),
            _quality("pkg", scorecard_score=1.0),
        ]
        result = detect_toxic_dependencies(findings, [])
        vuln_factor = [
            rf for rf in result[0].action["risk_factors"]
            if rf["type"] == "vulnerabilities"
        ]
        assert vuln_factor[0]["severity"] == "HIGH"

    def test_vuln_risk_factor_labels_medium_when_no_critical_or_high(self):
        findings = [
            _vuln("pkg", "LOW", finding_id="CVE-2024-001"),
            _quality("pkg", scorecard_score=1.0),
        ]
        result = detect_toxic_dependencies(findings, [])
        vuln_factor = [
            rf for rf in result[0].action["risk_factors"]
            if rf["type"] == "vulnerabilities"
        ]
        assert vuln_factor[0]["severity"] == "MEDIUM"


class TestDetectToxicDependenciesDeduplication:
    def test_duplicate_eol_findings_counted_once(self):
        findings = [
            _vuln("pkg", "HIGH", finding_id="CVE-2024-001"),
            _eol("pkg"),
            _eol("pkg"),  # duplicate
        ]
        result = detect_toxic_dependencies(findings, [])
        assert len(result) == 1
        eol_factors = [rf for rf in result[0].action["risk_factors"] if rf["type"] == "eol"]
        assert len(eol_factors) == 1

    def test_duplicate_scorecard_counted_once(self):
        findings = [
            _vuln("pkg", "HIGH", finding_id="CVE-2024-001"),
            _quality("pkg", scorecard_score=2.0),
            _quality("pkg", scorecard_score=2.0),
        ]
        result = detect_toxic_dependencies(findings, [])
        assert len(result) == 1
        scorecard_factors = [rf for rf in result[0].action["risk_factors"] if rf["type"] == "low_scorecard"]
        assert len(scorecard_factors) == 1


class TestAnalyzeAttackSurfaceEmpty:
    def test_empty_deps_returns_empty(self):
        result = analyze_attack_surface([], [])
        assert result == []


class TestAnalyzeAttackSurfaceTransitiveDeps:
    def test_transitive_dep_with_2_vulns_triggers_recommendation(self):
        deps = [_dep("transitive-pkg", direct=False)]
        findings = [
            _vuln("transitive-pkg", "HIGH", finding_id="CVE-2024-001"),
            _vuln("transitive-pkg", "MEDIUM", finding_id="CVE-2024-002"),
        ]
        result = analyze_attack_surface(deps, findings)
        assert len(result) == 1
        rec = result[0]
        assert rec.type == RecommendationType.ATTACK_SURFACE_REDUCTION
        assert rec.priority == Priority.MEDIUM

    def test_direct_dep_with_vulns_not_included(self):
        deps = [_dep("direct-pkg", direct=True)]
        findings = [
            _vuln("direct-pkg", "HIGH", finding_id="CVE-2024-001"),
            _vuln("direct-pkg", "MEDIUM", finding_id="CVE-2024-002"),
        ]
        result = analyze_attack_surface(deps, findings)
        assert result == []

    def test_transitive_dep_with_only_1_vuln_not_included(self):
        deps = [_dep("transitive-pkg", direct=False)]
        findings = [
            _vuln("transitive-pkg", "HIGH", finding_id="CVE-2024-001"),
        ]
        result = analyze_attack_surface(deps, findings)
        assert result == []


class TestAnalyzeAttackSurfaceLargeDependencyTree:
    def test_large_tree_triggers_recommendation(self):
        # 501 total deps, only 10 direct (< 10% of 501)
        deps = [_dep(f"direct-{i}", direct=True) for i in range(10)]
        deps += [_dep(f"transitive-{i}", direct=False) for i in range(491)]
        result = analyze_attack_surface(deps, [])
        assert len(result) == 1
        rec = result[0]
        assert rec.priority == Priority.LOW
        assert "Large Dependency Tree" in rec.title

    def test_normal_sized_tree_no_recommendation(self):
        # 100 deps, 50 direct -> 50% -> not < 10%
        deps = [_dep(f"direct-{i}", direct=True) for i in range(50)]
        deps += [_dep(f"transitive-{i}", direct=False) for i in range(50)]
        result = analyze_attack_surface(deps, [])
        assert result == []

    def test_500_deps_exactly_no_recommendation(self):
        # Boundary: exactly 500 (not >500)
        deps = [_dep(f"direct-{i}", direct=True) for i in range(5)]
        deps += [_dep(f"transitive-{i}", direct=False) for i in range(495)]
        result = analyze_attack_surface(deps, [])
        assert result == []


class TestAnalyzeAttackSurfaceCombined:
    def test_both_transitive_vulns_and_large_tree(self):
        deps = [_dep("direct-0", direct=True)]
        deps += [_dep(f"transitive-{i}", direct=False) for i in range(510)]
        findings = [
            _vuln("transitive-0", "HIGH", finding_id="CVE-2024-001"),
            _vuln("transitive-0", "MEDIUM", finding_id="CVE-2024-002"),
        ]
        result = analyze_attack_surface(deps, findings)
        # Should get 2 recommendations: transitive vulns + large tree
        assert len(result) == 2
        types = {r.title for r in result}
        assert any("Transitive" in t for t in types)
        assert any("Large" in t for t in types)
