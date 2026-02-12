"""Tests for optimization recommendations: identify_quick_wins."""

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.optimization import identify_quick_wins


def _vuln(component, severity="HIGH", version="1.0", fixed_version="2.0",
          is_kev=False, finding_id="CVE-2024-001"):
    return {
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": version,
        "details": {
            "fixed_version": fixed_version,
            "is_kev": is_kev,
        },
        "id": finding_id,
    }


def _vuln_no_fix(component, severity="HIGH", version="1.0", finding_id="CVE-2024-001"):
    return {
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": version,
        "details": {
            "is_kev": False,
        },
        "id": finding_id,
    }


def _dep(name, version="1.0", direct=True):
    return {"name": name, "version": version, "direct": direct}


class TestIdentifyQuickWinsEmpty:
    def test_empty_findings_returns_empty(self):
        result = identify_quick_wins([], [])
        assert result == []

    def test_empty_findings_with_deps_returns_empty(self):
        result = identify_quick_wins([], [_dep("pkg")])
        assert result == []


class TestIdentifyQuickWinsSingleVuln:
    def test_package_with_1_vuln_no_quick_win(self):
        vulns = [_vuln("pkg", finding_id="CVE-2024-001")]
        deps = [_dep("pkg")]
        result = identify_quick_wins(vulns, deps)
        assert result == []


class TestIdentifyQuickWinsMultiFixable:
    def test_3_fixable_vulns_gives_single_update_multi_fix(self):
        vulns = [
            _vuln("pkg", severity="HIGH", finding_id="CVE-2024-001"),
            _vuln("pkg", severity="MEDIUM", finding_id="CVE-2024-002"),
            _vuln("pkg", severity="LOW", finding_id="CVE-2024-003"),
        ]
        deps = [_dep("pkg")]
        result = identify_quick_wins(vulns, deps)
        assert len(result) == 1
        rec = result[0]
        assert rec.type == RecommendationType.SINGLE_UPDATE_MULTI_FIX
        assert rec.impact["total"] == 3

    def test_2_fixable_vulns_gives_quick_win(self):
        vulns = [
            _vuln("pkg", severity="HIGH", finding_id="CVE-2024-001"),
            _vuln("pkg", severity="MEDIUM", finding_id="CVE-2024-002"),
        ]
        deps = [_dep("pkg")]
        result = identify_quick_wins(vulns, deps)
        assert len(result) == 1
        rec = result[0]
        assert rec.type == RecommendationType.QUICK_WIN
        assert rec.impact["total"] == 2

    def test_description_mentions_vuln_count(self):
        vulns = [
            _vuln("pkg", severity="HIGH", finding_id="CVE-2024-001"),
            _vuln("pkg", severity="MEDIUM", finding_id="CVE-2024-002"),
        ]
        deps = [_dep("pkg")]
        result = identify_quick_wins(vulns, deps)
        assert "2 vulnerabilities" in result[0].description


class TestIdentifyQuickWinsDirectDepBonus:
    def test_direct_dep_scores_higher(self):
        vulns_direct = [
            _vuln("direct-pkg", severity="MEDIUM", finding_id="CVE-2024-001"),
            _vuln("direct-pkg", severity="MEDIUM", finding_id="CVE-2024-002"),
        ]
        vulns_transitive = [
            _vuln("trans-pkg", severity="MEDIUM", finding_id="CVE-2024-003"),
            _vuln("trans-pkg", severity="MEDIUM", finding_id="CVE-2024-004"),
        ]
        vulns = vulns_direct + vulns_transitive
        deps = [
            _dep("direct-pkg", direct=True),
            _dep("trans-pkg", direct=False),
        ]
        result = identify_quick_wins(vulns, deps)
        assert len(result) == 2
        # Direct dep should appear first due to bonus
        assert result[0].action["package"] == "direct-pkg"
        assert result[0].action["is_direct"] is True

    def test_description_says_direct_dependency(self):
        vulns = [
            _vuln("pkg", finding_id="CVE-2024-001"),
            _vuln("pkg", finding_id="CVE-2024-002"),
        ]
        deps = [_dep("pkg", direct=True)]
        result = identify_quick_wins(vulns, deps)
        assert "direct dependency" in result[0].description

    def test_description_says_transitive_dependency(self):
        vulns = [
            _vuln("pkg", finding_id="CVE-2024-001"),
            _vuln("pkg", finding_id="CVE-2024-002"),
        ]
        deps = [_dep("pkg", direct=False)]
        result = identify_quick_wins(vulns, deps)
        assert "transitive dependency" in result[0].description


class TestIdentifyQuickWinsKEV:
    def test_kev_vuln_gives_high_priority(self):
        vulns = [
            _vuln("pkg", is_kev=True, finding_id="CVE-2024-001"),
            _vuln("pkg", is_kev=False, finding_id="CVE-2024-002"),
        ]
        deps = [_dep("pkg")]
        result = identify_quick_wins(vulns, deps)
        assert len(result) == 1
        assert result[0].priority == Priority.HIGH

    def test_kev_boost_affects_scoring(self):
        vulns_kev = [
            _vuln("kev-pkg", severity="MEDIUM", is_kev=True, finding_id="CVE-2024-001"),
            _vuln("kev-pkg", severity="MEDIUM", finding_id="CVE-2024-002"),
        ]
        vulns_no_kev = [
            _vuln("normal-pkg", severity="MEDIUM", finding_id="CVE-2024-003"),
            _vuln("normal-pkg", severity="MEDIUM", finding_id="CVE-2024-004"),
        ]
        vulns = vulns_kev + vulns_no_kev
        deps = [_dep("kev-pkg"), _dep("normal-pkg")]
        result = identify_quick_wins(vulns, deps)
        assert result[0].action["package"] == "kev-pkg"


class TestIdentifyQuickWinsCriticalVuln:
    def test_critical_vuln_gives_high_priority(self):
        vulns = [
            _vuln("pkg", severity="CRITICAL", finding_id="CVE-2024-001"),
            _vuln("pkg", severity="LOW", finding_id="CVE-2024-002"),
        ]
        deps = [_dep("pkg")]
        result = identify_quick_wins(vulns, deps)
        assert result[0].priority == Priority.HIGH

    def test_medium_only_gives_medium_priority(self):
        vulns = [
            _vuln("pkg", severity="MEDIUM", finding_id="CVE-2024-001"),
            _vuln("pkg", severity="LOW", finding_id="CVE-2024-002"),
        ]
        deps = [_dep("pkg")]
        result = identify_quick_wins(vulns, deps)
        assert result[0].priority == Priority.MEDIUM


class TestIdentifyQuickWinsTop5Limit:
    def test_top_5_limit(self):
        vulns = []
        deps = []
        for i in range(7):
            pkg = f"pkg-{i}"
            vulns.append(_vuln(pkg, finding_id=f"CVE-2024-{i:03d}a"))
            vulns.append(_vuln(pkg, finding_id=f"CVE-2024-{i:03d}b"))
            deps.append(_dep(pkg))
        result = identify_quick_wins(vulns, deps)
        assert len(result) <= 5


class TestIdentifyQuickWinsSortedByScore:
    def test_sorted_by_score_descending(self):
        vulns = [
            # Low score: 2 MEDIUM vulns, transitive
            _vuln("low-pkg", severity="MEDIUM", finding_id="CVE-2024-001"),
            _vuln("low-pkg", severity="MEDIUM", finding_id="CVE-2024-002"),
            # High score: 2 CRITICAL vulns, direct
            _vuln("high-pkg", severity="CRITICAL", finding_id="CVE-2024-003"),
            _vuln("high-pkg", severity="CRITICAL", finding_id="CVE-2024-004"),
        ]
        deps = [
            _dep("low-pkg", direct=False),
            _dep("high-pkg", direct=True),
        ]
        result = identify_quick_wins(vulns, deps)
        assert result[0].action["package"] == "high-pkg"


class TestIdentifyQuickWinsNoFixedVersion:
    def test_vulns_without_fixed_version_excluded(self):
        vulns = [
            _vuln_no_fix("pkg", finding_id="CVE-2024-001"),
            _vuln_no_fix("pkg", finding_id="CVE-2024-002"),
        ]
        deps = [_dep("pkg")]
        result = identify_quick_wins(vulns, deps)
        assert result == []

    def test_mix_of_fixable_and_unfixable(self):
        vulns = [
            _vuln("pkg", finding_id="CVE-2024-001"),  # fixable
            _vuln("pkg", finding_id="CVE-2024-002"),  # fixable
            _vuln_no_fix("pkg", finding_id="CVE-2024-003"),  # not fixable
        ]
        deps = [_dep("pkg")]
        result = identify_quick_wins(vulns, deps)
        # Only fixable vulns are counted
        assert len(result) == 1
        assert result[0].impact["total"] == 2


class TestIdentifyQuickWinsActionDetails:
    def test_action_contains_package_info(self):
        vulns = [
            _vuln("pkg", version="1.0", fixed_version="3.0", finding_id="CVE-2024-001"),
            _vuln("pkg", version="1.0", fixed_version="3.0", finding_id="CVE-2024-002"),
        ]
        deps = [_dep("pkg", direct=True)]
        result = identify_quick_wins(vulns, deps)
        rec = result[0]
        assert rec.action["package"] == "pkg"
        assert rec.action["current_version"] == "1.0"
        assert rec.action["is_direct"] is True
        assert rec.action["fixes_count"] == 2

    def test_effort_is_low(self):
        vulns = [
            _vuln("pkg", finding_id="CVE-2024-001"),
            _vuln("pkg", finding_id="CVE-2024-002"),
        ]
        deps = [_dep("pkg")]
        result = identify_quick_wins(vulns, deps)
        assert result[0].effort == "low"


class TestIdentifyQuickWinsImpactBreakdown:
    def test_impact_has_severity_breakdown(self):
        vulns = [
            _vuln("pkg", severity="CRITICAL", finding_id="CVE-2024-001"),
            _vuln("pkg", severity="HIGH", finding_id="CVE-2024-002"),
            _vuln("pkg", severity="MEDIUM", finding_id="CVE-2024-003"),
        ]
        deps = [_dep("pkg")]
        result = identify_quick_wins(vulns, deps)
        impact = result[0].impact
        assert impact["critical"] == 1
        assert impact["high"] == 1
        assert impact["medium"] == 1
        assert impact["total"] == 3

    def test_kev_count_in_impact(self):
        vulns = [
            _vuln("pkg", is_kev=True, finding_id="CVE-2024-001"),
            _vuln("pkg", is_kev=True, finding_id="CVE-2024-002"),
        ]
        deps = [_dep("pkg")]
        result = identify_quick_wins(vulns, deps)
        assert result[0].impact["kev_count"] == 2


class TestIdentifyQuickWinsBestFixVersion:
    def test_picks_best_fix_version(self):
        vulns = [
            _vuln("pkg", fixed_version="2.0", finding_id="CVE-2024-001"),
            _vuln("pkg", fixed_version="3.0", finding_id="CVE-2024-002"),
        ]
        deps = [_dep("pkg")]
        result = identify_quick_wins(vulns, deps)
        # calculate_best_fix_version picks the highest version
        assert result[0].action["target_version"] == "3.0"


class TestIdentifyQuickWinsAffectedComponents:
    def test_affected_components_format(self):
        vulns = [
            _vuln("my-lib", version="1.2.3", finding_id="CVE-2024-001"),
            _vuln("my-lib", version="1.2.3", finding_id="CVE-2024-002"),
        ]
        deps = [_dep("my-lib", version="1.2.3")]
        result = identify_quick_wins(vulns, deps)
        assert result[0].affected_components == ["my-lib@1.2.3"]
