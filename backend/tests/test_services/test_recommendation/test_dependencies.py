"""Tests for app.services.recommendation.dependencies."""

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.dependencies import (
    analyze_outdated_dependencies,
    analyze_version_fragmentation,
    analyze_dev_in_production,
    analyze_end_of_life,
)


def _dep(name="requests", version="2.28.0", latest_version=None, direct=True, scope=None):
    d = {
        "name": name,
        "version": version,
        "direct": direct,
    }
    if latest_version is not None:
        d["latest_version"] = latest_version
    if scope is not None:
        d["scope"] = scope
    return d


def _eol_finding(
    component="node",
    version="16.0.0",
    severity="HIGH",
    eol_date="2023-09-11",
    finding_id="eol1",
):
    details = {}
    if eol_date is not None:
        details["eol_date"] = eol_date
    return {
        "type": "eol",
        "severity": severity,
        "component": component,
        "version": version,
        "details": details,
        "id": finding_id,
    }


class TestAnalyzeOutdatedDependenciesEmpty:
    """Empty input."""

    def test_empty_returns_empty(self):
        assert analyze_outdated_dependencies([]) == []


class TestAnalyzeOutdatedDependenciesDirectOutdated:
    """Direct dep with latest_version != version."""

    def test_direct_outdated_produces_recommendation(self):
        deps = [_dep(name="requests", version="2.28.0", latest_version="2.31.0", direct=True)]
        result = analyze_outdated_dependencies(deps)
        assert len(result) == 1

    def test_direct_outdated_type(self):
        deps = [_dep(name="requests", version="2.28.0", latest_version="2.31.0", direct=True)]
        rec = analyze_outdated_dependencies(deps)[0]
        assert rec.type == RecommendationType.OUTDATED_DEPENDENCY

    def test_direct_outdated_priority_medium(self):
        deps = [_dep(name="requests", version="2.28.0", latest_version="2.31.0", direct=True)]
        rec = analyze_outdated_dependencies(deps)[0]
        assert rec.priority == Priority.MEDIUM

    def test_direct_outdated_affected_components(self):
        deps = [_dep(name="requests", version="2.28.0", latest_version="2.31.0", direct=True)]
        rec = analyze_outdated_dependencies(deps)[0]
        assert "requests@2.28.0" in rec.affected_components

    def test_multiple_direct_outdated_counted(self):
        deps = [
            _dep(name="requests", version="2.28.0", latest_version="2.31.0", direct=True),
            _dep(name="flask", version="2.0.0", latest_version="3.0.0", direct=True),
        ]
        rec = analyze_outdated_dependencies(deps)[0]
        assert rec.impact["total"] == 2


class TestAnalyzeOutdatedDependenciesTransitive:
    """Transitive outdated deps flagged only if above SIGNIFICANT_FRAGMENTATION_THRESHOLD."""

    def test_few_transitive_not_flagged(self):
        # Only 2 transitive outdated, threshold is 3
        deps = [
            _dep(name="sub-a", version="1.0", latest_version="2.0", direct=False),
            _dep(name="sub-b", version="1.0", latest_version="2.0", direct=False),
        ]
        result = analyze_outdated_dependencies(deps)
        assert len(result) == 0

    def test_many_transitive_produces_low_priority(self):
        # 4 transitive outdated, above threshold of 3
        deps = [
            _dep(name=f"sub-{i}", version="1.0", latest_version="2.0", direct=False)
            for i in range(4)
        ]
        result = analyze_outdated_dependencies(deps)
        assert len(result) == 1
        assert result[0].priority == Priority.LOW


class TestAnalyzeOutdatedDependenciesNotFlagged:
    """Cases that should not produce recommendations."""

    def test_no_latest_version_not_flagged(self):
        deps = [_dep(name="requests", version="2.28.0", latest_version=None)]
        result = analyze_outdated_dependencies(deps)
        assert len(result) == 0

    def test_same_version_not_flagged(self):
        deps = [_dep(name="requests", version="2.31.0", latest_version="2.31.0")]
        result = analyze_outdated_dependencies(deps)
        assert len(result) == 0

    def test_empty_latest_version_not_flagged(self):
        deps = [_dep(name="requests", version="2.28.0", latest_version="")]
        result = analyze_outdated_dependencies(deps)
        assert len(result) == 0


class TestAnalyzeOutdatedDependenciesPythonSkipped:
    """Python lib packages are skipped."""

    def test_python3_prefix_skipped(self):
        deps = [_dep(name="python3-yaml", version="5.0", latest_version="6.0", direct=True)]
        result = analyze_outdated_dependencies(deps)
        assert len(result) == 0

    def test_python_prefix_skipped(self):
        deps = [_dep(name="python-dateutil", version="2.0", latest_version="2.9", direct=True)]
        result = analyze_outdated_dependencies(deps)
        assert len(result) == 0

    def test_python_suffix_skipped(self):
        deps = [_dep(name="lib-python", version="1.0", latest_version="2.0", direct=True)]
        result = analyze_outdated_dependencies(deps)
        assert len(result) == 0

    def test_python_case_insensitive_skipped(self):
        deps = [_dep(name="Python3-Utils", version="1.0", latest_version="2.0", direct=True)]
        result = analyze_outdated_dependencies(deps)
        assert len(result) == 0


class TestAnalyzeVersionFragmentationEmpty:
    """Empty input."""

    def test_empty_returns_empty(self):
        assert analyze_version_fragmentation([]) == []


class TestAnalyzeVersionFragmentationSignificant:
    """Same package with 3+ versions triggers recommendation."""

    def test_three_versions_produces_recommendation(self):
        deps = [
            _dep(name="lodash", version="4.17.15"),
            _dep(name="lodash", version="4.17.20"),
            _dep(name="lodash", version="4.17.21"),
        ]
        result = analyze_version_fragmentation(deps)
        assert len(result) == 1

    def test_three_versions_type(self):
        deps = [
            _dep(name="lodash", version=f"4.17.{15 + i}")
            for i in range(3)
        ]
        rec = analyze_version_fragmentation(deps)[0]
        assert rec.type == RecommendationType.VERSION_FRAGMENTATION

    def test_affected_components_show_version_count(self):
        deps = [
            _dep(name="lodash", version=f"4.17.{15 + i}")
            for i in range(3)
        ]
        rec = analyze_version_fragmentation(deps)[0]
        assert any("lodash" in c and "3 versions" in c for c in rec.affected_components)


class TestAnalyzeVersionFragmentationBelowThreshold:
    """Same package with only 2 versions is not significant."""

    def test_two_versions_no_recommendation(self):
        deps = [
            _dep(name="lodash", version="4.17.15"),
            _dep(name="lodash", version="4.17.20"),
        ]
        result = analyze_version_fragmentation(deps)
        assert len(result) == 0


class TestAnalyzeVersionFragmentationDifferentPackages:
    """Different packages with different versions are not fragmented."""

    def test_different_packages_no_fragmentation(self):
        deps = [
            _dep(name="lodash", version="4.17.15"),
            _dep(name="express", version="4.18.0"),
            _dep(name="react", version="18.2.0"),
        ]
        result = analyze_version_fragmentation(deps)
        assert len(result) == 0


class TestAnalyzeVersionFragmentationCaseInsensitive:
    """Name matching is case-insensitive."""

    def test_case_insensitive_grouping(self):
        deps = [
            _dep(name="Lodash", version="4.17.15"),
            _dep(name="lodash", version="4.17.20"),
            _dep(name="LODASH", version="4.17.21"),
        ]
        result = analyze_version_fragmentation(deps)
        assert len(result) == 1


class TestAnalyzeDevInProductionEmpty:
    """Empty input."""

    def test_empty_returns_empty(self):
        assert analyze_dev_in_production([]) == []


class TestAnalyzeDevInProductionFlagged:
    """Dev packages not in dev scope are flagged."""

    def test_jest_not_in_dev_scope_flagged(self):
        deps = [_dep(name="jest", version="29.0.0")]
        result = analyze_dev_in_production(deps)
        assert len(result) == 1

    def test_jest_flagged_type(self):
        deps = [_dep(name="jest", version="29.0.0")]
        rec = analyze_dev_in_production(deps)[0]
        assert rec.type == RecommendationType.DEV_IN_PRODUCTION

    def test_mocha_flagged(self):
        deps = [_dep(name="mocha", version="10.0.0")]
        result = analyze_dev_in_production(deps)
        assert len(result) == 1

    def test_eslint_flagged(self):
        deps = [_dep(name="eslint", version="8.0.0")]
        result = analyze_dev_in_production(deps)
        assert len(result) == 1

    def test_prettier_flagged(self):
        deps = [_dep(name="prettier", version="3.0.0")]
        result = analyze_dev_in_production(deps)
        assert len(result) == 1

    def test_types_package_flagged(self):
        deps = [_dep(name="@types/node", version="20.0.0")]
        result = analyze_dev_in_production(deps)
        assert len(result) == 1

    def test_cypress_flagged(self):
        deps = [_dep(name="cypress", version="13.0.0")]
        result = analyze_dev_in_production(deps)
        assert len(result) == 1

    def test_multiple_dev_deps_single_recommendation(self):
        deps = [
            _dep(name="jest", version="29.0.0"),
            _dep(name="eslint", version="8.0.0"),
        ]
        result = analyze_dev_in_production(deps)
        assert len(result) == 1
        assert result[0].impact["total"] == 2


class TestAnalyzeDevInProductionNotFlagged:
    """Dev packages in dev scope or non-dev packages."""

    def test_jest_in_dev_scope_not_flagged(self):
        deps = [_dep(name="jest", version="29.0.0", scope="dev")]
        result = analyze_dev_in_production(deps)
        assert len(result) == 0

    def test_jest_in_development_scope_not_flagged(self):
        deps = [_dep(name="jest", version="29.0.0", scope="development")]
        result = analyze_dev_in_production(deps)
        assert len(result) == 0

    def test_jest_in_test_scope_not_flagged(self):
        deps = [_dep(name="jest", version="29.0.0", scope="test")]
        result = analyze_dev_in_production(deps)
        assert len(result) == 0

    def test_non_dev_package_not_flagged(self):
        deps = [_dep(name="express", version="4.18.0")]
        result = analyze_dev_in_production(deps)
        assert len(result) == 0

    def test_unrelated_package_not_flagged(self):
        deps = [_dep(name="requests", version="2.31.0")]
        result = analyze_dev_in_production(deps)
        assert len(result) == 0


class TestAnalyzeEndOfLifeEmpty:
    """Empty input."""

    def test_empty_returns_empty(self):
        assert analyze_end_of_life([]) == []


class TestAnalyzeEndOfLifeCriticalSeverity:
    """EOL findings with CRITICAL severity get HIGH priority."""

    def test_critical_eol_produces_recommendation(self):
        findings = [_eol_finding(severity="CRITICAL")]
        result = analyze_end_of_life(findings)
        assert len(result) == 1

    def test_critical_eol_priority_high(self):
        findings = [_eol_finding(severity="CRITICAL")]
        rec = analyze_end_of_life(findings)[0]
        assert rec.priority == Priority.HIGH

    def test_critical_eol_type(self):
        findings = [_eol_finding(severity="CRITICAL")]
        rec = analyze_end_of_life(findings)[0]
        assert rec.type == RecommendationType.EOL_DEPENDENCY

    def test_critical_eol_impact_count(self):
        findings = [_eol_finding(severity="CRITICAL")]
        rec = analyze_end_of_life(findings)[0]
        assert rec.impact["critical"] == 1


class TestAnalyzeEndOfLifeNonCritical:
    """EOL findings without CRITICAL get MEDIUM priority."""

    def test_high_severity_priority_medium(self):
        findings = [_eol_finding(severity="HIGH")]
        rec = analyze_end_of_life(findings)[0]
        assert rec.priority == Priority.MEDIUM

    def test_medium_severity_priority_medium(self):
        findings = [_eol_finding(severity="MEDIUM")]
        rec = analyze_end_of_life(findings)[0]
        assert rec.priority == Priority.MEDIUM


class TestAnalyzeEndOfLifeAffectedComponents:
    """Affected components formatting."""

    def test_eol_date_included_in_components(self):
        findings = [_eol_finding(component="node", version="16.0.0", eol_date="2023-09-11")]
        rec = analyze_end_of_life(findings)[0]
        assert "node@16.0.0 (EOL: 2023-09-11)" in rec.affected_components

    def test_eol_without_date_just_name_version(self):
        findings = [_eol_finding(component="node", version="16.0.0", eol_date=None)]
        rec = analyze_end_of_life(findings)[0]
        assert "node@16.0.0" in rec.affected_components
        assert "(EOL:" not in rec.affected_components[0]

    def test_eol_empty_date_just_name_version(self):
        findings = [_eol_finding(component="node", version="16.0.0", eol_date="")]
        rec = analyze_end_of_life(findings)[0]
        assert "node@16.0.0" in rec.affected_components
        assert "(EOL:" not in rec.affected_components[0]


class TestAnalyzeEndOfLifeMultiple:
    """Multiple EOL findings."""

    def test_multiple_eol_counted(self):
        findings = [
            _eol_finding(component="node", version="14.0.0", finding_id="eol1"),
            _eol_finding(component="python", version="3.7.0", finding_id="eol2"),
        ]
        rec = analyze_end_of_life(findings)[0]
        assert rec.impact["total"] == 2

    def test_mixed_severities_highest_wins(self):
        findings = [
            _eol_finding(severity="CRITICAL", finding_id="eol1"),
            _eol_finding(severity="HIGH", finding_id="eol2"),
        ]
        rec = analyze_end_of_life(findings)[0]
        assert rec.priority == Priority.HIGH
