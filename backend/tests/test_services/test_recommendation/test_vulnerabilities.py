"""Tests for app.services.recommendation.vulnerabilities."""

import pytest

from app.services.recommendation.vulnerabilities import process_vulnerabilities
from app.schemas.recommendation import RecommendationType, Priority


def _make_finding(
    finding_id="CVE-2024-0001",
    severity="CRITICAL",
    component="pkg-name",
    version="1.0.0",
    fixed_version="1.1.0",
    purl=None,
    is_kev=False,
    epss_score=None,
    reachable=None,
    reachability_level=None,
    aliases=None,
    finding_type="vulnerability",
    kev_ransomware=False,
):
    return {
        "id": finding_id,
        "type": finding_type,
        "severity": severity,
        "component": component,
        "version": version,
        "details": {
            "fixed_version": fixed_version,
            "purl": purl or f"pkg:pypi/{component}@{version}",
            "in_kev": is_kev,
            "epss_score": epss_score,
            "kev_ransomware_use": kev_ransomware,
        },
        "reachable": reachable,
        "reachability_level": reachability_level,
        "aliases": aliases or [],
    }


def _make_dependency(
    name="pkg-name",
    version="1.0.0",
    purl=None,
    direct=True,
    source_type="application",
    dep_type="pypi",
):
    return {
        "name": name,
        "version": version,
        "purl": purl or f"pkg:pypi/{name}@{version}",
        "direct": direct,
        "source_type": source_type,
        "type": dep_type,
    }


def _build_lookup_maps(dependencies):
    dep_by_purl = {}
    dep_by_name_version = {}
    for d in dependencies:
        purl = d.get("purl")
        if purl:
            dep_by_purl[purl] = d
        name = d.get("name", "")
        ver = d.get("version", "")
        dep_by_name_version[f"{name}@{ver}"] = d
    return dep_by_purl, dep_by_name_version


class TestEmptyFindings:
    def test_empty_findings_returns_empty_list(self):
        result = process_vulnerabilities([], {}, {}, [], None)
        assert result == []

    def test_no_vulnerability_type_findings_ignored(self):
        finding = _make_finding(finding_type="secret")
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])
        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)
        assert result == []


class TestDirectDependencyUpdate:
    @pytest.mark.parametrize(
        "severity,expected_priority",
        [
            ("CRITICAL", Priority.CRITICAL),
            ("HIGH", Priority.HIGH),
            ("MEDIUM", Priority.MEDIUM),
            ("LOW", Priority.LOW),
        ],
    )
    def test_severity_maps_to_priority(self, severity, expected_priority):
        finding = _make_finding(severity=severity)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        assert len(result) >= 1
        rec = result[0]
        assert rec.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE
        assert rec.priority == expected_priority

    def test_affected_components_contains_package(self):
        finding = _make_finding(component="requests")
        dep = _make_dependency(name="requests")
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        assert "requests" in result[0].affected_components

    def test_action_contains_target_version(self):
        finding = _make_finding(fixed_version="2.0.0")
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        assert result[0].action["target_version"] == "2.0.0"

    def test_action_contains_current_version(self):
        finding = _make_finding(version="1.0.0")
        dep = _make_dependency(version="1.0.0")
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        assert result[0].action["current_version"] == "1.0.0"

    def test_finding_without_known_dep_still_treated_as_application(self):
        finding = _make_finding(component="unknown-pkg", purl="pkg:pypi/unknown-pkg@1.0.0")
        result = process_vulnerabilities([finding], {}, {}, [], None)

        assert len(result) >= 1
        assert result[0].type == RecommendationType.DIRECT_DEPENDENCY_UPDATE


class TestGroupedVulnerabilities:
    def test_two_vulns_same_component_grouped(self):
        findings = [
            _make_finding(finding_id="CVE-2024-0001", component="requests", version="1.0.0", fixed_version="1.1.0"),
            _make_finding(
                finding_id="CVE-2024-0002",
                component="requests",
                version="1.0.0",
                severity="HIGH",
                fixed_version="1.2.0",
            ),
        ]
        dep = _make_dependency(name="requests", version="1.0.0")
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities(findings, dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert len(direct_recs) == 1
        assert direct_recs[0].impact["total"] == 2

    def test_grouped_picks_best_fix_version(self):
        findings = [
            _make_finding(finding_id="CVE-2024-0001", component="flask", version="1.0.0", fixed_version="1.1.0"),
            _make_finding(finding_id="CVE-2024-0002", component="flask", version="1.0.0", fixed_version="1.2.0"),
        ]
        dep = _make_dependency(name="flask", version="1.0.0", purl="pkg:pypi/flask@1.0.0")
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities(findings, dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].action["target_version"] == "1.2.0"

    def test_different_components_not_grouped(self):
        findings = [
            _make_finding(finding_id="CVE-2024-0001", component="pkg-a", version="1.0.0", purl="pkg:pypi/pkg-a@1.0.0"),
            _make_finding(finding_id="CVE-2024-0002", component="pkg-b", version="2.0.0", purl="pkg:pypi/pkg-b@2.0.0"),
        ]
        deps = [
            _make_dependency(name="pkg-a", version="1.0.0", purl="pkg:pypi/pkg-a@1.0.0"),
            _make_dependency(name="pkg-b", version="2.0.0", purl="pkg:pypi/pkg-b@2.0.0"),
        ]
        dep_by_purl, dep_by_nv = _build_lookup_maps(deps)

        result = process_vulnerabilities(findings, dep_by_purl, dep_by_nv, deps, None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert len(direct_recs) == 2

    def test_grouped_severity_counts(self):
        findings = [
            _make_finding(finding_id="CVE-2024-0001", component="pkg", severity="CRITICAL", fixed_version="2.0.0"),
            _make_finding(finding_id="CVE-2024-0002", component="pkg", severity="HIGH", fixed_version="2.0.0"),
            _make_finding(finding_id="CVE-2024-0003", component="pkg", severity="MEDIUM", fixed_version="2.0.0"),
        ]
        dep = _make_dependency(name="pkg")
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities(findings, dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        impact = direct_recs[0].impact
        assert impact["critical"] == 1
        assert impact["high"] == 1
        assert impact["medium"] == 1


class TestBaseImageUpdate:
    def test_deb_packages_trigger_base_image_update(self):
        """3+ OS vulns should trigger a base image update recommendation."""
        findings = [
            _make_finding(
                finding_id=f"CVE-2024-000{i}",
                component=f"libfoo{i}",
                severity="HIGH",
                purl=f"pkg:deb/debian/libfoo{i}@1.0.0",
            )
            for i in range(4)
        ]
        deps = [
            _make_dependency(
                name=f"libfoo{i}",
                purl=f"pkg:deb/debian/libfoo{i}@1.0.0",
                direct=False,
                source_type="image",
                dep_type="deb",
            )
            for i in range(4)
        ]
        dep_by_purl, dep_by_nv = _build_lookup_maps(deps)

        result = process_vulnerabilities(findings, dep_by_purl, dep_by_nv, deps, "ubuntu:22.04")

        base_recs = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert len(base_recs) == 1
        assert base_recs[0].priority == Priority.HIGH

    def test_single_critical_os_vuln_triggers_base_image(self):
        finding = _make_finding(
            severity="CRITICAL",
            component="libssl",
            purl="pkg:deb/debian/libssl@1.0.0",
        )
        dep = _make_dependency(
            name="libssl",
            purl="pkg:deb/debian/libssl@1.0.0",
            direct=False,
            source_type="image",
            dep_type="deb",
        )
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], "debian:11")

        base_recs = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert len(base_recs) == 1
        assert base_recs[0].priority == Priority.CRITICAL

    def test_few_low_severity_os_vulns_no_recommendation(self):
        """Fewer than 3 low-severity OS vulns should NOT trigger base image update."""
        findings = [
            _make_finding(
                finding_id="CVE-2024-0001", component="libfoo", severity="LOW", purl="pkg:deb/debian/libfoo@1.0.0"
            ),
            _make_finding(
                finding_id="CVE-2024-0002", component="libbar", severity="LOW", purl="pkg:deb/debian/libbar@1.0.0"
            ),
        ]
        deps = [
            _make_dependency(
                name="libfoo", purl="pkg:deb/debian/libfoo@1.0.0", direct=False, source_type="image", dep_type="deb"
            ),
            _make_dependency(
                name="libbar", purl="pkg:deb/debian/libbar@1.0.0", direct=False, source_type="image", dep_type="deb"
            ),
        ]
        dep_by_purl, dep_by_nv = _build_lookup_maps(deps)

        result = process_vulnerabilities(findings, dep_by_purl, dep_by_nv, deps, "alpine:3.18")

        base_recs = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert len(base_recs) == 0

    def test_rpm_type_recognized_as_os(self):
        findings = [
            _make_finding(
                finding_id=f"CVE-2024-000{i}",
                component=f"rpm-pkg{i}",
                severity="MEDIUM",
                purl=f"pkg:rpm/centos/rpm-pkg{i}@1.0.0",
            )
            for i in range(4)
        ]
        deps = [
            _make_dependency(
                name=f"rpm-pkg{i}",
                purl=f"pkg:rpm/centos/rpm-pkg{i}@1.0.0",
                direct=False,
                source_type="image",
                dep_type="rpm",
            )
            for i in range(4)
        ]
        dep_by_purl, dep_by_nv = _build_lookup_maps(deps)

        result = process_vulnerabilities(findings, dep_by_purl, dep_by_nv, deps, "centos:8")

        base_recs = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert len(base_recs) == 1

    def test_base_image_recommendation_includes_image_name(self):
        findings = [
            _make_finding(
                finding_id=f"CVE-2024-000{i}",
                component=f"libfoo{i}",
                severity="HIGH",
                purl=f"pkg:deb/debian/libfoo{i}@1.0.0",
            )
            for i in range(4)
        ]
        deps = [
            _make_dependency(
                name=f"libfoo{i}",
                purl=f"pkg:deb/debian/libfoo{i}@1.0.0",
                direct=False,
                source_type="image",
                dep_type="deb",
            )
            for i in range(4)
        ]
        dep_by_purl, dep_by_nv = _build_lookup_maps(deps)

        result = process_vulnerabilities(findings, dep_by_purl, dep_by_nv, deps, "python:3.11-slim")

        base_recs = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert base_recs[0].action["current_image"] == "python:3.11-slim"

    def test_effort_low_for_many_vulns(self):
        """When more than 10 OS vulns, effort should be 'low' (batch fix via image update)."""
        findings = [
            _make_finding(
                finding_id=f"CVE-2024-{i:04d}",
                component=f"lib{i}",
                severity="MEDIUM",
                purl=f"pkg:deb/debian/lib{i}@1.0.0",
            )
            for i in range(15)
        ]
        deps = [
            _make_dependency(
                name=f"lib{i}", purl=f"pkg:deb/debian/lib{i}@1.0.0", direct=False, source_type="image", dep_type="deb"
            )
            for i in range(15)
        ]
        dep_by_purl, dep_by_nv = _build_lookup_maps(deps)

        result = process_vulnerabilities(findings, dep_by_purl, dep_by_nv, deps, "debian:11")

        base_recs = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert base_recs[0].effort == "low"


class TestTransitiveDependency:
    def test_transitive_vuln_with_fix(self):
        finding = _make_finding(
            component="transitive-pkg",
            version="0.5.0",
            fixed_version="0.6.0",
            purl="pkg:pypi/transitive-pkg@0.5.0",
        )
        dep = _make_dependency(
            name="transitive-pkg",
            version="0.5.0",
            purl="pkg:pypi/transitive-pkg@0.5.0",
            direct=False,
            source_type="application",
        )
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        trans_recs = [r for r in result if r.type == RecommendationType.TRANSITIVE_FIX_VIA_PARENT]
        assert len(trans_recs) == 1

    def test_transitive_high_effort(self):
        finding = _make_finding(
            component="deep-dep",
            version="1.0.0",
            fixed_version="1.1.0",
            purl="pkg:pypi/deep-dep@1.0.0",
        )
        dep = _make_dependency(
            name="deep-dep",
            version="1.0.0",
            purl="pkg:pypi/deep-dep@1.0.0",
            direct=False,
            source_type="application",
        )
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        trans_recs = [r for r in result if r.type == RecommendationType.TRANSITIVE_FIX_VIA_PARENT]
        assert trans_recs[0].effort == "high"

    def test_transitive_critical_priority(self):
        finding = _make_finding(
            severity="CRITICAL",
            component="transitive-pkg",
            version="0.5.0",
            fixed_version="0.6.0",
            purl="pkg:pypi/transitive-pkg@0.5.0",
        )
        dep = _make_dependency(
            name="transitive-pkg",
            version="0.5.0",
            purl="pkg:pypi/transitive-pkg@0.5.0",
            direct=False,
            source_type="application",
        )
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        trans_recs = [r for r in result if r.type == RecommendationType.TRANSITIVE_FIX_VIA_PARENT]
        assert trans_recs[0].priority == Priority.CRITICAL

    def test_transitive_multiple_vulns_grouped(self):
        findings = [
            _make_finding(
                finding_id="CVE-2024-0001",
                component="t-pkg",
                version="0.5.0",
                fixed_version="0.6.0",
                purl="pkg:pypi/t-pkg@0.5.0",
            ),
            _make_finding(
                finding_id="CVE-2024-0002",
                component="t-pkg",
                version="0.5.0",
                severity="HIGH",
                fixed_version="0.7.0",
                purl="pkg:pypi/t-pkg@0.5.0",
            ),
        ]
        dep = _make_dependency(
            name="t-pkg",
            version="0.5.0",
            purl="pkg:pypi/t-pkg@0.5.0",
            direct=False,
            source_type="application",
        )
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities(findings, dep_by_purl, dep_by_nv, [dep], None)

        trans_recs = [r for r in result if r.type == RecommendationType.TRANSITIVE_FIX_VIA_PARENT]
        assert len(trans_recs) == 1
        assert trans_recs[0].impact["total"] == 2


class TestNoFixAvailable:
    @pytest.mark.parametrize(
        "severity,expected_count,expected_priority",
        [
            ("CRITICAL", 1, Priority.HIGH),
            ("HIGH", 1, None),
            ("MEDIUM", 0, None),
            ("LOW", 0, None),
        ],
    )
    def test_no_fix_by_severity(self, severity, expected_count, expected_priority):
        finding = _make_finding(severity=severity, fixed_version=None)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        no_fix_recs = [r for r in result if r.type == RecommendationType.NO_FIX_AVAILABLE]
        assert len(no_fix_recs) == expected_count
        if expected_priority is not None:
            assert no_fix_recs[0].priority == expected_priority

    def test_no_fix_high_effort(self):
        finding = _make_finding(severity="CRITICAL", fixed_version=None)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        no_fix_recs = [r for r in result if r.type == RecommendationType.NO_FIX_AVAILABLE]
        assert no_fix_recs[0].effort == "high"

    def test_no_fix_affected_components(self):
        finding = _make_finding(severity="CRITICAL", fixed_version=None, component="vulnerable-lib")
        dep = _make_dependency(name="vulnerable-lib")
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        no_fix_recs = [r for r in result if r.type == RecommendationType.NO_FIX_AVAILABLE]
        assert "vulnerable-lib" in no_fix_recs[0].affected_components


class TestKevVulnerabilities:
    def test_kev_vuln_is_critical_priority(self):
        finding = _make_finding(severity="MEDIUM", is_kev=True)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert len(direct_recs) >= 1
        assert direct_recs[0].priority == Priority.CRITICAL

    def test_kev_count_in_impact(self):
        finding = _make_finding(is_kev=True)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["kev_count"] >= 1

    def test_kev_cves_in_action(self):
        finding = _make_finding(finding_id="CVE-2024-9999", is_kev=True)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert "CVE-2024-9999" in direct_recs[0].action.get("kev_cves", [])

    def test_kev_ransomware_count_in_impact(self):
        finding = _make_finding(is_kev=True, kev_ransomware=True)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["kev_ransomware_count"] >= 1

    def test_kev_transitive_also_critical(self):
        finding = _make_finding(
            severity="HIGH",
            is_kev=True,
            component="trans-kev",
            purl="pkg:pypi/trans-kev@1.0.0",
        )
        dep = _make_dependency(
            name="trans-kev",
            purl="pkg:pypi/trans-kev@1.0.0",
            direct=False,
            source_type="application",
        )
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        trans_recs = [r for r in result if r.type == RecommendationType.TRANSITIVE_FIX_VIA_PARENT]
        assert trans_recs[0].priority == Priority.CRITICAL


class TestUnreachableDowngrade:
    def test_all_critical_unreachable_downgraded_to_high(self):
        finding = _make_finding(severity="CRITICAL", reachable=False)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].priority == Priority.HIGH

    def test_mixed_reachable_unreachable_stays_critical(self):
        findings = [
            _make_finding(finding_id="CVE-2024-0001", severity="CRITICAL", reachable=True),
            _make_finding(finding_id="CVE-2024-0002", severity="CRITICAL", reachable=False),
        ]
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities(findings, dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].priority == Priority.CRITICAL

    def test_unknown_reachability_stays_critical(self):
        finding = _make_finding(severity="CRITICAL", reachable=None)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].priority == Priority.CRITICAL

    def test_unreachable_transitive_also_downgraded(self):
        finding = _make_finding(
            severity="CRITICAL",
            reachable=False,
            component="trans",
            purl="pkg:pypi/trans@1.0.0",
        )
        dep = _make_dependency(
            name="trans",
            purl="pkg:pypi/trans@1.0.0",
            direct=False,
            source_type="application",
        )
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        trans_recs = [r for r in result if r.type == RecommendationType.TRANSITIVE_FIX_VIA_PARENT]
        assert trans_recs[0].priority == Priority.HIGH


class TestEpssHandling:
    def test_high_epss_boosts_to_high_priority(self):
        finding = _make_finding(severity="MEDIUM", epss_score=0.15)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].priority == Priority.HIGH

    def test_high_epss_count_in_impact(self):
        finding = _make_finding(epss_score=0.2)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["high_epss_count"] >= 1

    def test_medium_epss_counted(self):
        finding = _make_finding(severity="LOW", epss_score=0.05)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["medium_epss_count"] >= 1

    def test_high_epss_cves_in_action(self):
        finding = _make_finding(finding_id="CVE-2024-5555", epss_score=0.5)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert "CVE-2024-5555" in direct_recs[0].action.get("high_epss_cves", [])


class TestReachabilityImpactData:
    def test_reachable_count_in_impact(self):
        finding = _make_finding(reachable=True)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["reachable_count"] >= 1

    def test_unreachable_count_in_impact(self):
        finding = _make_finding(reachable=False)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["unreachable_count"] >= 1

    def test_reachable_critical_count(self):
        finding = _make_finding(severity="CRITICAL", reachable=True)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["reachable_critical"] >= 1

    def test_reachable_high_count(self):
        finding = _make_finding(severity="HIGH", reachable=True)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["reachable_high"] >= 1

    def test_reachable_critical_forces_critical_priority(self):
        finding_crit = _make_finding(severity="CRITICAL", reachable=True)
        dep = _make_dependency()
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding_crit], dep_by_purl, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].priority == Priority.CRITICAL


class TestLookupFallback:
    def test_fallback_to_name_version(self):
        finding = _make_finding(
            component="my-lib",
            version="2.0.0",
            purl="pkg:pypi/wrong-purl@1.0.0",
        )
        dep = _make_dependency(
            name="my-lib",
            version="2.0.0",
            purl="pkg:pypi/my-lib@2.0.0",
        )
        # The finding's purl won't match the dep's purl, but name@version will
        dep_by_purl, dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_purl, dep_by_nv, [dep], None)

        assert len(result) >= 1
