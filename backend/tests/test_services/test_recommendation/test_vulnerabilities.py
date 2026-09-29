"""Tests for app.services.recommendation.vulnerabilities."""

import json
from pathlib import Path

import pytest

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.vulnerabilities import process_vulnerabilities
from app.services.sbom_parser import parse_sbom
from tests.helpers.findings import stored_vulnerability


def _make_finding(
    finding_id="CVE-2024-0001",
    severity="CRITICAL",
    component="pkg-name",
    version="1.0.0",
    fixed_version="1.1.0",
    is_kev=False,
    epss_score=None,
    reachable=None,
    reachability_level=None,
    aliases=None,
    finding_type="vulnerability",
    kev_ransomware=False,
):
    """Aggregator shape: the document id is component:version and every advisory lives in
    details.vulnerabilities, so ``finding_id`` names the advisory, not the document."""
    return {
        "id": f"{component}:{version}",
        "type": finding_type,
        "severity": severity,
        "component": component,
        "version": version,
        "details": {
            "fixed_version": fixed_version,
            "vulnerabilities": [
                {
                    "id": finding_id,
                    "severity": severity,
                    "fixed_version": fixed_version,
                    "aliases": aliases or [],
                    "in_kev": is_kev,
                    "epss_score": epss_score,
                    "kev_ransomware_use": kev_ransomware,
                }
            ],
        },
        "reachable": reachable,
        "reachability_level": reachability_level,
        "aliases": [],
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
    return {f"{d.get('name', '')}@{d.get('version', '')}": d for d in dependencies}


class TestEmptyFindings:
    def test_empty_findings_returns_empty_list(self):
        result = process_vulnerabilities([], {}, [], None)
        assert result == []

    def test_no_vulnerability_type_findings_ignored(self):
        finding = _make_finding(finding_type="secret")
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])
        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)
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
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        assert len(result) >= 1
        rec = result[0]
        assert rec.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE
        assert rec.priority == expected_priority

    def test_affected_components_names_the_installed_copy(self):
        finding = _make_finding(component="requests")
        dep = _make_dependency(name="requests")
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        assert result[0].affected_components == ["requests@1.0.0"]

    def test_action_contains_target_version(self):
        finding = _make_finding(fixed_version="2.0.0")
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        assert result[0].action["target_version"] == "2.0.0"

    def test_action_contains_current_version(self):
        finding = _make_finding(version="1.0.0")
        dep = _make_dependency(version="1.0.0")
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        assert result[0].action["current_version"] == "1.0.0"

    def test_finding_without_known_dep_still_treated_as_application(self):
        finding = _make_finding(component="unknown-pkg")
        result = process_vulnerabilities([finding], {}, [], None)

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
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities(findings, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert len(direct_recs) == 1
        assert direct_recs[0].impact["total"] == 2

    def test_grouped_picks_best_fix_version(self):
        findings = [
            _make_finding(finding_id="CVE-2024-0001", component="flask", version="1.0.0", fixed_version="1.1.0"),
            _make_finding(finding_id="CVE-2024-0002", component="flask", version="1.0.0", fixed_version="1.2.0"),
        ]
        dep = _make_dependency(name="flask", version="1.0.0", purl="pkg:pypi/flask@1.0.0")
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities(findings, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].action["target_version"] == "1.2.0"

    def test_different_components_not_grouped(self):
        findings = [
            _make_finding(finding_id="CVE-2024-0001", component="pkg-a", version="1.0.0"),
            _make_finding(finding_id="CVE-2024-0002", component="pkg-b", version="2.0.0"),
        ]
        deps = [
            _make_dependency(name="pkg-a", version="1.0.0", purl="pkg:pypi/pkg-a@1.0.0"),
            _make_dependency(name="pkg-b", version="2.0.0", purl="pkg:pypi/pkg-b@2.0.0"),
        ]
        dep_by_nv = _build_lookup_maps(deps)

        result = process_vulnerabilities(findings, dep_by_nv, deps, None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert len(direct_recs) == 2

    def test_grouped_severity_counts(self):
        findings = [
            _make_finding(finding_id="CVE-2024-0001", component="pkg", severity="CRITICAL", fixed_version="2.0.0"),
            _make_finding(finding_id="CVE-2024-0002", component="pkg", severity="HIGH", fixed_version="2.0.0"),
            _make_finding(finding_id="CVE-2024-0003", component="pkg", severity="MEDIUM", fixed_version="2.0.0"),
        ]
        dep = _make_dependency(name="pkg")
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities(findings, dep_by_nv, [dep], None)

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
        dep_by_nv = _build_lookup_maps(deps)

        result = process_vulnerabilities(findings, dep_by_nv, deps, "ubuntu:22.04")

        base_recs = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert len(base_recs) == 1
        assert base_recs[0].priority == Priority.HIGH

    def test_single_critical_os_vuln_triggers_base_image(self):
        finding = _make_finding(
            severity="CRITICAL",
            component="libssl",
        )
        dep = _make_dependency(
            name="libssl",
            purl="pkg:deb/debian/libssl@1.0.0",
            direct=False,
            source_type="image",
            dep_type="deb",
        )
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], "debian:11")

        base_recs = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert len(base_recs) == 1
        assert base_recs[0].priority == Priority.CRITICAL

    def test_os_packages_of_a_directory_scan_get_no_base_image_card(self):
        finding = _make_finding(severity="CRITICAL", component="libssl")
        dep = _make_dependency(
            name="libssl", purl="pkg:deb/debian/libssl@1.0.0", direct=True, source_type="directory", dep_type="deb"
        )

        result = process_vulnerabilities([finding], _build_lookup_maps([dep]), [dep], "/srv/rootfs")

        assert [r.type for r in result] == [RecommendationType.DIRECT_DEPENDENCY_UPDATE]

    def test_os_packages_of_an_sbom_naming_no_source_count_as_image(self):
        finding = _make_finding(severity="CRITICAL", component="libssl")
        dep = _make_dependency(
            name="libssl", purl="pkg:deb/debian/libssl@1.0.0", direct=False, source_type=None, dep_type="deb"
        )

        result = process_vulnerabilities([finding], _build_lookup_maps([dep]), [dep], "debian:11")

        assert [r.type for r in result] == [RecommendationType.BASE_IMAGE_UPDATE]

    def test_os_packages_of_an_application_rooted_sbom_count_as_image(self):
        # trivy rootfs names the scanned tree an application, so its apk rows inherit that label.
        sbom = json.loads((Path(__file__).parents[2] / "fixtures" / "sbom" / "rootfs.trivy.cdx.json").read_text())
        dep = next(d.to_dict() for d in parse_sbom(sbom).dependencies if d.name == "libssl3")
        finding = _make_finding(severity="CRITICAL", component="libssl3", version=dep["version"])

        result = process_vulnerabilities([finding], _build_lookup_maps([dep]), [dep], None)

        assert dep["source_type"] == "application"
        assert [r.type for r in result] == [RecommendationType.BASE_IMAGE_UPDATE]

    def test_few_low_severity_os_vulns_no_recommendation(self):
        """Fewer than 3 low-severity OS vulns should NOT trigger base image update."""
        findings = [
            _make_finding(finding_id="CVE-2024-0001", component="libfoo", severity="LOW"),
            _make_finding(finding_id="CVE-2024-0002", component="libbar", severity="LOW"),
        ]
        deps = [
            _make_dependency(
                name="libfoo", purl="pkg:deb/debian/libfoo@1.0.0", direct=False, source_type="image", dep_type="deb"
            ),
            _make_dependency(
                name="libbar", purl="pkg:deb/debian/libbar@1.0.0", direct=False, source_type="image", dep_type="deb"
            ),
        ]
        dep_by_nv = _build_lookup_maps(deps)

        result = process_vulnerabilities(findings, dep_by_nv, deps, "alpine:3.18")

        base_recs = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert len(base_recs) == 0

    def test_rpm_type_recognized_as_os(self):
        findings = [
            _make_finding(
                finding_id=f"CVE-2024-000{i}",
                component=f"rpm-pkg{i}",
                severity="MEDIUM",
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
        dep_by_nv = _build_lookup_maps(deps)

        result = process_vulnerabilities(findings, dep_by_nv, deps, "centos:8")

        base_recs = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert len(base_recs) == 1

    def test_base_image_recommendation_includes_image_name(self):
        findings = [
            _make_finding(
                finding_id=f"CVE-2024-000{i}",
                component=f"libfoo{i}",
                severity="HIGH",
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
        dep_by_nv = _build_lookup_maps(deps)

        result = process_vulnerabilities(findings, dep_by_nv, deps, "python:3.11-slim")

        base_recs = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert base_recs[0].action["current_image"] == "python:3.11-slim"

    @pytest.mark.parametrize(
        ("source_target", "image_name"),
        [
            pytest.param(
                "registry.example.com/team/app@sha256:9b2c1f0e5d8a7b6c4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d",
                "registry.example.com/team/app",
                id="digest",
            ),
            pytest.param("registry.example.com:5000/team/app", "registry.example.com:5000/team/app", id="port-no-tag"),
            pytest.param("registry.example.com:5000/team/app:1.4", "registry.example.com:5000/team/app", id="port-tag"),
            pytest.param("debian:11", "debian", id="tag"),
        ],
    )
    def test_the_suggested_pull_names_the_image_repository(self, source_target, image_name):
        finding = _make_finding(severity="CRITICAL", component="libssl")
        dep = _make_dependency(
            name="libssl", purl="pkg:deb/debian/libssl@1.0.0", direct=False, source_type="image", dep_type="deb"
        )

        result = process_vulnerabilities([finding], _build_lookup_maps([dep]), [dep], source_target)

        [base_rec] = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert base_rec.action["commands"][1] == f"docker pull {image_name}:latest"
        assert base_rec.action["current_image"] == source_target

    def test_effort_low_for_many_vulns(self):
        """When more than 10 OS vulns, effort should be 'low' (batch fix via image update)."""
        findings = [
            _make_finding(
                finding_id=f"CVE-2024-{i:04d}",
                component=f"lib{i}",
                severity="MEDIUM",
            )
            for i in range(15)
        ]
        deps = [
            _make_dependency(
                name=f"lib{i}", purl=f"pkg:deb/debian/lib{i}@1.0.0", direct=False, source_type="image", dep_type="deb"
            )
            for i in range(15)
        ]
        dep_by_nv = _build_lookup_maps(deps)

        result = process_vulnerabilities(findings, dep_by_nv, deps, "debian:11")

        base_recs = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert base_recs[0].effort == "low"


class TestTransitiveDependency:
    def test_transitive_vuln_with_fix(self):
        finding = _make_finding(
            component="transitive-pkg",
            version="0.5.0",
            fixed_version="0.6.0",
        )
        dep = _make_dependency(
            name="transitive-pkg",
            version="0.5.0",
            purl="pkg:pypi/transitive-pkg@0.5.0",
            direct=False,
            source_type="application",
        )
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        trans_recs = [r for r in result if r.type == RecommendationType.TRANSITIVE_FIX_VIA_PARENT]
        assert len(trans_recs) == 1

    def test_transitive_high_effort(self):
        finding = _make_finding(
            component="deep-dep",
            version="1.0.0",
            fixed_version="1.1.0",
        )
        dep = _make_dependency(
            name="deep-dep",
            version="1.0.0",
            purl="pkg:pypi/deep-dep@1.0.0",
            direct=False,
            source_type="application",
        )
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        trans_recs = [r for r in result if r.type == RecommendationType.TRANSITIVE_FIX_VIA_PARENT]
        assert trans_recs[0].effort == "high"

    def test_transitive_critical_priority(self):
        finding = _make_finding(
            severity="CRITICAL",
            component="transitive-pkg",
            version="0.5.0",
            fixed_version="0.6.0",
        )
        dep = _make_dependency(
            name="transitive-pkg",
            version="0.5.0",
            purl="pkg:pypi/transitive-pkg@0.5.0",
            direct=False,
            source_type="application",
        )
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        trans_recs = [r for r in result if r.type == RecommendationType.TRANSITIVE_FIX_VIA_PARENT]
        assert trans_recs[0].priority == Priority.CRITICAL

    def test_transitive_multiple_vulns_grouped(self):
        findings = [
            _make_finding(
                finding_id="CVE-2024-0001",
                component="t-pkg",
                version="0.5.0",
                fixed_version="0.6.0",
            ),
            _make_finding(
                finding_id="CVE-2024-0002",
                component="t-pkg",
                version="0.5.0",
                severity="HIGH",
                fixed_version="0.7.0",
            ),
        ]
        dep = _make_dependency(
            name="t-pkg",
            version="0.5.0",
            purl="pkg:pypi/t-pkg@0.5.0",
            direct=False,
            source_type="application",
        )
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities(findings, dep_by_nv, [dep], None)

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
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        no_fix_recs = [r for r in result if r.type == RecommendationType.NO_FIX_AVAILABLE]
        assert len(no_fix_recs) == expected_count
        if expected_priority is not None:
            assert no_fix_recs[0].priority == expected_priority

    def test_no_fix_high_effort(self):
        finding = _make_finding(severity="CRITICAL", fixed_version=None)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        no_fix_recs = [r for r in result if r.type == RecommendationType.NO_FIX_AVAILABLE]
        assert no_fix_recs[0].effort == "high"

    def test_no_fix_affected_components(self):
        finding = _make_finding(severity="CRITICAL", fixed_version=None, component="vulnerable-lib")
        dep = _make_dependency(name="vulnerable-lib")
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        no_fix_recs = [r for r in result if r.type == RecommendationType.NO_FIX_AVAILABLE]
        assert "vulnerable-lib" in no_fix_recs[0].affected_components

    def test_the_card_claims_only_what_the_advisory_records(self):
        """A missing fixed_version is the absence of a recorded fix, and the card recommends
        replacing a component, so it must not present that absence as proof none exists."""
        finding = _make_finding(severity="CRITICAL", fixed_version=None)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        card = next(r for r in result if r.type == RecommendationType.NO_FIX_AVAILABLE)
        assert _UNSUPPORTED_NO_FIX_CLAIM not in card.description
        assert _ADVISORY_ATTRIBUTION in card.description
        assert any(_UPSTREAM_STEP in step for step in card.action["steps"])


# The claim the data cannot support, the attribution that replaces it, and the step that
# follows from the distinction.
_UNSUPPORTED_NO_FIX_CLAIM = "have no fix available"
_ADVISORY_ATTRIBUTION = "no fixed version in their advisories"
_UPSTREAM_STEP = "Check the upstream project"


class TestKevVulnerabilities:
    def test_kev_vuln_is_critical_priority(self):
        finding = _make_finding(severity="MEDIUM", is_kev=True)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert len(direct_recs) >= 1
        assert direct_recs[0].priority == Priority.CRITICAL

    def test_kev_count_in_impact(self):
        finding = _make_finding(is_kev=True)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["kev_count"] >= 1

    def test_kev_cves_in_action(self):
        finding = _make_finding(finding_id="CVE-2024-9999", is_kev=True)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert "CVE-2024-9999" in direct_recs[0].action.get("kev_cves", [])

    def test_kev_ransomware_count_in_impact(self):
        finding = _make_finding(is_kev=True, kev_ransomware=True)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["kev_ransomware_count"] >= 1

    def test_kev_transitive_also_critical(self):
        finding = _make_finding(
            severity="HIGH",
            is_kev=True,
            component="trans-kev",
        )
        dep = _make_dependency(
            name="trans-kev",
            purl="pkg:pypi/trans-kev@1.0.0",
            direct=False,
            source_type="application",
        )
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        trans_recs = [r for r in result if r.type == RecommendationType.TRANSITIVE_FIX_VIA_PARENT]
        assert trans_recs[0].priority == Priority.CRITICAL


class TestUnreachableDowngrade:
    def test_all_critical_unreachable_downgraded_to_high(self):
        finding = _make_finding(severity="CRITICAL", reachable=False)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].priority == Priority.HIGH

    def test_mixed_reachable_unreachable_stays_critical(self):
        findings = [
            _make_finding(finding_id="CVE-2024-0001", severity="CRITICAL", reachable=True),
            _make_finding(finding_id="CVE-2024-0002", severity="CRITICAL", reachable=False),
        ]
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities(findings, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].priority == Priority.CRITICAL

    def test_unknown_reachability_stays_critical(self):
        finding = _make_finding(severity="CRITICAL", reachable=None)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].priority == Priority.CRITICAL

    def test_an_unreachable_critical_beside_one_of_unknown_reachability_stays_critical(self):
        findings = [
            _make_finding(finding_id="CVE-2024-0001", severity="CRITICAL", reachable=False),
            _make_finding(finding_id="CVE-2024-0002", severity="CRITICAL", reachable=None),
        ]
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities(findings, dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].priority == Priority.CRITICAL

    def test_unreachable_transitive_also_downgraded(self):
        finding = _make_finding(
            severity="CRITICAL",
            reachable=False,
            component="trans",
        )
        dep = _make_dependency(
            name="trans",
            purl="pkg:pypi/trans@1.0.0",
            direct=False,
            source_type="application",
        )
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        trans_recs = [r for r in result if r.type == RecommendationType.TRANSITIVE_FIX_VIA_PARENT]
        assert trans_recs[0].priority == Priority.HIGH


class TestEpssHandling:
    def test_high_epss_boosts_to_high_priority(self):
        finding = _make_finding(severity="MEDIUM", epss_score=0.15)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].priority == Priority.HIGH

    def test_high_epss_count_in_impact(self):
        finding = _make_finding(epss_score=0.2)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["high_epss_count"] >= 1

    def test_medium_epss_counted(self):
        finding = _make_finding(severity="LOW", epss_score=0.05)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["medium_epss_count"] >= 1

    def test_a_score_exactly_at_the_high_threshold_counts_as_high(self):
        finding = _make_finding(finding_id="CVE-2024-7777", severity="MEDIUM", epss_score=0.1)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["high_epss_count"] == 1
        assert direct_recs[0].impact["medium_epss_count"] == 0
        assert direct_recs[0].priority == Priority.HIGH
        assert "CVE-2024-7777" in direct_recs[0].action.get("high_epss_cves", [])

    def test_high_epss_cves_in_action(self):
        finding = _make_finding(finding_id="CVE-2024-5555", epss_score=0.5)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert "CVE-2024-5555" in direct_recs[0].action.get("high_epss_cves", [])


class TestReachabilityImpactData:
    def test_reachable_count_in_impact(self):
        finding = _make_finding(reachable=True)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["reachable_count"] >= 1

    def test_unreachable_count_in_impact(self):
        finding = _make_finding(reachable=False)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["unreachable_count"] >= 1

    def test_reachable_critical_count(self):
        finding = _make_finding(severity="CRITICAL", reachable=True)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["reachable_critical"] >= 1

    def test_reachable_high_count(self):
        finding = _make_finding(severity="HIGH", reachable=True)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].impact["reachable_high"] >= 1

    def test_reachable_critical_forces_critical_priority(self):
        finding_crit = _make_finding(severity="CRITICAL", reachable=True)
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding_crit], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].priority == Priority.CRITICAL


class TestLookupFallback:
    def test_fallback_to_name_version(self):
        finding = _make_finding(
            component="my-lib",
            version="2.0.0",
        )
        dep = _make_dependency(
            name="my-lib",
            version="2.0.0",
            purl="pkg:pypi/my-lib@2.0.0",
        )
        # The finding's purl won't match the dep's purl, but name@version will
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        assert len(result) >= 1


class TestCveIdOnTheStoredShape:
    def test_action_cves_never_carry_the_component_version_pair(self):
        finding = _make_finding(finding_id="CVE-2024-7777", component="log4j-core", version="2.14.1")
        dep = _make_dependency(name="log4j-core", version="2.14.1")
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].action["cves"] == ["CVE-2024-7777"]

    def test_ghsa_entry_is_shown_under_its_cve_alias(self):
        finding = _make_finding(finding_id="GHSA-jfh8-c2jp-5v3q", aliases=["CVE-2021-44228"])
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        result = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert direct_recs[0].action["cves"] == ["CVE-2021-44228"]

    def test_a_finding_naming_no_advisory_is_not_shown_under_its_component(self):
        finding = _make_finding()
        finding["details"]["vulnerabilities"] = []
        dep = _make_dependency()
        dep_by_nv = _build_lookup_maps([dep])

        [card] = process_vulnerabilities([finding], dep_by_nv, [dep], None)

        assert (card.type, "cves" in card.action) == (RecommendationType.NO_FIX_AVAILABLE, False)


class TestUpdateCardsArePerInstalledVersion:
    def _cards(self, findings, deps, card_type):
        dep_by_nv = _build_lookup_maps(deps)
        return [r for r in process_vulnerabilities(findings, dep_by_nv, deps, None) if r.type == card_type]

    def test_each_transitive_version_gets_its_own_card(self):
        findings = [
            _make_finding(finding_id="CVE-1", component="minimist", version="0.0.8", fixed_version="0.2.1"),
            _make_finding(finding_id="CVE-2", component="minimist", version="1.2.0", fixed_version="1.2.6"),
        ]
        deps = [_make_dependency(name="minimist", version=v, direct=False) for v in ("0.0.8", "1.2.0")]

        cards = self._cards(findings, deps, RecommendationType.TRANSITIVE_FIX_VIA_PARENT)

        assert sorted(
            (c.affected_components[0], c.action["current_version"], c.action["target_version"]) for c in cards
        ) == [
            ("minimist@0.0.8", "0.0.8", "0.2.1"),
            ("minimist@1.2.0", "1.2.0", "1.2.6"),
        ]
        assert sorted(c.action["cves"][0] for c in cards) == ["CVE-1", "CVE-2"]

    def test_each_direct_version_gets_its_own_card(self):
        findings = [
            _make_finding(finding_id="CVE-1", severity="HIGH", version="4.17.15", fixed_version="4.17.21"),
            _make_finding(finding_id="CVE-2", severity="CRITICAL", version="3.10.1", fixed_version="4.17.12"),
        ]
        deps = [_make_dependency(version=v) for v in ("4.17.15", "3.10.1")]

        cards = self._cards(findings, deps, RecommendationType.DIRECT_DEPENDENCY_UPDATE)

        assert {c.title: c.priority for c in cards} == {
            "Update pkg-name@4.17.15": Priority.HIGH,
            "Update pkg-name@3.10.1": Priority.CRITICAL,
        }

    def test_the_transitive_card_reports_the_average_epss_like_the_direct_one(self):
        finding = _make_finding(component="trans", epss_score=0.2)
        dep = _make_dependency(name="trans", direct=False)

        [card] = self._cards([finding], [dep], RecommendationType.TRANSITIVE_FIX_VIA_PARENT)

        assert card.impact["avg_epss"] == 0.2


class TestInferredDirectnessIsNotPresentedAsDeclared:
    def test_an_inferred_direct_dependency_says_the_sbom_does_not_record_it(self):
        finding = _make_finding(component="openssl-lib")
        dep = {**_make_dependency(name="openssl-lib"), "direct_inferred": True}

        result = process_vulnerabilities([finding], _build_lookup_maps([dep]), [dep], None)

        [card] = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert card.action["direct_inferred"] is True
        assert card.effort == "medium"
        assert "does not record whether openssl-lib is a direct dependency" in card.description

    def test_a_declared_direct_dependency_keeps_the_low_effort_update(self):
        finding = _make_finding()
        dep = _make_dependency()

        result = process_vulnerabilities([finding], _build_lookup_maps([dep]), [dep], None)

        [card] = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert card.action["direct_inferred"] is False
        assert card.effort == "low"


class TestUpdateCardsReadTheLiveAdvisories:
    def _direct_card(self, advisories, **details):
        finding = _make_finding(component="log4j-core", version="2.14.1", severity="MEDIUM", fixed_version="2.17.1")
        fixed = [a | {"fixed_version": "2.17.1"} for a in advisories]
        finding["details"] |= {**details, "vulnerabilities": fixed}
        dep = _make_dependency(name="log4j-core", version="2.14.1")
        result = process_vulnerabilities([finding], _build_lookup_maps([dep]), [dep], None)
        [card] = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        return card

    def test_a_kev_cve_waived_on_its_own_neither_raises_the_card_nor_is_named(self):
        waived = {"id": "CVE-2021-44228", "waived": True, "in_kev": True, "epss_score": 0.94}
        card = self._direct_card([waived, {"id": "CVE-2021-44832", "epss_score": 0.001}], in_kev=True, epss_score=0.94)

        assert card.priority == Priority.MEDIUM
        assert (card.impact["kev_count"], card.impact["high_epss_count"]) == (0, 0)
        assert (card.action["kev_cves"], card.action["high_epss_cves"]) == ([], [])
        assert card.action["cves"] == ["CVE-2021-44832"]

    def test_the_kev_and_epss_samples_name_the_cve_that_carries_the_mark(self):
        card = self._direct_card(
            [
                {"id": "CVE-2026-0001"},
                {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-0002"], "in_kev": True},
                {"id": "CVE-2026-0003", "epss_score": 0.5},
            ],
            in_kev=True,
            epss_score=0.5,
        )

        assert card.action["kev_cves"] == ["CVE-2026-0002"]
        assert card.action["high_epss_cves"] == ["CVE-2026-0003"]
        assert card.action["cves"] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]


class TestPartiallyFixableRecords:
    """One record bundles every advisory of a component@version, and OS images routinely pair a
    fixable CRITICAL with a LOW the distribution will not fix."""

    def _types(self, finding, dep, target=None):
        return [r.type for r in process_vulnerabilities([finding], _build_lookup_maps([dep]), [dep], target)]

    def test_a_fixed_critical_beside_an_unfixed_low_gets_the_base_image_card(self):
        finding = stored_vulnerability(
            "libssl3",
            "3.0.11-1~deb12u2",
            [
                {"id": "CVE-2024-0001", "severity": "CRITICAL", "fixed_version": "3.0.13-1~deb12u1"},
                {"id": "CVE-2024-0002", "severity": "LOW", "fixed_version": None},
            ],
        )
        dep = _make_dependency(
            name="libssl3",
            version="3.0.11-1~deb12u2",
            purl="pkg:deb/debian/libssl3@3.0.11-1~deb12u2",
            direct=False,
            source_type="image",
            dep_type="deb",
        )

        assert self._types(finding, dep, "debian:12") == [RecommendationType.BASE_IMAGE_UPDATE]

    def test_the_update_targets_the_fix_of_every_advisory_that_names_one(self):
        finding = stored_vulnerability(
            "axios",
            "1.5.0",
            [
                {"id": "CVE-2024-0003", "severity": "HIGH", "fixed_version": "1.6.0"},
                {"id": "CVE-2024-0004", "severity": "MEDIUM", "fixed_version": "1.5.1"},
                {"id": "CVE-2024-0005", "severity": "LOW", "fixed_version": None},
            ],
        )
        dep = _make_dependency(name="axios", version="1.5.0")

        [card] = process_vulnerabilities([finding], _build_lookup_maps([dep]), [dep], None)

        assert card.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE
        assert card.action["target_version"] == "1.6.0"

    def test_an_unfixed_critical_beside_a_fixed_low_stays_without_a_known_fix(self):
        finding = stored_vulnerability(
            "lodash",
            "4.17.0",
            [
                {"id": "CVE-2024-0006", "severity": "CRITICAL", "fixed_version": None},
                {"id": "CVE-2024-0007", "severity": "LOW", "fixed_version": "4.17.21"},
            ],
        )

        assert self._types(finding, _make_dependency(name="lodash", version="4.17.0")) == [
            RecommendationType.NO_FIX_AVAILABLE
        ]

    def test_a_waived_unfixed_critical_no_longer_blocks_the_update(self):
        finding = stored_vulnerability(
            "express",
            "4.18.0",
            [
                {"id": "CVE-2024-0008", "severity": "CRITICAL", "fixed_version": None, "waived": True},
                {"id": "CVE-2024-0009", "severity": "HIGH", "fixed_version": "4.19.2"},
            ],
        )

        assert self._types(finding, _make_dependency(name="express", version="4.18.0")) == [
            RecommendationType.DIRECT_DEPENDENCY_UPDATE
        ]
