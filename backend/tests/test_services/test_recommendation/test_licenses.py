"""Tests for app.services.recommendation.licenses."""

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.licenses import process_licenses


def _license(
    severity="HIGH",
    component="gpl-lib",
    license_name="GPL-3.0",
    finding_id="lic1",
):
    return {
        "type": "license",
        "severity": severity,
        "component": component,
        "details": {"license": license_name},
        "id": finding_id,
    }


class TestProcessLicensesEmpty:
    """Edge case: no findings."""

    def test_empty_list_returns_empty(self):
        assert process_licenses([]) == []

    def test_empty_iterable(self):
        assert process_licenses(list()) == []


class TestProcessLicensesSingleFinding:
    """A single license finding produces exactly one recommendation."""

    def test_returns_one_recommendation(self):
        result = process_licenses([_license()])
        assert len(result) == 1

    def test_type_is_license_compliance(self):
        rec = process_licenses([_license()])[0]
        assert rec.type == RecommendationType.LICENSE_COMPLIANCE

    def test_title_is_resolve_license_compliance(self):
        rec = process_licenses([_license()])[0]
        assert rec.title == "Resolve License Compliance Issues"

    def test_affected_components_contains_component(self):
        rec = process_licenses([_license(component="gpl-lib")])[0]
        assert "gpl-lib" in rec.affected_components

    def test_effort_is_medium(self):
        rec = process_licenses([_license()])[0]
        assert rec.effort == "medium"


class TestProcessLicensesPriorityCritical:
    """CRITICAL severity findings yield CRITICAL priority."""

    def test_single_critical(self):
        rec = process_licenses([_license(severity="CRITICAL")])[0]
        assert rec.priority == Priority.CRITICAL

    def test_critical_among_lows(self):
        findings = [
            _license(severity="LOW", finding_id="l1"),
            _license(severity="CRITICAL", finding_id="l2"),
            _license(severity="LOW", finding_id="l3"),
        ]
        rec = process_licenses(findings)[0]
        assert rec.priority == Priority.CRITICAL


class TestProcessLicensesPriorityHigh:
    """HIGH severity findings without CRITICAL yield HIGH priority."""

    def test_single_high(self):
        rec = process_licenses([_license(severity="HIGH")])[0]
        assert rec.priority == Priority.HIGH

    def test_high_among_mediums(self):
        findings = [
            _license(severity="MEDIUM", finding_id="l1"),
            _license(severity="HIGH", finding_id="l2"),
        ]
        rec = process_licenses(findings)[0]
        assert rec.priority == Priority.HIGH


class TestProcessLicensesPriorityMedium:
    """Only MEDIUM (or lower) severity -> MEDIUM priority."""

    def test_only_medium(self):
        findings = [
            _license(severity="MEDIUM", finding_id="l1"),
            _license(severity="MEDIUM", finding_id="l2"),
        ]
        rec = process_licenses(findings)[0]
        assert rec.priority == Priority.MEDIUM

    def test_only_low(self):
        rec = process_licenses([_license(severity="LOW")])[0]
        assert rec.priority == Priority.MEDIUM

    def test_mix_of_medium_and_low(self):
        findings = [
            _license(severity="MEDIUM", finding_id="l1"),
            _license(severity="LOW", finding_id="l2"),
        ]
        rec = process_licenses(findings)[0]
        assert rec.priority == Priority.MEDIUM


class TestProcessLicensesGroupedByType:
    """Multiple license types are grouped correctly."""

    def test_single_license_in_description(self):
        rec = process_licenses([_license(license_name="GPL-3.0")])[0]
        assert "GPL-3.0" in rec.description

    def test_multiple_license_types_in_description(self):
        findings = [
            _license(license_name="GPL-3.0", finding_id="l1"),
            _license(license_name="AGPL-3.0", finding_id="l2"),
        ]
        rec = process_licenses(findings)[0]
        assert "GPL-3.0" in rec.description
        assert "AGPL-3.0" in rec.description

    def test_problematic_licenses_in_action(self):
        findings = [
            _license(license_name="GPL-3.0", finding_id="l1"),
            _license(license_name="AGPL-3.0", finding_id="l2"),
            _license(license_name="SSPL", finding_id="l3"),
        ]
        rec = process_licenses(findings)[0]
        licenses = rec.action["problematic_licenses"]
        assert "GPL-3.0" in licenses
        assert "AGPL-3.0" in licenses
        assert "SSPL" in licenses

    def test_problematic_licenses_limited_to_ten(self):
        findings = [
            _license(license_name=f"License-{i}", finding_id=f"l{i}")
            for i in range(15)
        ]
        rec = process_licenses(findings)[0]
        assert len(rec.action["problematic_licenses"]) <= 10

    def test_description_limited_to_five_license_names(self):
        """Description should show at most 5 license names."""
        findings = [
            _license(license_name=f"License-{i}", finding_id=f"l{i}")
            for i in range(8)
        ]
        rec = process_licenses(findings)[0]
        # The description joins at most 5 via problematic_licenses[:5]
        # Count occurrences of "License-" in description
        count = rec.description.count("License-")
        assert count <= 5


class TestProcessLicensesComponentsTracked:
    """Components are tracked correctly."""

    def test_unique_components(self):
        findings = [
            _license(component="lib-a", finding_id="l1"),
            _license(component="lib-b", finding_id="l2"),
        ]
        rec = process_licenses(findings)[0]
        assert "lib-a" in rec.affected_components
        assert "lib-b" in rec.affected_components

    def test_duplicate_components_deduplicated(self):
        findings = [
            _license(component="lib-a", finding_id="l1"),
            _license(component="lib-a", finding_id="l2"),
        ]
        rec = process_licenses(findings)[0]
        assert rec.affected_components.count("lib-a") == 1

    def test_description_component_count(self):
        findings = [
            _license(component="lib-a", finding_id="l1"),
            _license(component="lib-b", finding_id="l2"),
        ]
        rec = process_licenses(findings)[0]
        assert "2 components" in rec.description

    def test_affected_components_limited_to_twenty(self):
        findings = [
            _license(component=f"lib-{i}", finding_id=f"l{i}")
            for i in range(25)
        ]
        rec = process_licenses(findings)[0]
        assert len(rec.affected_components) <= 20


class TestProcessLicensesImpact:
    """Impact dict contains correct severity counts."""

    def test_severity_counts(self):
        findings = [
            _license(severity="CRITICAL", finding_id="l1"),
            _license(severity="HIGH", finding_id="l2"),
            _license(severity="HIGH", finding_id="l3"),
            _license(severity="MEDIUM", finding_id="l4"),
            _license(severity="LOW", finding_id="l5"),
        ]
        rec = process_licenses(findings)[0]
        assert rec.impact["critical"] == 1
        assert rec.impact["high"] == 2
        assert rec.impact["medium"] == 1
        assert rec.impact["low"] == 1
        assert rec.impact["total"] == 5


class TestProcessLicensesLicenseIdFallback:
    """license_id is used as fallback when license key is missing."""

    def test_license_id_fallback(self):
        finding = {
            "type": "license",
            "severity": "HIGH",
            "component": "some-lib",
            "details": {"license_id": "MIT-0"},
            "id": "l1",
        }
        rec = process_licenses([finding])[0]
        assert "MIT-0" in rec.description

    def test_unknown_fallback(self):
        finding = {
            "type": "license",
            "severity": "HIGH",
            "component": "some-lib",
            "details": {},
            "id": "l1",
        }
        rec = process_licenses([finding])[0]
        assert "unknown" in rec.description


class TestProcessLicensesAction:
    """Action dict structure."""

    def test_action_type(self):
        rec = process_licenses([_license()])[0]
        assert rec.action["type"] == "license_compliance"

    def test_action_has_steps(self):
        rec = process_licenses([_license()])[0]
        assert len(rec.action["steps"]) > 0
