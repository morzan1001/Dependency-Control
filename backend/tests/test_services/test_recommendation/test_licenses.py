"""Tests for app.services.recommendation.licenses."""

import pytest

from app.schemas.recommendation import Priority, RecommendationType
from app.services.aggregation import ResultAggregator
from app.services.analyzers.license_compliance.analyzer import LicenseAnalyzer
from app.services.analyzers.license_compliance.constants import UNDETERMINED_LICENSE_ID
from app.services.recommendation.common import AFFECTED_COMPONENTS_SHOWN
from app.services.recommendation.licenses import _LICENSES_NAMED, detect_license_drift, process_licenses


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
    def test_empty_list_returns_empty(self):
        assert process_licenses([]) == []


class TestProcessLicensesSingleFinding:
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

    def test_the_action_carries_every_problematic_license(self):
        found = 15
        findings = [_license(license_name=f"License-{i:02d}", finding_id=f"l{i}") for i in range(found)]

        rec = process_licenses(findings)[0]

        assert len(rec.action["problematic_licenses"]) == found

    def test_the_description_names_a_few_and_counts_the_rest(self):
        found = 8
        findings = [_license(license_name=f"License-{i:02d}", finding_id=f"l{i}") for i in range(found)]

        rec = process_licenses(findings)[0]

        assert rec.description.count("License-") == _LICENSES_NAMED
        assert f"and {found - _LICENSES_NAMED} more" in rec.description


class TestProcessLicensesComponentsTracked:
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
        findings = [_license(component=f"lib-{i}", finding_id=f"l{i}") for i in range(25)]
        rec = process_licenses(findings)[0]
        assert len(rec.affected_components) <= 20


class TestProcessLicensesImpact:
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


class TestProcessLicensesMissingLicense:
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
    def test_action_type(self):
        rec = process_licenses([_license()])[0]
        assert rec.action["type"] == "license_compliance"

    def test_action_has_steps(self):
        rec = process_licenses([_license()])[0]
        assert len(rec.action["steps"]) > 0


_INTERNAL_ONLY = {"distribution_model": "internal_only"}


def _component(name, licence=None, version="1.0"):
    component = {"name": name, "version": version, "purl": f"pkg:npm/{name}@{version}", "direct": True}
    if licence:
        component["license"] = licence
    return component


async def _analyzed(components, settings):
    result = await LicenseAnalyzer().analyze(sbom={}, settings=settings, parsed_components=components)
    aggregator = ResultAggregator()
    aggregator.aggregate("license_compliance", result)
    return aggregator.get_findings()


class TestProcessLicensesPolicyAccepted:
    """INFO is the evaluator's verdict for an outcome the policy accepts; only the undeterminable licence needs action."""

    @pytest.mark.asyncio
    async def test_licences_the_policy_accepted_produce_no_card(self):
        findings = await _analyzed([_component("gpl-lib", "GPL-3.0-only")], _INTERNAL_ONLY)

        assert [f.severity for f in findings] == ["INFO"]
        assert process_licenses(findings) == []

    @pytest.mark.asyncio
    async def test_accepted_findings_are_left_out_of_the_count_and_the_licences(self):
        findings = await _analyzed(
            [_component("gpl-lib", "GPL-3.0-only"), _component("nc-lib", "CC-BY-NC-4.0")], _INTERNAL_ONLY
        )

        [rec] = process_licenses(findings)

        assert rec.priority == Priority.HIGH
        assert rec.impact["total"] == 1
        assert rec.action["problematic_licenses"] == ["CC-BY-NC-4.0"]
        assert rec.affected_components == ["nc-lib"]
        assert rec.description.startswith("Found 1 license compliance issues across 1 components.")

    @pytest.mark.asyncio
    async def test_an_undeterminable_licence_is_still_counted(self):
        findings = await _analyzed([_component("mystery-lib")], _INTERNAL_ONLY)

        [rec] = process_licenses(findings)

        assert rec.priority == Priority.LOW
        assert rec.impact["total"] == 1
        assert rec.action["problematic_licenses"] == [UNDETERMINED_LICENSE_ID]


# --- License Drift Detection ---


async def _stored(*components):
    """Each SBOM row with the licence category the analysis engine copies onto it from the licence scan."""
    result = await LicenseAnalyzer().analyze(sbom={}, settings={}, parsed_components=list(components))
    aggregator = ResultAggregator()
    aggregator.aggregate("license_compliance", result)
    categories = {entry["purl"]: entry["data"]["license_category"] for entry in aggregator.get_dependency_enrichments()}
    return [
        {**component, "license_category": categories[component["purl"]]}
        if component["purl"] in categories
        else component
        for component in components
    ]


async def _drift(previous, current):
    return detect_license_drift(await _stored(*current), await _stored(*previous))


class TestDetectLicenseDrift:
    @pytest.mark.asyncio
    async def test_a_package_relicensed_from_mit_to_gpl_between_two_scans_is_drift(self):
        [rec] = await _drift([_component("lib", "MIT")], [_component("lib", "GPL-3.0-only", version="2.0")])

        assert rec.type == RecommendationType.LICENSE_DRIFT
        assert rec.priority == Priority.HIGH
        assert rec.impact == {"total": 1, "restrictive_drift": 1}
        assert rec.affected_components == ["lib: MIT → GPL-3.0-only"]
        assert rec.action["drifted_components"] == [
            {
                "component": "lib",
                "previous_license": "MIT",
                "previous_category": "permissive",
                "current_license": "GPL-3.0-only",
                "current_category": "strong_copyleft",
            }
        ]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("licence", ["MIT", "GPL-3.0-only"])
    async def test_a_licence_that_became_determinable_is_not_drift(self, licence):
        assert await _drift([_component("lib")], [_component("lib", licence)]) == []

    @pytest.mark.asyncio
    async def test_an_unchanged_package_with_two_licence_findings_is_not_drift(self):
        package = _component("lib", "GPL-2.0-only AND FooBar-License")
        assert [f.details["license"] for f in await _analyzed([package], {})] == [
            "GPL-2.0-only",
            UNDETERMINED_LICENSE_ID,
        ]

        assert await _drift([package], [package]) == []

    @pytest.mark.asyncio
    async def test_the_action_names_how_many_drifted_components_it_sampled(self):
        names = [f"lib-{i:02d}" for i in range(AFFECTED_COMPONENTS_SHOWN + 2)]

        [rec] = await _drift([_component(n, "MIT") for n in names], [_component(n, "GPL-3.0-only") for n in names])

        assert len(rec.action["drifted_components"]) == AFFECTED_COMPONENTS_SHOWN
        assert rec.action["drifted_components_total"] == len(names)

    @pytest.mark.asyncio
    async def test_drift_to_weak_copyleft_is_medium(self):
        [rec] = await _drift([_component("lib", "MIT")], [_component("lib", "MPL-2.0")])

        assert rec.priority == Priority.MEDIUM
        assert rec.impact == {"total": 1, "restrictive_drift": 0}

    @pytest.mark.asyncio
    async def test_a_switch_to_proprietary_counts_as_restrictive_drift_not_copyleft(self):
        [rec] = await _drift([_component("lib", "MIT")], [_component("lib", "CC-BY-NC-4.0")])

        assert rec.priority == Priority.HIGH
        assert rec.impact == {"total": 1, "restrictive_drift": 1}

    @pytest.mark.asyncio
    async def test_copyleft_to_permissive_is_not_drift(self):
        assert await _drift([_component("lib", "GPL-3.0-only")], [_component("lib", "MIT")]) == []

    @pytest.mark.asyncio
    async def test_a_licence_change_inside_one_category_is_not_drift(self):
        assert await _drift([_component("lib", "MIT")], [_component("lib", "Apache-2.0")]) == []

    @pytest.mark.asyncio
    async def test_a_package_new_in_this_scan_is_not_drift(self):
        assert await _drift([_component("lodash", "MIT")], [_component("underscore", "GPL-3.0-only")]) == []

    @pytest.mark.asyncio
    async def test_two_versions_of_one_package_count_once_at_their_most_restrictive_licence(self):
        [rec] = await _drift(
            [_component("lib", "MIT")],
            [_component("lib", "MIT"), _component("lib", "GPL-3.0-only", version="2.0")],
        )

        assert rec.impact["total"] == 1
        assert rec.affected_components == ["lib: MIT → GPL-3.0-only"]
