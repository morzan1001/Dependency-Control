"""Tests for the LicenseAnalyzer - license compliance analysis."""

import asyncio
import itertools
from dataclasses import replace
from typing import Any, ClassVar

import pytest

from app.core.constants import NON_RUNTIME_SCOPES, get_severity_value
from app.models.finding import Severity
from app.models.license import (
    DeploymentModel,
    DistributionModel,
    LibraryUsage,
    LicenseCategory,
)
from app.schemas.project import LicensePolicySchema
from app.services.analyzers.license_compliance import LicenseAnalyzer
from app.services.analyzers.license_compliance.compatibility import partition_or_groups
from app.services.analyzers.license_compliance.constants import LICENSE_INCOMPATIBILITY_CATEGORY
from app.services.analyzers.license_compliance.evaluator import (
    apply_transitive_adjustment,
    evaluate_license,
    is_acceptable_under_policy,
    should_include_finding,
)
from app.services.analyzers.license_compliance.normalizer import normalize_license
from app.services.sbom_parser import parse_sbom


_TEST_PKG = {"name": "test-pkg", "version": "1.0.0", "purl": "pkg:pypi/test-pkg@1.0.0"}


def _parsed_cyclonedx(components: list[dict[str, Any]], transitive_refs: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    sbom: dict[str, Any] = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}
    if transitive_refs:
        # An undeclared node is transparent to the parser, so the hub must be a real package.
        sbom["components"] = [*components, _library("hub", "MIT")]
        sbom["metadata"] = {"component": {"bom-ref": "app"}}
        sbom["dependencies"] = [
            {"ref": "app", "dependsOn": ["hub"]},
            {"ref": "hub", "dependsOn": list(transitive_refs)},
        ]
    return [dep.model_dump() for dep in parse_sbom(sbom).dependencies]


def _library(name: str, licence: str) -> dict[str, Any]:
    return {
        "type": "library",
        "bom-ref": name,
        "name": name,
        "version": "1.0",
        "purl": f"pkg:npm/{name}@1.0",
        "licenses": [{"expression": licence}],
    }


class TestNormalizeLicense:
    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            pytest.param("MIT", "MIT", id="exact-mit"),
            pytest.param("Apache-2.0", "Apache-2.0", id="exact-apache"),
            pytest.param("mit", "MIT", id="lowercase-mit"),
            pytest.param("apache-2.0", "Apache-2.0", id="lowercase-apache"),
            pytest.param("Apache 2.0", "Apache-2.0", id="alias-apache-spaced"),
            pytest.param("Expat", "MIT", id="alias-expat"),
            pytest.param("MIT/X11", "MIT", id="alias-mit-x11"),
            pytest.param("GPLv3", "GPL-3.0", id="alias-gplv3"),
            pytest.param("AGPL", "AGPL-3.0", id="alias-agpl"),
            pytest.param("apache 2.0", "Apache-2.0", id="alias-lowercase"),
            pytest.param("BSD", "BSD-3-Clause", id="alias-bsd"),
            pytest.param("Public Domain", "Unlicense", id="alias-public-domain"),
            pytest.param("PSF", "Python-2.0", id="alias-psf"),
            pytest.param("Boost", "BSL-1.0", id="alias-boost"),
            pytest.param('MIT;link="https://example.com"', "MIT", id="metadata-semicolon"),
            pytest.param('Apache-2.0";link="https://spdx.org"', "Apache-2.0", id="metadata-quote-and-semicolon"),
            pytest.param('"MIT"', "MIT", id="surrounding-quotes"),
            pytest.param("  MIT  ", "MIT", id="surrounding-spaces"),
            pytest.param("", "", id="empty-string"),
            pytest.param(';link="https://example.com"', "", id="metadata-only"),
            pytest.param("SomeCustomLicense-1.0", "SomeCustomLicense-1.0", id="unknown-passthrough"),
            pytest.param("GPL-2.0+", "GPL-2.0-or-later", id="plus-means-or-later"),
            pytest.param("LGPL-2.1-only+", "LGPL-2.1-or-later", id="plus-on-an-only-id"),
        ],
    )
    def test_normalizes_to_the_canonical_spdx_id(self, raw, expected):
        assert normalize_license(raw) == expected


class TestEvaluateLicense:
    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def _get_license_info(self, spdx_id):
        return self.analyzer.LICENSE_DATABASE[spdx_id]

    def _evaluate(self, spdx_id, allow_strong=False, allow_network=False):
        info = self._get_license_info(spdx_id)
        policy = LicensePolicySchema(
            allow_strong_copyleft=allow_strong,
            allow_network_copyleft=allow_network,
        )
        return evaluate_license(_TEST_PKG, info, policy)

    @pytest.mark.parametrize(
        "spdx_id",
        [
            pytest.param("MIT", id="permissive-mit"),
            pytest.param("Apache-2.0", id="permissive-apache"),
            pytest.param("BSD-3-Clause", id="permissive-bsd"),
            pytest.param("Unlicense", id="public-domain-unlicense"),
            pytest.param("CC0-1.0", id="public-domain-cc0"),
        ],
    )
    def test_a_licence_with_no_obligation_raises_no_issue(self, spdx_id):
        result = self._evaluate(spdx_id)
        assert result is None

    @pytest.mark.parametrize(
        ("spdx_id", "policy_kwargs", "expected_severity"),
        [
            pytest.param("LGPL-3.0", {}, Severity.INFO, id="weak-copyleft-lgpl"),
            pytest.param("MPL-2.0", {}, Severity.INFO, id="weak-copyleft-mpl"),
            pytest.param("GPL-3.0", {"allow_strong": False}, Severity.HIGH, id="strong-copyleft-disallowed"),
            pytest.param("GPL-3.0", {"allow_strong": True}, Severity.INFO, id="strong-copyleft-allowed"),
            pytest.param("GPL-2.0", {"allow_strong": False}, Severity.HIGH, id="strong-copyleft-gpl2-disallowed"),
            pytest.param("AGPL-3.0", {"allow_network": False}, Severity.CRITICAL, id="network-copyleft-disallowed"),
            pytest.param("AGPL-3.0", {"allow_network": True}, Severity.MEDIUM, id="network-copyleft-allowed"),
            pytest.param(
                "SSPL-1.0", {"allow_network": False}, Severity.CRITICAL, id="network-copyleft-sspl-disallowed"
            ),
            pytest.param("SSPL-1.0", {"allow_network": True}, Severity.MEDIUM, id="network-copyleft-sspl-allowed"),
            pytest.param("CC-BY-NC-4.0", {}, Severity.HIGH, id="proprietary"),
        ],
    )
    def test_the_severity_follows_the_category_and_the_policy(self, spdx_id, policy_kwargs, expected_severity):
        result = self._evaluate(spdx_id, **policy_kwargs)
        assert result is not None
        assert result["severity"] == expected_severity.value

    @pytest.mark.parametrize(
        ("field", "expected"),
        [
            pytest.param("component", "test-pkg", id="component"),
            pytest.param("version", "1.0.0", id="version"),
            pytest.param("license", "GPL-3.0", id="license"),
            pytest.param("category", LicenseCategory.STRONG_COPYLEFT.value, id="category"),
            pytest.param("purl", "pkg:pypi/test-pkg@1.0.0", id="purl"),
        ],
    )
    def test_the_issue_identifies_the_component_it_was_raised_for(self, field, expected):
        result = self._evaluate("GPL-3.0")
        assert result[field] == expected

    def test_issue_contains_obligations(self):
        result = self._evaluate("GPL-3.0")
        assert isinstance(result["obligations"], list)
        assert len(result["obligations"]) > 0

    @pytest.mark.parametrize("spdx_id", ["CC-BY-ND-4.0", "BUSL-1.1", "Elastic-2.0", "CC-BY-NC-4.0"])
    def test_a_restricted_licence_is_judged_against_its_own_terms(self, spdx_id):
        result = self._evaluate(spdx_id)
        assert result["explanation"] == self._get_license_info(spdx_id).description
        assert result["recommendation"].startswith("This license restricts commercial use, production use or")


class TestLicenseDatabase:
    """Spot-check that LICENSE_DATABASE has correct entries and categories."""

    def setup_method(self):
        self.db = LicenseAnalyzer.LICENSE_DATABASE

    @pytest.mark.parametrize(
        ("spdx_id", "category"),
        [
            pytest.param("MIT", LicenseCategory.PERMISSIVE, id="mit"),
            pytest.param("Apache-2.0", LicenseCategory.PERMISSIVE, id="apache"),
            pytest.param("ISC", LicenseCategory.PERMISSIVE, id="isc"),
            pytest.param("LGPL-3.0", LicenseCategory.WEAK_COPYLEFT, id="lgpl"),
            pytest.param("MPL-2.0", LicenseCategory.WEAK_COPYLEFT, id="mpl"),
            pytest.param("GPL-3.0-only", LicenseCategory.STRONG_COPYLEFT, id="gpl3-only"),
            pytest.param("AGPL-3.0-only", LicenseCategory.NETWORK_COPYLEFT, id="agpl3-only"),
            pytest.param("SSPL-1.0", LicenseCategory.NETWORK_COPYLEFT, id="sspl"),
            pytest.param("CC-BY-NC-4.0", LicenseCategory.PROPRIETARY, id="cc-by-nc"),
            pytest.param("Unlicense", LicenseCategory.PUBLIC_DOMAIN, id="unlicense"),
        ],
    )
    def test_the_licence_is_filed_under_its_category(self, spdx_id, category):
        assert spdx_id in self.db
        assert self.db[spdx_id].category == category

    @pytest.mark.parametrize(
        ("category", "spdx_ids"),
        [
            (LicenseCategory.PROPRIETARY, "BUSL-1.1 Elastic-2.0 CC-BY-NC-SA-4.0 CC-BY-NC-ND-4.0 CC-BY-ND-4.0"),
            (LicenseCategory.NETWORK_COPYLEFT, "AGPL-1.0 AGPL-1.0-only AGPL-1.0-or-later CPAL-1.0 RPL-1.5 OSL-3.0"),
            (LicenseCategory.STRONG_COPYLEFT, "GPL-1.0 GPL-1.0-only GPL-1.0-or-later EUPL-1.1 EUPL-1.2 Sleepycat"),
            (LicenseCategory.WEAK_COPYLEFT, "LGPL-2.0-only LGPL-2.0-or-later MPL-1.1 CDDL-1.1 MS-RL"),
            (
                LicenseCategory.PERMISSIVE,
                "PSF-2.0 MIT-0 BlueOak-1.0.0 Unicode-DFS-2016 Unicode-3.0 BSD-4-Clause Apache-1.1 OpenSSL curl X11 "
                "HPND ICU NCSA UPL-1.0 OFL-1.1 CC-BY-3.0 Python-2.0.1",
            ),
        ],
    )
    def test_common_spdx_ids_are_filed_under_their_category(self, category, spdx_ids):
        filed = {lic: self.db[lic].category if lic in self.db else None for lic in spdx_ids.split()}
        assert filed == dict.fromkeys(spdx_ids.split(), category)

    @pytest.mark.parametrize(
        "deprecated", ["GPL-1.0", "GPL-2.0", "GPL-3.0", "LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "AGPL-1.0", "AGPL-3.0"]
    )
    def test_a_deprecated_id_carries_the_terms_of_its_only_form(self, deprecated):
        only = self.db[f"{deprecated}-only"]
        assert replace(self.db[deprecated], spdx_id=only.spdx_id, name=only.name) == only

    def test_every_licence_name_resolves_to_one_licence(self):
        names = [info.name.lower() for info in self.db.values()]
        assert len(set(names)) == len(names)


class TestEvaluateLicenseWithContext:
    """Context-aware license evaluation driven by LicensePolicySchema."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def _get_license_info(self, spdx_id):
        return self.analyzer.LICENSE_DATABASE[spdx_id]

    def _evaluate_with_policy(self, spdx_id, **policy_kwargs):
        info = self._get_license_info(spdx_id)
        policy = LicensePolicySchema(**policy_kwargs)
        return evaluate_license(_TEST_PKG, info, policy)

    # --- Weak Copyleft + library_usage ---

    @pytest.mark.parametrize(
        "spdx_id",
        [
            pytest.param("LGPL-3.0", id="lgpl"),
            pytest.param("MPL-2.0", id="mpl"),
        ],
    )
    def test_weak_copyleft_used_unmodified_returns_none(self, spdx_id):
        result = self._evaluate_with_policy(spdx_id, library_usage=LibraryUsage.UNMODIFIED)
        assert result is None

    def test_weak_copyleft_modified_returns_info(self):
        result = self._evaluate_with_policy("LGPL-3.0", library_usage=LibraryUsage.MODIFIED)
        assert result is not None
        assert result["severity"] == Severity.INFO.value
        assert result["context_reason"] is not None

    @pytest.mark.parametrize(
        "policy_kwargs",
        [
            pytest.param({"library_usage": LibraryUsage.MIXED}, id="mixed-usage"),
            pytest.param({}, id="usage-unstated"),
        ],
    )
    def test_weak_copyleft_otherwise_returns_info(self, policy_kwargs):
        result = self._evaluate_with_policy("LGPL-3.0", **policy_kwargs)
        assert result is not None
        assert result["severity"] == Severity.INFO.value

    # --- Strong Copyleft + distribution_model ---

    @pytest.mark.parametrize(
        "policy_kwargs",
        [
            pytest.param({"distribution_model": DistributionModel.INTERNAL_ONLY}, id="internal-only"),
            pytest.param({"distribution_model": DistributionModel.OPEN_SOURCE}, id="open-source"),
            pytest.param({"allow_strong_copyleft": True}, id="allowed-by-policy"),
        ],
    )
    def test_softened_strong_copyleft_is_info_and_says_why(self, policy_kwargs):
        result = self._evaluate_with_policy("GPL-3.0", **policy_kwargs)
        assert result["severity"] == Severity.INFO.value
        assert result["context_reason"]
        assert result["severity_without_context"] == Severity.HIGH.value

    # --- Network Copyleft + deployment_model ---

    @pytest.mark.parametrize(
        ("spdx_id", "policy_kwargs", "expected_severity"),
        [
            *(
                pytest.param(
                    "AGPL-3.0", {"deployment_model": deployment}, Severity.HIGH, id=f"{deployment.value}-distributed"
                )
                for deployment in (DeploymentModel.CLI_BATCH, DeploymentModel.DESKTOP, DeploymentModel.EMBEDDED)
            ),
            *(
                pytest.param(
                    "AGPL-3.0",
                    {"deployment_model": DeploymentModel.DESKTOP, "distribution_model": distribution},
                    Severity.LOW,
                    id=f"desktop-{distribution.value}",
                )
                for distribution in (DistributionModel.INTERNAL_ONLY, DistributionModel.OPEN_SOURCE)
            ),
            *(
                pytest.param(
                    "SSPL-1.0",
                    {"deployment_model": DeploymentModel.EMBEDDED, allowed: True},
                    Severity.MEDIUM,
                    id=allowed,
                )
                for allowed in ("allow_network_copyleft", "allow_strong_copyleft")
            ),
            pytest.param(
                "AGPL-3.0",
                {"distribution_model": DistributionModel.INTERNAL_ONLY},
                Severity.MEDIUM,
                id="network-facing-internal-only",
            ),
            pytest.param("AGPL-3.0", {"allow_network_copyleft": True}, Severity.MEDIUM, id="network-facing-allowed"),
            pytest.param(
                "AGPL-3.0-only",
                {"distribution_model": DistributionModel.OPEN_SOURCE},
                Severity.INFO,
                id="network-facing-open-source",
            ),
        ],
    )
    def test_softened_network_copyleft_says_why(self, spdx_id, policy_kwargs, expected_severity):
        result = self._evaluate_with_policy(spdx_id, **policy_kwargs)
        assert result["severity"] == expected_severity.value
        assert result["context_reason"]
        assert result["severity_without_context"] == Severity.CRITICAL.value

    @pytest.mark.parametrize(
        ("spdx_id", "policy_kwargs"),
        [
            pytest.param("AGPL-3.0", {}, id="agpl-network-facing-distributed"),
            # Publishing the project does not satisfy SSPL's clause over the whole service stack.
            pytest.param("SSPL-1.0", {"distribution_model": DistributionModel.OPEN_SOURCE}, id="sspl-open-source"),
        ],
    )
    def test_network_copyleft_offered_to_users_stays_critical(self, spdx_id, policy_kwargs):
        result = self._evaluate_with_policy(spdx_id, **policy_kwargs)
        assert result["severity"] == Severity.CRITICAL.value
        assert "severity_without_context" not in result

    @pytest.mark.parametrize(
        ("spdx_id", "baseline"),
        [("GPL-3.0-only", Severity.HIGH), ("AGPL-3.0-only", Severity.CRITICAL), ("SSPL-1.0", Severity.CRITICAL)],
    )
    def test_every_policy_softening_records_the_severity_it_replaced(self, spdx_id, baseline):
        for distribution, deployment, allow_strong, allow_network in itertools.product(
            DistributionModel, DeploymentModel, (False, True), (False, True)
        ):
            result = self._evaluate_with_policy(
                spdx_id,
                distribution_model=distribution,
                deployment_model=deployment,
                allow_strong_copyleft=allow_strong,
                allow_network_copyleft=allow_network,
            )
            softened = get_severity_value(result["severity"]) < get_severity_value(baseline.value)
            recorded = (result.get("severity_without_context"), bool(result.get("context_reason")))
            assert recorded == ((baseline.value, True) if softened else (None, False)), result


class TestSpdxExpressionEvaluation:
    """SPDX OR/AND expression handling."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    @pytest.mark.parametrize(
        "or_groups",
        [
            # MIT is permissive -> no issue, the least restrictive alternative.
            pytest.param([["MIT"], ["GPL-3.0"]], id="permissive-beside-strong-copyleft"),
            pytest.param([["MIT"], ["Apache-2.0"]], id="all-permissive"),
        ],
    )
    def test_an_or_offering_a_permissive_alternative_raises_no_issue(self, or_groups):
        _, issues = self.analyzer._select_or_alternative(_TEST_PKG, or_groups, LicensePolicySchema())
        assert issues == []

    @pytest.mark.parametrize(
        ("policy", "or_groups", "expected"),
        [
            pytest.param(LicensePolicySchema(), [["GPL-3.0"], ["LGPL-3.0"]], [("LGPL-3.0", Severity.INFO)], id="or"),
            pytest.param(LicensePolicySchema(), [["MIT", "GPL-3.0"]], [("GPL-3.0", Severity.HIGH)], id="and"),
            # Under internal_only GPL is INFO and AGPL on a network service MEDIUM, so GPL wins on severity.
            pytest.param(
                LicensePolicySchema(distribution_model=DistributionModel.INTERNAL_ONLY),
                [["GPL-3.0"], ["AGPL-3.0"]],
                [("GPL-3.0", Severity.INFO)],
                id="or-respects-policy",
            ),
        ],
    )
    def test_the_selected_alternative_carries_its_verdicts(self, policy, or_groups, expected):
        _, issues = self.analyzer._select_or_alternative(_TEST_PKG, or_groups, policy)
        assert [(issue["license"], issue["severity"]) for issue in issues] == [
            (lic, sev.value) for lic, sev in expected
        ]


class TestOrResolution:
    """The alternative a dual-licensed component is settled on, and what is reported for it."""

    @staticmethod
    async def _analyze(expression, settings=None):
        components = _parsed_cyclonedx([_library("dual", expression)])
        return await LicenseAnalyzer().analyze({}, settings or {}, parsed_components=components)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("expression", "settings", "expected"),
        [
            pytest.param("LGPL-2.1-only OR MIT", {"library_usage": "unmodified"}, "MIT", id="no-finding-tie"),
            pytest.param("MPL-2.0 OR Apache-2.0", {"library_usage": "unmodified"}, "Apache-2.0", id="weak-first"),
            pytest.param("Apache-2.0 OR MPL-2.0", {"library_usage": "unmodified"}, "Apache-2.0", id="weak-last"),
            pytest.param("CC-BY-NC-4.0 OR GPL-3.0", {}, "GPL-3.0", id="high-tie"),
            pytest.param("GPL-2.0 OR CDDL-1.0", {"distribution_model": "internal_only"}, "CDDL-1.0", id="info-tie"),
            pytest.param("GPL-3.0 OR MIT", {}, "MIT", id="later-and-lower"),
            pytest.param("GPL-2.0 OR GPL-3.0", {}, "GPL-2.0", id="full-tie-keeps-declared-order"),
            pytest.param("GPL-3.0 OR GPL-2.0", {}, "GPL-3.0", id="full-tie-keeps-declared-order-reversed"),
        ],
    )
    async def test_a_severity_tie_goes_to_the_less_restrictive_alternative(self, expression, settings, expected):
        result = await self._analyze(expression, settings)
        assert [entry["license"] for entry in result["component_licenses"]] == [expected]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            pytest.param(
                "(GPL-3.0-only AND CC-BY-NC-4.0) OR AGPL-3.0-only",
                [("GPL-3.0-only", Severity.HIGH), ("CC-BY-NC-4.0", Severity.HIGH)],
                id="equally-severe-members",
            ),
            pytest.param(
                "(MPL-2.0 AND GPL-2.0-only) OR SSPL-1.0",
                [("MPL-2.0", Severity.INFO), ("GPL-2.0-only", Severity.HIGH)],
                id="milder-member",
            ),
        ],
    )
    async def test_every_member_of_the_chosen_conjunction_is_reported(self, expression, expected):
        result = await self._analyze(expression)
        verdicts = [(issue["license"], issue["severity"]) for issue in result["license_issues"]]
        assert verdicts == [(lic, sev.value) for lic, sev in expected]


class TestTransitiveDependencySeverity:
    """Transitive dependency severity adjustment."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def test_transitive_critical_downgraded_to_high(self):
        issue = {"severity": Severity.CRITICAL.value, "category": "network_copyleft"}
        apply_transitive_adjustment(issue, is_transitive=True)
        assert issue["severity"] == Severity.HIGH.value
        assert issue["is_transitive"] is True
        assert "context_reason" in issue

    @pytest.mark.parametrize(
        ("severity", "category", "expected_severity"),
        [
            pytest.param(Severity.HIGH, "strong_copyleft", Severity.MEDIUM, id="high-to-medium"),
            pytest.param(Severity.MEDIUM, "network_copyleft", Severity.LOW, id="medium-to-low"),
            pytest.param(Severity.INFO, "weak_copyleft", Severity.INFO, id="info-stays-info"),
        ],
    )
    def test_a_transitive_finding_is_downgraded_one_step_at_most(self, severity, category, expected_severity):
        issue = {"severity": severity.value, "category": category}
        apply_transitive_adjustment(issue, is_transitive=True)
        assert issue["severity"] == expected_severity.value

    def test_direct_not_affected(self):
        issue = {"severity": Severity.HIGH.value, "category": "strong_copyleft"}
        apply_transitive_adjustment(issue, is_transitive=False)
        assert issue["severity"] == Severity.HIGH.value
        assert "is_transitive" not in issue

    def test_transitive_records_the_severity_without_context(self):
        issue = {"severity": Severity.HIGH.value, "category": "strong_copyleft"}
        apply_transitive_adjustment(issue, is_transitive=True)
        assert issue["severity_without_context"] == Severity.HIGH.value

    @pytest.mark.parametrize(
        ("severity", "is_transitive", "included"),
        [
            pytest.param(Severity.INFO, True, False, id="transitive-info-filtered-out"),
            pytest.param(Severity.LOW, True, False, id="transitive-low-filtered-out"),
            pytest.param(Severity.MEDIUM, True, True, id="transitive-medium-included"),
            pytest.param(Severity.INFO, False, True, id="direct-info-included"),
        ],
    )
    def test_only_a_transitive_finding_below_medium_is_filtered_out(self, severity, is_transitive, included):
        issue = {"severity": severity.value}
        assert should_include_finding(issue, is_transitive=is_transitive) is included


class TestLicenseCompatibility:
    """Cross-component conflicts, judged on the licences the analyzer settled each component on."""

    _GPL_PAIR: ClassVar[list[dict[str, Any]]] = [_library("a", "GPL-2.0-only"), _library("b", "GPL-3.0-only")]

    @staticmethod
    def _conflicts(components, settings=None, transitive_refs=()):
        parsed = _parsed_cyclonedx(components, transitive_refs)
        result = asyncio.run(LicenseAnalyzer().analyze({}, settings or {}, parsed_components=parsed))
        return [issue for issue in result["license_issues"] if issue["category"] == LICENSE_INCOMPATIBILITY_CATEGORY]

    @pytest.mark.parametrize(
        "licences",
        [
            pytest.param(["MIT", "Apache-2.0"], id="permissive-only"),
            pytest.param(["GPL-3.0", "GPL-3.0"], id="same-license-twice"),
            pytest.param(["CDDL-1.0 OR GPL-2.0"], id="dual-licensed-alone"),
            pytest.param(["CDDL-1.0 OR GPL-2.0", "EPL-1.0"], id="optional-gpl-branch-not-taken"),
            pytest.param(["GPL-2.0-only AND GPL-3.0-only"], id="one-component-declaring-both"),
            pytest.param(["GPL-2.0-only WITH Classpath-exception-2.0", "Apache-2.0"], id="linking-exception"),
            pytest.param(["GPL-2.0-only WITH Classpath-exception-2.0", "GPL-3.0-only"], id="linking-exception-gpl3"),
        ],
    )
    def test_components_that_can_ship_together_raise_no_conflict(self, licences):
        assert self._conflicts([_library(f"lib{i}", licence) for i, licence in enumerate(licences)]) == []

    @pytest.mark.parametrize(
        ("licences", "expected"),
        [
            pytest.param(["GPL-2.0 AND GPL-3.0", "CDDL-1.0"], ["CDDL-1.0 / GPL-2.0", "CDDL-1.0 / GPL-3.0"], id="and"),
            pytest.param(["GPL-2.0 OR GPL-3.0", "CDDL-1.0"], ["CDDL-1.0 / GPL-2.0"], id="tied-or-keeps-declared"),
        ],
    )
    def test_the_conflicts_follow_the_settled_licences(self, licences, expected):
        conflicts = self._conflicts([_library(f"lib{i}", licence) for i, licence in enumerate(licences)])
        assert [conflict["license"] for conflict in conflicts] == expected

    def test_the_conflict_check_sees_the_alternative_the_policy_chose(self):
        # Allowed network copyleft is MEDIUM while GPL-2.0-only stays HIGH, so the component is taken under AGPL.
        components = [_library("dual", "GPL-2.0-only OR AGPL-3.0-only"), _library("gpl3-lib", "GPL-3.0-only")]
        assert self._conflicts(components, {"allow_network_copyleft": True}) == []

    def test_one_finding_per_licence_pair_names_every_component(self):
        components = [
            _library("x", "GPL-2.0-only"),
            _library("y", "GPL-3.0-only"),
            _library("z", "GPL-3.0-only"),
            _library("w", "GPL-2.0-only"),
        ]
        [conflict] = self._conflicts(components)
        label = "GPL-2.0-only / GPL-3.0-only"
        assert (conflict["component"], conflict["version"], conflict["license"]) == (label, "", label)
        assert conflict["purl"] == "pkg:npm/w@1.0"
        assert "GPL-2.0-only: w@1.0, x@1.0\nGPL-3.0-only: y@1.0, z@1.0" in conflict["explanation"]

    def test_the_finding_does_not_depend_on_the_sbom_order(self):
        components = [_library("x", "GPL-3.0-only"), _library("y", "GPL-2.0-only"), _library("z", "GPL-3.0-only")]
        assert self._conflicts(components) == self._conflicts(components[::-1])

    @pytest.mark.parametrize(
        ("settings", "severity", "without_context"),
        [
            pytest.param({}, Severity.HIGH, None, id="distributed"),
            pytest.param({"distribution_model": "open_source"}, Severity.HIGH, None, id="open-source"),
            pytest.param({"allow_strong_copyleft": True}, Severity.HIGH, None, id="allowed-copyleft-still-conflicts"),
            pytest.param({"distribution_model": "internal_only"}, Severity.INFO, Severity.HIGH, id="internal-only"),
        ],
    )
    def test_the_conflict_severity_follows_the_distribution_model(self, settings, severity, without_context):
        [conflict] = self._conflicts(self._GPL_PAIR, settings)
        expected_without_context = without_context.value if without_context else None
        assert (conflict["severity"], conflict.get("severity_without_context")) == (
            severity.value,
            expected_without_context,
        )
        assert ("context_reason" in conflict) == (without_context is not None)

    def test_a_conflict_between_transitive_dependencies_is_downgraded(self):
        [conflict] = self._conflicts(self._GPL_PAIR, transitive_refs=("a", "b"))
        assert (conflict["severity"], conflict["severity_without_context"], conflict["is_transitive"]) == (
            Severity.MEDIUM.value,
            Severity.HIGH.value,
            True,
        )

    def test_a_conflict_involving_a_direct_dependency_keeps_its_severity(self):
        [conflict] = self._conflicts(self._GPL_PAIR, transitive_refs=("a",))
        assert conflict["severity"] == Severity.HIGH.value
        assert "is_transitive" not in conflict

    def test_an_ignored_transitive_dependency_takes_no_part(self):
        assert self._conflicts(self._GPL_PAIR, {"ignore_transitive": True}, transitive_refs=("a",)) == []


class TestIncompatibilityTable:
    @staticmethod
    def _conflicts(*licences: str) -> list[str]:
        components = _parsed_cyclonedx(
            [
                {"type": "library", "name": f"lib{i}", "version": "1.0", "licenses": [{"expression": licence}]}
                for i, licence in enumerate(licences)
            ]
        )
        result = asyncio.run(LicenseAnalyzer().analyze({}, parsed_components=components))
        return [i["license"] for i in result["license_issues"] if i["category"] == LICENSE_INCOMPATIBILITY_CATEGORY]

    @pytest.mark.parametrize(
        ("first", "second"),
        [
            ("EPL-1.0", "GPL-3.0-only"),
            ("GPL-3.0-only", "SSPL-1.0"),
            ("GPL-2.0-or-later", "SSPL-1.0"),
            ("CDDL-1.0", "GPL-2.0-or-later"),
            ("CDDL-1.1", "GPL-3.0-or-later"),
            ("GPL-2.0-only", "GPL-3.0-or-later"),
            ("AGPL-3.0-or-later", "GPL-2.0-only"),
            ("GPL-2.0", "GPL-3.0-only"),
            ("GPL-2.0", "GPL-3.0"),
            ("AGPL-3.0", "GPL-2.0"),
            ("CDDL-1.0", "GPL-2.0"),
            ("Apache-2.0", "GPL-2.0-only"),
            ("Apache-2.0", "GPL-2.0"),
        ],
    )
    def test_every_spelling_of_an_incompatible_pair_conflicts(self, first, second):
        assert self._conflicts(first, second) == [f"{first} / {second}"]

    @pytest.mark.parametrize("other", ["GPL-3.0-only", "Apache-2.0"])
    def test_gpl_2_or_later_combines_through_gpl_3(self, other):
        assert self._conflicts("GPL-2.0-or-later", other) == []


class TestTransitiveDirectness:
    """End-to-end analyze() directness detection via the top-level `direct` field."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def _gpl_component(self, name, *, direct):
        """A GPL-3.0 component in ParsedDependency.to_dict() shape."""
        return {
            "name": name,
            "version": "1.0.0",
            "purl": f"pkg:pypi/{name}@1.0.0",
            "license": "GPL-3.0",
            "scope": "runtime",
            "direct": direct,
            "properties": {},  # Dict[str,str], never contains 'direct'.
        }

    @pytest.mark.asyncio
    async def test_ignore_transitive_skips_transitive_dep(self):
        components = [self._gpl_component("trans-gpl", direct=False)]
        result = await self.analyzer.analyze(
            sbom={},
            settings={"ignore_transitive": True},
            parsed_components=components,
        )
        assert result["license_issues"] == []
        assert result["summary"]["skipped"] == 1

    @pytest.mark.asyncio
    async def test_ignore_transitive_keeps_direct_dep(self):
        components = [self._gpl_component("direct-gpl", direct=True)]
        result = await self.analyzer.analyze(
            sbom={},
            settings={"ignore_transitive": True},
            parsed_components=components,
        )
        issues = result["license_issues"]
        assert len(issues) == 1
        assert issues[0]["severity"] == Severity.HIGH.value
        assert result["summary"]["skipped"] == 0

    @pytest.mark.asyncio
    async def test_transitive_dep_severity_downgraded(self):
        components = [self._gpl_component("trans-gpl", direct=False)]
        result = await self.analyzer.analyze(
            sbom={},
            settings={"ignore_transitive": False},
            parsed_components=components,
        )
        issues = result["license_issues"]
        assert len(issues) == 1
        assert issues[0]["is_transitive"] is True
        assert issues[0]["severity"] == Severity.MEDIUM.value
        assert issues[0]["severity_without_context"] == Severity.HIGH.value

    @pytest.mark.asyncio
    async def test_a_transitive_agpl_in_a_distributed_desktop_product_is_reported(self):
        components = _parsed_cyclonedx(
            [
                {
                    "type": "library",
                    "bom-ref": "agpl-lib",
                    "name": "agpl-lib",
                    "version": "1.0",
                    "licenses": [{"license": {"id": "AGPL-3.0-only"}}],
                }
            ],
            transitive_refs=("agpl-lib",),
        )
        result = await self.analyzer.analyze({}, {"deployment_model": "desktop"}, parsed_components=components)
        verdicts = [(i["component"], i["severity"], i["severity_without_context"]) for i in result["license_issues"]]
        assert verdicts == [("agpl-lib", Severity.MEDIUM.value, Severity.CRITICAL.value)]

    @pytest.mark.asyncio
    async def test_direct_dep_not_downgraded(self):
        components = [self._gpl_component("direct-gpl", direct=True)]
        result = await self.analyzer.analyze(
            sbom={},
            settings={"ignore_transitive": False},
            parsed_components=components,
        )
        issues = result["license_issues"]
        assert len(issues) == 1
        assert issues[0]["severity"] == Severity.HIGH.value
        assert "is_transitive" not in issues[0]


class TestIgnoredScopes:
    """Which dependency scopes `ignore_dev_dependencies` takes out of the licence verdict."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def _gpl_component(self, scope):
        return {
            "name": f"{scope}-gpl",
            "version": "1.0.0",
            "purl": f"pkg:pypi/{scope}-gpl@1.0.0",
            "license": "GPL-3.0",
            "scope": scope,
            "direct": True,
        }

    @pytest.mark.asyncio
    @pytest.mark.parametrize("scope", sorted(NON_RUNTIME_SCOPES))
    async def test_non_shipped_scope_is_skipped(self, scope):
        result = await self.analyzer.analyze(sbom={}, settings={}, parsed_components=[self._gpl_component(scope)])
        assert result["license_issues"] == []
        assert result["summary"]["skipped"] == 1
        assert result["summary"]["strong_copyleft"] == 0

    @pytest.mark.asyncio
    async def test_runtime_scope_is_still_evaluated(self):
        result = await self.analyzer.analyze(sbom={}, settings={}, parsed_components=[self._gpl_component("required")])
        assert result["summary"]["skipped"] == 0
        assert len(result["license_issues"]) == 1

    @pytest.mark.asyncio
    async def test_an_excluded_component_takes_no_part_in_a_licence_conflict(self):
        """CycloneDX 'excluded' is test and build tooling, so its GPL-2.0 cannot conflict with shipped GPL-3.0."""
        components = _parsed_cyclonedx(
            [
                {
                    "type": "library",
                    "name": "gpl2-test-tool",
                    "version": "1.0",
                    "scope": "excluded",
                    "purl": "pkg:npm/gpl2-test-tool@1.0",
                    "licenses": [{"license": {"id": "GPL-2.0-only"}}],
                },
                {
                    "type": "library",
                    "name": "gpl3-lib",
                    "version": "1.0",
                    "scope": "required",
                    "purl": "pkg:npm/gpl3-lib@1.0",
                    "licenses": [{"license": {"id": "GPL-3.0-only"}}],
                },
            ]
        )

        result = await self.analyzer.analyze(sbom={}, settings={}, parsed_components=components)

        assert [issue["component"] for issue in result["license_issues"]] == ["gpl3-lib"]

    @pytest.mark.asyncio
    async def test_an_npm_development_marker_without_a_scope_is_skipped(self):
        components = _parsed_cyclonedx(
            [
                {
                    "type": "library",
                    "name": "gpl-dev-tool",
                    "version": "1.0",
                    "purl": "pkg:npm/gpl-dev-tool@1.0",
                    "licenses": [{"license": {"id": "GPL-3.0-only"}}],
                    "properties": [{"name": "cdx:npm:package:development", "value": "true"}],
                }
            ]
        )

        result = await self.analyzer.analyze(sbom={}, settings={}, parsed_components=components)

        assert (result["license_issues"], result["summary"]["skipped"]) == ([], 1)

    @pytest.mark.asyncio
    async def test_the_operating_system_descriptor_is_not_a_licensed_dependency(self):
        components = _parsed_cyclonedx(
            [
                {"type": "operating-system", "name": "debian", "version": "12"},
                {
                    "type": "library",
                    "name": "libc6",
                    "version": "2.36",
                    "purl": "pkg:deb/debian/libc6@2.36",
                    "licenses": [{"license": {"id": "MIT"}}],
                },
            ]
        )

        result = await self.analyzer.analyze(sbom={}, settings={}, parsed_components=components)

        assert result["license_issues"] == []
        assert (result["summary"]["skipped"], result["summary"]["unknown"]) == (1, 0)


class TestStoredPolicy:
    """The analyzer grades against the policy stored in analyzer_settings, read the way the write validator stores it."""

    _GPL: ClassVar[dict[str, Any]] = {
        "name": "gpl-lib",
        "version": "1.0",
        "purl": "pkg:pypi/gpl-lib@1.0",
        "license": "GPL-3.0",
        "direct": True,
    }

    async def _severities(self, settings):
        result = await LicenseAnalyzer().analyze(sbom={}, settings=settings, parsed_components=[self._GPL])
        return [issue["severity"] for issue in result["license_issues"]]

    @pytest.mark.asyncio
    async def test_a_legacy_string_false_does_not_allow_strong_copyleft(self):
        assert await self._severities({"allow_strong_copyleft": "false"}) == [Severity.HIGH.value]

    @pytest.mark.asyncio
    async def test_the_flat_policy_decides_the_verdict(self):
        assert await self._severities({"distribution_model": "internal_only"}) == [Severity.INFO.value]


_UNREADABLE_ALTERNATIVE = "Acme-1.0"
_UNREADABLE_OR_EXPRESSION = f"{_UNREADABLE_ALTERNATIVE} OR Widget-2.0"
_READABLE_OR_EXPRESSION = "MIT OR Apache-2.0"
# An OR expression settles on one alternative, so one component contributes one count.
_ONE_ALTERNATIVE_RESOLVED = 1


class TestUndeterminableLicense:
    """A component the SBOM does not let us classify must reach the audit control as a finding."""

    UNDETERMINABLE_SHAPES: ClassVar[list[dict[str, Any]]] = [
        {"type": "library", "name": "no-licenses-key", "version": "1.0.0"},
        {"type": "library", "name": "empty-licenses-list", "version": "1.0.0", "licenses": []},
        {
            "type": "library",
            "name": "noassertion-lib",
            "version": "1.0.0",
            "licenses": [{"license": {"id": "NOASSERTION"}}],
        },
        {
            "type": "library",
            "name": "see-license-file",
            "version": "1.0.0",
            "licenses": [{"license": {"name": "SEE LICENSE IN LICENSE.txt"}}],
        },
        {
            "type": "library",
            "name": "custom-eula-lib",
            "version": "1.0.0",
            "licenses": [{"license": {"name": "Acme Custom EULA 1.0"}}],
        },
    ]

    @staticmethod
    async def _run(components):
        return await LicenseAnalyzer().analyze({}, parsed_components=_parsed_cyclonedx(components))

    @staticmethod
    def _unknown_issues(result):
        return [i for i in result["license_issues"] if i["category"] == LicenseCategory.UNKNOWN.value]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("component", UNDETERMINABLE_SHAPES, ids=lambda c: c["name"])
    async def test_each_undeterminable_shape_emits_one_finding(self, component):
        result = await self._run([component])
        issues = self._unknown_issues(result)
        assert len(issues) == 1
        assert issues[0]["component"] == component["name"]

    @pytest.mark.asyncio
    async def test_unknown_count_and_emitted_findings_agree(self):
        result = await self._run(self.UNDETERMINABLE_SHAPES)
        assert result["summary"]["unknown"] == len(self.UNDETERMINABLE_SHAPES)
        assert len(self._unknown_issues(result)) == len(self.UNDETERMINABLE_SHAPES)

    @pytest.mark.asyncio
    async def test_finding_is_informational_so_it_moves_no_risk_score(self):
        result = await self._run([self.UNDETERMINABLE_SHAPES[0]])
        assert self._unknown_issues(result)[0]["severity"] == Severity.INFO.value

    @pytest.mark.asyncio
    async def test_transitive_component_still_emits_the_finding(self):
        component = {**self.UNDETERMINABLE_SHAPES[0], "direct": False}
        result = await LicenseAnalyzer().analyze(
            {},
            settings={"ignore_transitive": False},
            parsed_components=[{"name": component["name"], "version": "1.0.0", "direct": False}],
        )
        assert len(self._unknown_issues(result)) == 1

    @pytest.mark.asyncio
    async def test_recognised_license_emits_no_undeterminable_finding(self):
        component = {"type": "library", "name": "mit-lib", "version": "1.0.0", "licenses": [{"license": {"id": "MIT"}}]}
        result = await self._run([component])
        assert result["summary"]["unknown"] == 0
        assert self._unknown_issues(result) == []

    @pytest.mark.asyncio
    async def test_unrecognised_name_is_quoted_in_the_explanation(self):
        result = await self._run([self.UNDETERMINABLE_SHAPES[4]])
        assert "Acme Custom EULA 1.0" in self._unknown_issues(result)[0]["explanation"]

    @pytest.mark.asyncio
    async def test_an_unreadable_spdx_expression_is_undeterminable_too(self):
        """The OR-expression path resolves an alternative before classifying it, so an expression
        naming nothing we know reached neither the unknown count nor a finding."""
        component = {
            "type": "library",
            "name": "expression-lib",
            "version": "1.0.0",
            "licenses": [{"expression": _UNREADABLE_OR_EXPRESSION}],
        }

        result = await self._run([component])

        assert result["summary"]["unknown"] == _ONE_ALTERNATIVE_RESOLVED
        issues = self._unknown_issues(result)
        assert len(issues) == 1
        assert issues[0]["severity"] == Severity.INFO.value
        assert _UNREADABLE_ALTERNATIVE in issues[0]["explanation"]

    @pytest.mark.asyncio
    async def test_a_readable_spdx_expression_stays_determinable(self):
        component = {
            "type": "library",
            "name": "dual-licensed",
            "version": "1.0.0",
            "licenses": [{"expression": _READABLE_OR_EXPRESSION}],
        }

        result = await self._run([component])

        assert result["summary"]["unknown"] == 0
        assert self._unknown_issues(result) == []


_PERMISSIVE_ID = "MIT"
_STRONG_COPYLEFT_ID = "GPL-3.0-only"
_CONFLICTING_ID = "CDDL-1.0"
_UNREADABLE_OR_COPYLEFT = f"{_UNREADABLE_ALTERNATIVE} OR {_STRONG_COPYLEFT_ID}"
_UNREADABLE_OR_PERMISSIVE = f"{_UNREADABLE_ALTERNATIVE} OR {_PERMISSIVE_ID}"
_UNREADABLE_CONJUNCT_OR_COPYLEFT = f"({_PERMISSIVE_ID} AND {_UNREADABLE_ALTERNATIVE}) OR {_STRONG_COPYLEFT_ID}"
_CONJUNCTION_WITH_UNREADABLE = f"{_PERMISSIVE_ID} AND {_UNREADABLE_ALTERNATIVE}"
_NO_FINDINGS = 0
_ONE_FINDING = 1


class TestUnreadableOrAlternative:
    """An alternative we cannot read is not a choice we can rank, so it must not shadow one we can."""

    @staticmethod
    async def _analyze(expression, settings=None):
        component = {
            "type": "library",
            "name": "dual-licensed",
            "version": "1.0.0",
            "purl": "pkg:pypi/dual-licensed@1.0.0",
            "licenses": [{"expression": expression}],
        }
        return await LicenseAnalyzer().analyze({}, settings or {}, parsed_components=_parsed_cyclonedx([component]))

    @staticmethod
    def _by_category(result, category):
        return [issue for issue in result["license_issues"] if issue["category"] == category]

    @pytest.mark.asyncio
    async def test_unreadable_alternative_no_longer_shadows_a_permissive_one(self):
        result = await self._analyze(_UNREADABLE_OR_PERMISSIVE)

        assert self._by_category(result, LicenseCategory.UNKNOWN.value) == []
        assert result["summary"]["permissive"] == _ONE_ALTERNATIVE_RESOLVED
        assert [entry["license"] for entry in result["component_licenses"]] == [_PERMISSIVE_ID]

    @pytest.mark.asyncio
    async def test_unreadable_beside_an_unacceptable_licence_is_undeterminable(self):
        result = await self._analyze(_UNREADABLE_OR_COPYLEFT)

        assert self._by_category(result, LicenseCategory.STRONG_COPYLEFT.value) == []
        undeterminable = self._by_category(result, LicenseCategory.UNKNOWN.value)
        assert len(undeterminable) == _ONE_FINDING
        assert undeterminable[0]["severity"] == Severity.INFO.value

    @pytest.mark.asyncio
    async def test_the_undeterminable_verdict_names_the_alternative_it_rejected(self):
        result = await self._analyze(_UNREADABLE_OR_COPYLEFT)

        explanation = self._by_category(result, LicenseCategory.UNKNOWN.value)[0]["explanation"]
        assert _UNREADABLE_ALTERNATIVE in explanation
        assert _STRONG_COPYLEFT_ID in explanation

    @pytest.mark.asyncio
    async def test_an_acceptable_known_alternative_settles_the_licence(self):
        result = await self._analyze(_UNREADABLE_OR_COPYLEFT, {"allow_strong_copyleft": True})

        assert self._by_category(result, LicenseCategory.UNKNOWN.value) == []
        allowed = self._by_category(result, LicenseCategory.STRONG_COPYLEFT.value)
        assert len(allowed) == _ONE_FINDING
        assert allowed[0]["license"] == _STRONG_COPYLEFT_ID
        assert result["summary"]["strong_copyleft"] == _ONE_ALTERNATIVE_RESOLVED

    @pytest.mark.asyncio
    async def test_an_unreadable_conjunct_disqualifies_its_whole_alternative(self):
        result = await self._analyze(_UNREADABLE_CONJUNCT_OR_COPYLEFT)

        assert result["component_licenses"] == []
        assert len(self._by_category(result, LicenseCategory.UNKNOWN.value)) == _ONE_FINDING

    @pytest.mark.asyncio
    async def test_a_conjunction_reports_every_term_that_binds(self):
        """AND offers no choice, so the readable term is classified and the unreadable one is disclosed."""
        result = await self._analyze(_CONJUNCTION_WITH_UNREADABLE)

        assert [entry["license"] for entry in result["component_licenses"]] == [_PERMISSIVE_ID]
        assert len(self._by_category(result, LicenseCategory.UNKNOWN.value)) == _ONE_FINDING

    @pytest.mark.asyncio
    async def test_an_unsettled_expression_takes_no_part_in_the_conflict_check(self):
        components = [
            {
                "type": "library",
                "name": "dual-licensed",
                "version": "1.0.0",
                "purl": "pkg:pypi/dual-licensed@1.0.0",
                "licenses": [{"expression": _UNREADABLE_OR_COPYLEFT}],
            },
            {
                "type": "library",
                "name": "cddl-lib",
                "version": "1.0.0",
                "purl": "pkg:pypi/cddl-lib@1.0.0",
                "licenses": [{"license": {"id": _CONFLICTING_ID}}],
            },
        ]

        result = await LicenseAnalyzer().analyze({}, parsed_components=_parsed_cyclonedx(components))

        assert self._by_category(result, LICENSE_INCOMPATIBILITY_CATEGORY) == []


class TestPolicyAcceptability:
    """The line between a licence a consumer could take and one policy refuses."""

    def test_no_finding_is_acceptable(self):
        assert is_acceptable_under_policy(None) is True

    @pytest.mark.parametrize("severity", [Severity.INFO, Severity.LOW, Severity.MEDIUM])
    def test_a_softened_verdict_is_acceptable(self, severity):
        assert is_acceptable_under_policy({"severity": severity.value}) is True

    @pytest.mark.parametrize("severity", [Severity.HIGH, Severity.CRITICAL])
    def test_an_unsoftened_verdict_is_not_acceptable(self, severity):
        assert is_acceptable_under_policy({"severity": severity.value}) is False


class TestPartitionOrGroups:
    """Splitting OR-alternatives into the readable ones and what made the rest unreadable."""

    def test_a_group_with_an_unreadable_member_is_not_readable(self):
        readable, unreadable = partition_or_groups([[_PERMISSIVE_ID, _UNREADABLE_ALTERNATIVE], [_STRONG_COPYLEFT_ID]])
        assert readable == [[_STRONG_COPYLEFT_ID]]
        assert unreadable == [_UNREADABLE_ALTERNATIVE]

    def test_an_identifier_is_reported_once_across_alternatives(self):
        readable, unreadable = partition_or_groups([[_UNREADABLE_ALTERNATIVE], [_UNREADABLE_ALTERNATIVE]])
        assert readable == []
        assert len(unreadable) == _ONE_FINDING

    def test_the_readable_alternatives_come_back_as_database_ids(self):
        readable, _ = partition_or_groups([["GPL-2.0-only WITH Classpath-exception-2.0", "GPL-2.0-only"]])
        assert readable == [["GPL-2.0-only"]]

    def test_all_readable_leaves_nothing_unreadable(self):
        readable, unreadable = partition_or_groups([[_PERMISSIVE_ID], [_STRONG_COPYLEFT_ID]])
        assert readable == [[_PERMISSIVE_ID], [_STRONG_COPYLEFT_ID]]
        assert len(unreadable) == _NO_FINDINGS
