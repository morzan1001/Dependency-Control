"""Tests for the LicenseAnalyzer - license compliance analysis."""

import time
from typing import Any, ClassVar

import pytest

from app.models.finding import Severity
from app.models.license import (
    DeploymentModel,
    DistributionModel,
    LibraryUsage,
    LicenseCategory,
    LicensePolicy,
)
from app.services.analyzers.license_compliance import LicenseAnalyzer
from app.services.analyzers.license_compliance.compatibility import (
    check_license_compatibility,
    partition_or_groups,
)
from app.services.analyzers.license_compliance.evaluator import (
    apply_transitive_adjustment,
    evaluate_license,
    is_acceptable_under_policy,
    should_include_finding,
)
from app.services.analyzers.license_compliance.normalizer import (
    extract_licenses,
    normalize_license,
    parse_spdx_expression,
)


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
        ],
    )
    def test_normalizes_to_the_canonical_spdx_id(self, raw, expected):
        assert normalize_license(raw) == expected


class TestExtractLicenses:
    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    @pytest.mark.parametrize(
        ("component", "expected"),
        [
            pytest.param(
                {"licenses": [{"license": {"id": "MIT", "url": "https://spdx.org/licenses/MIT"}}]},
                ("MIT", "https://spdx.org/licenses/MIT"),
                id="cyclonedx-license-id",
            ),
            pytest.param(
                {"license": "MIT", "license_url": "https://example.com/MIT"},
                ("MIT", "https://example.com/MIT"),
                id="direct-license-field",
            ),
        ],
    )
    def test_a_lone_licence_is_extracted_with_its_url(self, component, expected):
        result = extract_licenses(component)
        assert len(result) == 1
        assert result[0] == expected

    def test_cyclonedx_license_name_fallback(self):
        component = {"licenses": [{"license": {"name": "Apache-2.0"}}]}
        result = extract_licenses(component)
        assert len(result) == 1
        assert result[0][0] == "Apache-2.0"

    def test_cyclonedx_multiple_licenses(self):
        component = {
            "licenses": [
                {"license": {"id": "MIT"}},
                {"license": {"id": "Apache-2.0"}},
            ]
        }
        result = extract_licenses(component)
        assert len(result) == 2

    @pytest.mark.parametrize(
        ("component", "expected_ids"),
        [
            pytest.param(
                {"licenses": [{"expression": "MIT OR Apache-2.0"}]}, ("MIT", "Apache-2.0"), id="expression-or"
            ),
            pytest.param(
                {"licenses": [{"expression": "MIT AND BSD-3-Clause"}]}, ("MIT", "BSD-3-Clause"), id="expression-and"
            ),
            pytest.param(
                {"licenses": [{"expression": "(MIT OR Apache-2.0)"}]},
                ("MIT", "Apache-2.0"),
                id="expression-parenthesised",
            ),
            pytest.param({"license": "MIT, Apache-2.0"}, ("MIT", "Apache-2.0"), id="direct-comma-separated"),
            pytest.param({"license": "MIT OR Apache-2.0"}, ("MIT", "Apache-2.0"), id="direct-expression"),
            pytest.param(
                {"licenses": [{"license": {"id": "MIT"}}], "license": "Apache-2.0"},
                ("MIT", "Apache-2.0"),
                id="cyclonedx-and-direct-combined",
            ),
        ],
    )
    def test_every_licence_the_component_names_is_extracted(self, component, expected_ids):
        ids = [r[0] for r in extract_licenses(component)]
        for expected in expected_ids:
            assert expected in ids

    @pytest.mark.parametrize(
        "component",
        [
            pytest.param({"licenses": [{"license": {"id": "NOASSERTION"}}]}, id="cyclonedx-noassertion"),
            pytest.param({"licenses": [{"license": {"id": "UNKNOWN"}}]}, id="cyclonedx-unknown"),
            pytest.param({"licenses": [{"expression": "NOASSERTION"}]}, id="expression-noassertion"),
            pytest.param({"license": "NOASSERTION"}, id="direct-noassertion"),
            pytest.param({"licenses": []}, id="empty-licenses-list"),
            pytest.param({"name": "some-package"}, id="no-licenses-key"),
            pytest.param({"license": None}, id="direct-license-none"),
            pytest.param({"license": "   "}, id="direct-license-blank"),
        ],
    )
    def test_a_component_naming_no_licence_extracts_nothing(self, component):
        assert extract_licenses(component) == []


class TestEvaluateLicense:
    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def _get_license_info(self, spdx_id):
        return self.analyzer.LICENSE_DATABASE[spdx_id]

    def _evaluate(self, spdx_id, allow_strong=False, allow_network=False):
        info = self._get_license_info(spdx_id)
        policy = LicensePolicy(
            allow_strong_copyleft=allow_strong,
            allow_network_copyleft=allow_network,
        )
        return evaluate_license(
            component="test-pkg",
            version="1.0.0",
            license_info=info,
            lic_url=None,
            purl="pkg:pypi/test-pkg@1.0.0",
            policy=policy,
        )

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
        ("spdx_id", "compatible"),
        [
            pytest.param("MIT", True, id="mit"),
            pytest.param("GPL-3.0", False, id="gpl3"),
        ],
    )
    def test_proprietary_compatibility_is_recorded(self, spdx_id, compatible):
        assert self.db[spdx_id].compatible_with_proprietary is compatible


class TestEvaluateLicenseWithContext:
    """Context-aware license evaluation driven by LicensePolicy."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def _get_license_info(self, spdx_id):
        return self.analyzer.LICENSE_DATABASE[spdx_id]

    def _evaluate_with_policy(self, spdx_id, **policy_kwargs):
        info = self._get_license_info(spdx_id)
        policy = LicensePolicy(**policy_kwargs)
        return evaluate_license(
            component="test-pkg",
            version="1.0.0",
            license_info=info,
            lic_url=None,
            purl="pkg:pypi/test-pkg@1.0.0",
            policy=policy,
        )

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
        "distribution_model",
        [
            pytest.param(DistributionModel.INTERNAL_ONLY, id="internal-only"),
            pytest.param(DistributionModel.OPEN_SOURCE, id="open-source"),
        ],
    )
    def test_strong_copyleft_without_proprietary_distribution_is_softened_to_info(self, distribution_model):
        result = self._evaluate_with_policy("GPL-3.0", distribution_model=distribution_model)
        assert result is not None
        assert result["severity"] == Severity.INFO.value
        assert result["context_reason"] is not None
        assert result["effective_severity"] == Severity.HIGH.value

    @pytest.mark.parametrize(
        ("allow_strong_copyleft", "expected_severity"),
        [
            pytest.param(False, Severity.HIGH, id="not-allowed"),
            pytest.param(True, Severity.INFO, id="allowed"),
        ],
    )
    def test_strong_copyleft_distributed_follows_the_policy(self, allow_strong_copyleft, expected_severity):
        result = self._evaluate_with_policy(
            "GPL-3.0",
            distribution_model=DistributionModel.DISTRIBUTED,
            allow_strong_copyleft=allow_strong_copyleft,
        )
        assert result is not None
        assert result["severity"] == expected_severity.value

    # --- Network Copyleft + deployment_model ---

    @pytest.mark.parametrize(
        ("policy_kwargs", "expected_severity"),
        [
            pytest.param(
                {"deployment_model": DeploymentModel.CLI_BATCH},
                Severity.LOW,
                id="cli-batch",
            ),
            pytest.param(
                {
                    "deployment_model": DeploymentModel.NETWORK_FACING,
                    "distribution_model": DistributionModel.INTERNAL_ONLY,
                },
                Severity.MEDIUM,
                id="network-facing-internal-only",
            ),
        ],
    )
    def test_network_copyleft_out_of_reach_of_users_is_softened(self, policy_kwargs, expected_severity):
        result = self._evaluate_with_policy("AGPL-3.0", **policy_kwargs)
        assert result is not None
        assert result["severity"] == expected_severity.value
        assert result["context_reason"] is not None
        assert result["effective_severity"] == Severity.CRITICAL.value

    @pytest.mark.parametrize(
        ("policy_kwargs", "expected_severity"),
        [
            pytest.param({"deployment_model": DeploymentModel.DESKTOP}, Severity.LOW, id="desktop"),
            pytest.param({"deployment_model": DeploymentModel.EMBEDDED}, Severity.LOW, id="embedded"),
            pytest.param(
                {
                    "deployment_model": DeploymentModel.NETWORK_FACING,
                    "distribution_model": DistributionModel.DISTRIBUTED,
                    "allow_network_copyleft": False,
                },
                Severity.CRITICAL,
                id="network-facing-distributed-not-allowed",
            ),
            pytest.param(
                {"deployment_model": DeploymentModel.NETWORK_FACING, "allow_network_copyleft": True},
                Severity.MEDIUM,
                id="network-facing-allowed",
            ),
        ],
    )
    def test_network_copyleft_severity_follows_the_deployment(self, policy_kwargs, expected_severity):
        result = self._evaluate_with_policy("AGPL-3.0", **policy_kwargs)
        assert result is not None
        assert result["severity"] == expected_severity.value

    # --- context_reason and effective_severity fields ---

    @pytest.mark.parametrize("field", ["context_reason", "effective_severity"])
    def test_the_context_fields_are_absent_when_not_adjusted(self, field):
        result = self._evaluate_with_policy("GPL-3.0")
        assert field not in result

    def test_context_fields_present_when_adjusted(self):
        result = self._evaluate_with_policy("GPL-3.0", distribution_model=DistributionModel.INTERNAL_ONLY)
        assert "context_reason" in result
        assert "effective_severity" in result
        assert result["effective_severity"] == Severity.HIGH.value


class TestSpdxExpressionEvaluation:
    """SPDX OR/AND expression handling."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            pytest.param("MIT OR Apache-2.0", [["MIT"], ["Apache-2.0"]], id="or"),
            pytest.param("GPL-2.0 AND Classpath", [["GPL-2.0", "Classpath"]], id="and"),
            # WITH clauses are stripped: they modify but don't add licenses.
            pytest.param("GPL-2.0 WITH Classpath-exception-2.0", [["GPL-2.0"]], id="with-exception"),
            pytest.param("MIT", [["MIT"]], id="single-license"),
        ],
    )
    def test_the_expression_parses_into_its_alternatives(self, expression, expected):
        assert parse_spdx_expression(expression) == expected

    def test_parse_mixed_or_and(self):
        result = parse_spdx_expression("MIT OR GPL-2.0 AND Classpath")
        assert len(result) == 2
        assert ["MIT"] in result

    def test_long_whitespace_run_between_tokens_still_splits(self):
        """Whitespace is not a separator budget: an operator stays an operator however far it sits."""
        expr = "MIT" + " " * 5000 + "OR" + " " * 5000 + "Apache-2.0"
        assert parse_spdx_expression(expr) == [["MIT"], ["Apache-2.0"]]

    def test_whitespace_run_parses_without_superlinear_backtracking(self):
        """A run of spaces matching no operator must cost linear time, not quadratic.

        Every SPDX pattern starts with a repeated whitespace class, so without pruning the
        doomed start positions one 50 KB component licence burns ~10 s of CPU on a stage no
        deadline can interrupt.
        """
        expr = "MIT" + " " * 50_000 + "Apache-2.0"
        started = time.perf_counter()
        result = parse_spdx_expression(expr)
        assert time.perf_counter() - started < 1.0
        assert result == [["MIT" + " " * 50_000 + "Apache-2.0"]]

    def test_expression_scan_without_superlinear_backtracking(self):
        """The same pruning has to hold for the AND|OR|WITH scan extract_licenses runs."""
        component = {"licenses": [{"expression": "MIT" + " " * 50_000 + "Apache-2.0"}]}
        started = time.perf_counter()
        licenses = extract_licenses(component)
        assert time.perf_counter() - started < 1.0
        assert licenses == [("MIT" + " " * 50_000 + "Apache-2.0", None)]

    @pytest.mark.parametrize(
        "or_groups",
        [
            # MIT is permissive -> no issue, the least restrictive alternative.
            pytest.param([["MIT"], ["GPL-3.0"]], id="permissive-beside-strong-copyleft"),
            pytest.param([["MIT"], ["Apache-2.0"]], id="all-permissive"),
        ],
    )
    def test_an_or_offering_a_permissive_alternative_raises_no_issue(self, or_groups):
        policy = LicensePolicy()
        _, result = self.analyzer._select_or_alternative(
            "test-pkg", "1.0.0", "pkg:pypi/test-pkg@1.0.0", or_groups, policy
        )
        assert result is None

    def test_evaluate_or_gpl_or_lgpl_picks_lgpl(self):
        policy = LicensePolicy()
        or_groups = [["GPL-3.0"], ["LGPL-3.0"]]
        _, result = self.analyzer._select_or_alternative(
            "test-pkg", "1.0.0", "pkg:pypi/test-pkg@1.0.0", or_groups, policy
        )
        assert result is not None
        assert result["severity"] == Severity.INFO.value
        assert result["license"] == "LGPL-3.0"

    @pytest.mark.parametrize(
        ("policy", "or_groups", "expected_severity"),
        [
            pytest.param(LicensePolicy(), [["MIT", "GPL-3.0"]], Severity.HIGH, id="and-picks-most-restrictive"),
            # Both become INFO with internal_only, but GPL is evaluated first.
            pytest.param(
                LicensePolicy(distribution_model=DistributionModel.INTERNAL_ONLY),
                [["GPL-3.0"], ["AGPL-3.0"]],
                Severity.INFO,
                id="or-respects-policy",
            ),
        ],
    )
    def test_the_selected_alternative_carries_its_severity(self, policy, or_groups, expected_severity):
        _, result = self.analyzer._select_or_alternative(
            "test-pkg", "1.0.0", "pkg:pypi/test-pkg@1.0.0", or_groups, policy
        )
        assert result is not None
        assert result["severity"] == expected_severity.value


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

    def test_transitive_preserves_effective_severity(self):
        issue = {"severity": Severity.HIGH.value, "category": "strong_copyleft"}
        apply_transitive_adjustment(issue, is_transitive=True)
        assert issue["effective_severity"] == Severity.HIGH.value

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
    """Cross-dependency license compatibility checking."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def _make_component(self, name, version, license_id, scope="runtime"):
        return {
            "name": name,
            "version": version,
            "licenses": [{"license": {"id": license_id}}],
            "scope": scope,
            "purl": f"pkg:pypi/{name}@{version}",
        }

    @pytest.mark.parametrize(
        "specs",
        [
            pytest.param([("a", "1.0", "MIT"), ("b", "1.0", "Apache-2.0")], id="permissive-only"),
            pytest.param(
                [("a", "1.0", "GPL-2.0-only"), ("b", "1.0", "GPL-3.0-only", "dev")],
                id="incompatible-pair-in-dev-scope",
            ),
            pytest.param([("a", "1.0", "GPL-3.0"), ("b", "1.0", "GPL-3.0")], id="same-license-twice"),
        ],
    )
    def test_components_that_can_ship_together_raise_no_conflict(self, specs):
        components = [self._make_component(*spec) for spec in specs]
        issues = check_license_compatibility(components, ignore_dev=True)
        assert len(issues) == 0

    def test_gpl2_only_vs_gpl3_only_conflict(self):
        components = [
            self._make_component("a", "1.0", "GPL-2.0-only"),
            self._make_component("b", "1.0", "GPL-3.0-only"),
        ]
        issues = check_license_compatibility(components, ignore_dev=True)
        assert len(issues) == 1
        assert issues[0]["severity"] == Severity.HIGH.value
        assert issues[0]["category"] == "license_incompatibility"

    @pytest.mark.parametrize(
        "specs",
        [
            pytest.param([("a", "1.0", "CDDL-1.0"), ("b", "1.0", "GPL-2.0")], id="cddl-vs-gpl"),
            pytest.param(
                [("a", "1.0", "GPL-2.0-only"), ("b", "1.0", "GPL-3.0-only"), ("c", "2.0", "GPL-2.0-only")],
                id="repeated-pair-deduplicated",
            ),
        ],
    )
    def test_an_incompatible_licence_pair_is_reported_once(self, specs):
        components = [self._make_component(*spec) for spec in specs]
        issues = check_license_compatibility(components, ignore_dev=True)
        assert len(issues) == 1

    def test_conflict_purl_points_at_the_component_named_first(self):
        """The purl is the only machine-readable anchor on a pair finding; it must match Component A."""
        components = [
            self._make_component("alpha", "1.0", "CDDL-1.0"),
            self._make_component("beta", "2.0", "GPL-2.0"),
        ]
        issues = check_license_compatibility(components, ignore_dev=True)
        assert len(issues) == 1
        purl_by_name = {c["name"]: c["purl"] for c in components}
        component_a = issues[0]["component"].split(" + ")[0]
        assert issues[0]["purl"] == purl_by_name[component_a]


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
        assert issues[0]["effective_severity"] == Severity.HIGH.value

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
    @pytest.mark.parametrize("scope", ["dev", "development", "test", "optional"])
    async def test_non_shipped_scope_is_skipped(self, scope):
        result = await self.analyzer.analyze(sbom={}, settings={}, parsed_components=[self._gpl_component(scope)])
        assert result["license_issues"] == []
        assert result["summary"]["skipped"] == 1
        assert result["summary"]["strong_copyleft"] == 0

    @pytest.mark.asyncio
    async def test_runtime_scope_is_still_evaluated(self):
        result = await self.analyzer.analyze(sbom={}, settings={}, parsed_components=[self._gpl_component("runtime")])
        assert result["summary"]["skipped"] == 0
        assert len(result["license_issues"]) == 1


_UNREADABLE_ALTERNATIVE = "Acme-1.0"
_UNREADABLE_OR_EXPRESSION = f"{_UNREADABLE_ALTERNATIVE} OR Widget-2.0"
_READABLE_OR_EXPRESSION = "MIT OR Apache-2.0"
# least_restrictive_group returns one OR alternative, so one component contributes one count.
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
        return await LicenseAnalyzer().analyze({"components": components})

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
            {"components": [component]},
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
_INCOMPATIBILITY_CATEGORY = "license_incompatibility"
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
        return await LicenseAnalyzer().analyze({"components": [component]}, settings or {})

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
    async def test_a_shadowed_alternative_still_reaches_the_conflict_check(self):
        components = [
            {
                "name": "dual-licensed",
                "version": "1.0.0",
                "purl": "pkg:pypi/dual-licensed@1.0.0",
                "licenses": [{"expression": _UNREADABLE_OR_COPYLEFT}],
            },
            {
                "name": "cddl-lib",
                "version": "1.0.0",
                "purl": "pkg:pypi/cddl-lib@1.0.0",
                "licenses": [{"license": {"id": _CONFLICTING_ID}}],
            },
        ]

        result = await LicenseAnalyzer().analyze({"components": components})

        conflicts = self._by_category(result, _INCOMPATIBILITY_CATEGORY)
        assert len(conflicts) == _ONE_FINDING
        assert _STRONG_COPYLEFT_ID in conflicts[0]["license"]


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

    def test_all_readable_leaves_nothing_unreadable(self):
        readable, unreadable = partition_or_groups([[_PERMISSIVE_ID], [_STRONG_COPYLEFT_ID]])
        assert readable == [[_PERMISSIVE_ID], [_STRONG_COPYLEFT_ID]]
        assert len(unreadable) == _NO_FINDINGS
