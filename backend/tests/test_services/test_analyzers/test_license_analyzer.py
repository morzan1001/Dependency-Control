"""Tests for the LicenseAnalyzer - license compliance analysis."""

from app.models.finding import Severity
from app.models.license import (
    DeploymentModel,
    DistributionModel,
    LicenseCategory,
    LicensePolicy,
    LibraryUsage,
)
from app.services.analyzers.license import LicenseAnalyzer


class TestNormalizeLicense:
    """Tests for _normalize_license - normalizes license identifiers to SPDX format."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def test_exact_match_returned_as_is(self):
        """Known SPDX ID is returned unchanged."""
        assert self.analyzer._normalize_license("MIT") == "MIT"

    def test_exact_match_apache(self):
        assert self.analyzer._normalize_license("Apache-2.0") == "Apache-2.0"

    def test_case_insensitive_match(self):
        """Lowercase input maps to correct SPDX ID."""
        assert self.analyzer._normalize_license("mit") == "MIT"

    def test_case_insensitive_mixed(self):
        assert self.analyzer._normalize_license("apache-2.0") == "Apache-2.0"

    def test_alias_resolution_apache(self):
        """Common alias 'Apache 2.0' resolves to SPDX 'Apache-2.0'."""
        assert self.analyzer._normalize_license("Apache 2.0") == "Apache-2.0"

    def test_alias_resolution_expat(self):
        assert self.analyzer._normalize_license("Expat") == "MIT"

    def test_alias_resolution_mit_x11(self):
        assert self.analyzer._normalize_license("MIT/X11") == "MIT"

    def test_alias_resolution_gplv3(self):
        assert self.analyzer._normalize_license("GPLv3") == "GPL-3.0"

    def test_alias_resolution_agpl(self):
        assert self.analyzer._normalize_license("AGPL") == "AGPL-3.0"

    def test_alias_case_insensitive(self):
        """Case-insensitive alias lookup works."""
        assert self.analyzer._normalize_license("apache 2.0") == "Apache-2.0"

    def test_metadata_stripping_semicolon(self):
        """Metadata suffix after semicolon is stripped."""
        assert self.analyzer._normalize_license('MIT;link="https://example.com"') == "MIT"

    def test_metadata_stripping_complex(self):
        result = self.analyzer._normalize_license('Apache-2.0";link="https://spdx.org"')
        assert result == "Apache-2.0"

    def test_surrounding_quotes_stripped(self):
        assert self.analyzer._normalize_license('"MIT"') == "MIT"

    def test_surrounding_spaces_stripped(self):
        assert self.analyzer._normalize_license("  MIT  ") == "MIT"

    def test_empty_string_returns_empty(self):
        assert self.analyzer._normalize_license("") == ""

    def test_only_semicolon_metadata_returns_empty(self):
        """String that is only metadata after stripping."""
        assert self.analyzer._normalize_license(';link="https://example.com"') == ""

    def test_unknown_license_passthrough(self):
        """Unrecognized license IDs are returned as-is."""
        assert self.analyzer._normalize_license("SomeCustomLicense-1.0") == "SomeCustomLicense-1.0"

    def test_bsd_alias(self):
        assert self.analyzer._normalize_license("BSD") == "BSD-3-Clause"

    def test_public_domain_alias(self):
        assert self.analyzer._normalize_license("Public Domain") == "Unlicense"

    def test_psf_alias(self):
        assert self.analyzer._normalize_license("PSF") == "Python-2.0"

    def test_boost_alias(self):
        assert self.analyzer._normalize_license("Boost") == "BSL-1.0"


class TestExtractLicenses:
    """Tests for _extract_licenses - extracts license IDs from component data."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def test_cyclonedx_license_id(self):
        """CycloneDX format with license.id field."""
        component = {"licenses": [{"license": {"id": "MIT", "url": "https://spdx.org/licenses/MIT"}}]}
        result = self.analyzer._extract_licenses(component)
        assert len(result) == 1
        assert result[0] == ("MIT", "https://spdx.org/licenses/MIT")

    def test_cyclonedx_license_name_fallback(self):
        """CycloneDX format falling back to license.name when id is absent."""
        component = {"licenses": [{"license": {"name": "Apache-2.0"}}]}
        result = self.analyzer._extract_licenses(component)
        assert len(result) == 1
        assert result[0][0] == "Apache-2.0"

    def test_cyclonedx_multiple_licenses(self):
        component = {
            "licenses": [
                {"license": {"id": "MIT"}},
                {"license": {"id": "Apache-2.0"}},
            ]
        }
        result = self.analyzer._extract_licenses(component)
        assert len(result) == 2

    def test_spdx_expression_or(self):
        """SPDX expression 'MIT OR Apache-2.0' is split into individual licenses."""
        component = {"licenses": [{"expression": "MIT OR Apache-2.0"}]}
        result = self.analyzer._extract_licenses(component)
        ids = [r[0] for r in result]
        assert "MIT" in ids
        assert "Apache-2.0" in ids

    def test_spdx_expression_and(self):
        component = {"licenses": [{"expression": "MIT AND BSD-3-Clause"}]}
        result = self.analyzer._extract_licenses(component)
        ids = [r[0] for r in result]
        assert "MIT" in ids
        assert "BSD-3-Clause" in ids

    def test_spdx_expression_with_parentheses(self):
        component = {"licenses": [{"expression": "(MIT OR Apache-2.0)"}]}
        result = self.analyzer._extract_licenses(component)
        ids = [r[0] for r in result]
        assert "MIT" in ids
        assert "Apache-2.0" in ids

    def test_direct_license_field_simple(self):
        """Direct 'license' field on component."""
        component = {"license": "MIT", "license_url": "https://example.com/MIT"}
        result = self.analyzer._extract_licenses(component)
        assert len(result) == 1
        assert result[0] == ("MIT", "https://example.com/MIT")

    def test_direct_license_comma_separated(self):
        """Comma-separated licenses in direct field."""
        component = {"license": "MIT, Apache-2.0"}
        result = self.analyzer._extract_licenses(component)
        ids = [r[0] for r in result]
        assert "MIT" in ids
        assert "Apache-2.0" in ids

    def test_direct_license_spdx_expression(self):
        """SPDX expression in direct license field."""
        component = {"license": "MIT OR Apache-2.0"}
        result = self.analyzer._extract_licenses(component)
        ids = [r[0] for r in result]
        assert "MIT" in ids
        assert "Apache-2.0" in ids

    def test_unknown_pattern_filtered_noassertion(self):
        """NOASSERTION is filtered out as an unknown license pattern."""
        component = {"licenses": [{"license": {"id": "NOASSERTION"}}]}
        result = self.analyzer._extract_licenses(component)
        assert len(result) == 0

    def test_unknown_pattern_filtered_unknown(self):
        component = {"licenses": [{"license": {"id": "UNKNOWN"}}]}
        result = self.analyzer._extract_licenses(component)
        assert len(result) == 0

    def test_unknown_pattern_expression_filtered(self):
        component = {"licenses": [{"expression": "NOASSERTION"}]}
        result = self.analyzer._extract_licenses(component)
        assert len(result) == 0

    def test_unknown_pattern_direct_field_filtered(self):
        component = {"license": "NOASSERTION"}
        result = self.analyzer._extract_licenses(component)
        assert len(result) == 0

    def test_empty_licenses_list(self):
        component = {"licenses": []}
        result = self.analyzer._extract_licenses(component)
        assert result == []

    def test_no_licenses_key(self):
        component = {"name": "some-package"}
        result = self.analyzer._extract_licenses(component)
        assert result == []

    def test_license_none_direct_field_ignored(self):
        """Non-string direct license field is ignored."""
        component = {"license": None}
        result = self.analyzer._extract_licenses(component)
        assert result == []

    def test_empty_string_direct_license_ignored(self):
        component = {"license": "   "}
        result = self.analyzer._extract_licenses(component)
        assert result == []

    def test_cyclonedx_and_direct_combined(self):
        """Both CycloneDX licenses and direct license field are extracted."""
        component = {
            "licenses": [{"license": {"id": "MIT"}}],
            "license": "Apache-2.0",
        }
        result = self.analyzer._extract_licenses(component)
        ids = [r[0] for r in result]
        assert "MIT" in ids
        assert "Apache-2.0" in ids


class TestEvaluateLicense:
    """Tests for _evaluate_license - returns issue dicts based on license category."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def _get_license_info(self, spdx_id):
        """Look up a LicenseInfo from the DATABASE."""
        return self.analyzer.LICENSE_DATABASE[spdx_id]

    def _evaluate(self, spdx_id, allow_strong=False, allow_network=False):
        """Evaluate a license with default component metadata (conservative defaults)."""
        info = self._get_license_info(spdx_id)
        policy = LicensePolicy(
            allow_strong_copyleft=allow_strong,
            allow_network_copyleft=allow_network,
        )
        return self.analyzer._evaluate_license(
            component="test-pkg",
            version="1.0.0",
            license_info=info,
            lic_url=None,
            purl="pkg:pypi/test-pkg@1.0.0",
            policy=policy,
        )

    def test_permissive_returns_none(self):
        """Permissive licenses (MIT) produce no issue."""
        result = self._evaluate("MIT")
        assert result is None

    def test_permissive_apache_returns_none(self):
        result = self._evaluate("Apache-2.0")
        assert result is None

    def test_permissive_bsd_returns_none(self):
        result = self._evaluate("BSD-3-Clause")
        assert result is None

    def test_public_domain_returns_none(self):
        """Public domain licenses produce no issue."""
        result = self._evaluate("Unlicense")
        assert result is None

    def test_public_domain_cc0_returns_none(self):
        result = self._evaluate("CC0-1.0")
        assert result is None

    def test_weak_copyleft_returns_info(self):
        """Weak copyleft (LGPL) returns INFO severity."""
        result = self._evaluate("LGPL-3.0")
        assert result is not None
        assert result["severity"] == Severity.INFO.value

    def test_weak_copyleft_mpl_returns_info(self):
        result = self._evaluate("MPL-2.0")
        assert result is not None
        assert result["severity"] == Severity.INFO.value

    def test_strong_copyleft_disallowed_returns_high(self):
        """Strong copyleft (GPL) without allow flag returns HIGH."""
        result = self._evaluate("GPL-3.0", allow_strong=False)
        assert result is not None
        assert result["severity"] == Severity.HIGH.value

    def test_strong_copyleft_allowed_returns_info(self):
        """Strong copyleft (GPL) with allow flag returns INFO."""
        result = self._evaluate("GPL-3.0", allow_strong=True)
        assert result is not None
        assert result["severity"] == Severity.INFO.value

    def test_strong_copyleft_gpl2_disallowed(self):
        result = self._evaluate("GPL-2.0", allow_strong=False)
        assert result is not None
        assert result["severity"] == Severity.HIGH.value

    def test_network_copyleft_disallowed_returns_critical(self):
        """Network copyleft (AGPL) without allow flag returns CRITICAL."""
        result = self._evaluate("AGPL-3.0", allow_network=False)
        assert result is not None
        assert result["severity"] == Severity.CRITICAL.value

    def test_network_copyleft_allowed_returns_medium(self):
        """Network copyleft (AGPL) with allow flag returns MEDIUM."""
        result = self._evaluate("AGPL-3.0", allow_network=True)
        assert result is not None
        assert result["severity"] == Severity.MEDIUM.value

    def test_network_copyleft_sspl_disallowed(self):
        result = self._evaluate("SSPL-1.0", allow_network=False)
        assert result is not None
        assert result["severity"] == Severity.CRITICAL.value

    def test_network_copyleft_sspl_allowed(self):
        result = self._evaluate("SSPL-1.0", allow_network=True)
        assert result is not None
        assert result["severity"] == Severity.MEDIUM.value

    def test_proprietary_returns_high(self):
        """Proprietary/NC license returns HIGH severity."""
        result = self._evaluate("CC-BY-NC-4.0")
        assert result is not None
        assert result["severity"] == Severity.HIGH.value

    def test_issue_contains_component_name(self):
        result = self._evaluate("GPL-3.0")
        assert result["component"] == "test-pkg"

    def test_issue_contains_version(self):
        result = self._evaluate("GPL-3.0")
        assert result["version"] == "1.0.0"

    def test_issue_contains_license_id(self):
        result = self._evaluate("GPL-3.0")
        assert result["license"] == "GPL-3.0"

    def test_issue_contains_category(self):
        result = self._evaluate("GPL-3.0")
        assert result["category"] == LicenseCategory.STRONG_COPYLEFT.value

    def test_issue_contains_obligations(self):
        result = self._evaluate("GPL-3.0")
        assert isinstance(result["obligations"], list)
        assert len(result["obligations"]) > 0

    def test_issue_contains_purl(self):
        result = self._evaluate("GPL-3.0")
        assert result["purl"] == "pkg:pypi/test-pkg@1.0.0"


class TestLicenseDatabase:
    """Spot-check that LICENSE_DATABASE has correct entries and categories."""

    def setup_method(self):
        self.db = LicenseAnalyzer.LICENSE_DATABASE

    def test_mit_is_permissive(self):
        assert "MIT" in self.db
        assert self.db["MIT"].category == LicenseCategory.PERMISSIVE

    def test_apache_is_permissive(self):
        assert "Apache-2.0" in self.db
        assert self.db["Apache-2.0"].category == LicenseCategory.PERMISSIVE

    def test_lgpl_is_weak_copyleft(self):
        assert "LGPL-3.0" in self.db
        assert self.db["LGPL-3.0"].category == LicenseCategory.WEAK_COPYLEFT

    def test_gpl3_only_is_strong_copyleft(self):
        assert "GPL-3.0-only" in self.db
        assert self.db["GPL-3.0-only"].category == LicenseCategory.STRONG_COPYLEFT

    def test_agpl_is_network_copyleft(self):
        assert "AGPL-3.0-only" in self.db
        assert self.db["AGPL-3.0-only"].category == LicenseCategory.NETWORK_COPYLEFT

    def test_cc_by_nc_is_proprietary(self):
        assert "CC-BY-NC-4.0" in self.db
        assert self.db["CC-BY-NC-4.0"].category == LicenseCategory.PROPRIETARY

    def test_unlicense_is_public_domain(self):
        assert "Unlicense" in self.db
        assert self.db["Unlicense"].category == LicenseCategory.PUBLIC_DOMAIN

    def test_isc_is_permissive(self):
        assert "ISC" in self.db
        assert self.db["ISC"].category == LicenseCategory.PERMISSIVE

    def test_sspl_is_network_copyleft(self):
        assert "SSPL-1.0" in self.db
        assert self.db["SSPL-1.0"].category == LicenseCategory.NETWORK_COPYLEFT

    def test_mpl_is_weak_copyleft(self):
        assert "MPL-2.0" in self.db
        assert self.db["MPL-2.0"].category == LicenseCategory.WEAK_COPYLEFT

    def test_mit_compatible_with_proprietary(self):
        assert self.db["MIT"].compatible_with_proprietary is True

    def test_gpl_not_compatible_with_proprietary(self):
        assert self.db["GPL-3.0"].compatible_with_proprietary is False


class TestEvaluateLicenseWithContext:
    """Tests for context-aware license evaluation using LicensePolicy."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def _get_license_info(self, spdx_id):
        return self.analyzer.LICENSE_DATABASE[spdx_id]

    def _evaluate_with_policy(self, spdx_id, **policy_kwargs):
        """Evaluate a license with a specific LicensePolicy."""
        info = self._get_license_info(spdx_id)
        policy = LicensePolicy(**policy_kwargs)
        return self.analyzer._evaluate_license(
            component="test-pkg",
            version="1.0.0",
            license_info=info,
            lic_url=None,
            purl="pkg:pypi/test-pkg@1.0.0",
            policy=policy,
        )

    # --- Weak Copyleft + library_usage ---

    def test_weak_copyleft_unmodified_returns_none(self):
        """LGPL with unmodified usage produces no finding."""
        result = self._evaluate_with_policy("LGPL-3.0", library_usage=LibraryUsage.UNMODIFIED)
        assert result is None

    def test_weak_copyleft_mpl_unmodified_returns_none(self):
        """MPL with unmodified usage produces no finding."""
        result = self._evaluate_with_policy("MPL-2.0", library_usage=LibraryUsage.UNMODIFIED)
        assert result is None

    def test_weak_copyleft_modified_returns_info(self):
        """LGPL with modified usage produces INFO finding."""
        result = self._evaluate_with_policy("LGPL-3.0", library_usage=LibraryUsage.MODIFIED)
        assert result is not None
        assert result["severity"] == Severity.INFO.value
        assert result["context_reason"] is not None

    def test_weak_copyleft_mixed_returns_info(self):
        """LGPL with mixed usage produces INFO finding (conservative, same as before)."""
        result = self._evaluate_with_policy("LGPL-3.0", library_usage=LibraryUsage.MIXED)
        assert result is not None
        assert result["severity"] == Severity.INFO.value

    def test_weak_copyleft_default_returns_info(self):
        """Default policy (mixed) preserves existing behavior for weak copyleft."""
        result = self._evaluate_with_policy("LGPL-3.0")
        assert result is not None
        assert result["severity"] == Severity.INFO.value

    # --- Strong Copyleft + distribution_model ---

    def test_strong_copyleft_internal_only_returns_info(self):
        """GPL with internal-only distribution produces INFO."""
        result = self._evaluate_with_policy(
            "GPL-3.0", distribution_model=DistributionModel.INTERNAL_ONLY
        )
        assert result is not None
        assert result["severity"] == Severity.INFO.value
        assert result["context_reason"] is not None
        assert result["effective_severity"] == Severity.HIGH.value

    def test_strong_copyleft_open_source_returns_info(self):
        """GPL with open source project produces INFO."""
        result = self._evaluate_with_policy(
            "GPL-3.0", distribution_model=DistributionModel.OPEN_SOURCE
        )
        assert result is not None
        assert result["severity"] == Severity.INFO.value
        assert result["context_reason"] is not None
        assert result["effective_severity"] == Severity.HIGH.value

    def test_strong_copyleft_distributed_not_allowed_returns_high(self):
        """GPL with distributed project and no allowance returns HIGH (unchanged)."""
        result = self._evaluate_with_policy(
            "GPL-3.0",
            distribution_model=DistributionModel.DISTRIBUTED,
            allow_strong_copyleft=False,
        )
        assert result is not None
        assert result["severity"] == Severity.HIGH.value

    def test_strong_copyleft_distributed_allowed_returns_info(self):
        """GPL with distributed project but allowed returns INFO (unchanged)."""
        result = self._evaluate_with_policy(
            "GPL-3.0",
            distribution_model=DistributionModel.DISTRIBUTED,
            allow_strong_copyleft=True,
        )
        assert result is not None
        assert result["severity"] == Severity.INFO.value

    # --- Network Copyleft + deployment_model ---

    def test_network_copyleft_cli_batch_returns_low(self):
        """AGPL with CLI/batch deployment produces LOW."""
        result = self._evaluate_with_policy(
            "AGPL-3.0", deployment_model=DeploymentModel.CLI_BATCH
        )
        assert result is not None
        assert result["severity"] == Severity.LOW.value
        assert result["context_reason"] is not None
        assert result["effective_severity"] == Severity.CRITICAL.value

    def test_network_copyleft_desktop_returns_low(self):
        """AGPL with desktop deployment produces LOW."""
        result = self._evaluate_with_policy(
            "AGPL-3.0", deployment_model=DeploymentModel.DESKTOP
        )
        assert result is not None
        assert result["severity"] == Severity.LOW.value

    def test_network_copyleft_embedded_returns_low(self):
        """AGPL with embedded deployment produces LOW."""
        result = self._evaluate_with_policy(
            "AGPL-3.0", deployment_model=DeploymentModel.EMBEDDED
        )
        assert result is not None
        assert result["severity"] == Severity.LOW.value

    def test_network_copyleft_network_facing_internal_returns_medium(self):
        """AGPL with network-facing but internal-only returns MEDIUM."""
        result = self._evaluate_with_policy(
            "AGPL-3.0",
            deployment_model=DeploymentModel.NETWORK_FACING,
            distribution_model=DistributionModel.INTERNAL_ONLY,
        )
        assert result is not None
        assert result["severity"] == Severity.MEDIUM.value
        assert result["context_reason"] is not None
        assert result["effective_severity"] == Severity.CRITICAL.value

    def test_network_copyleft_network_facing_distributed_not_allowed_returns_critical(self):
        """AGPL with network-facing + distributed + not allowed returns CRITICAL (unchanged)."""
        result = self._evaluate_with_policy(
            "AGPL-3.0",
            deployment_model=DeploymentModel.NETWORK_FACING,
            distribution_model=DistributionModel.DISTRIBUTED,
            allow_network_copyleft=False,
        )
        assert result is not None
        assert result["severity"] == Severity.CRITICAL.value

    def test_network_copyleft_network_facing_allowed_returns_medium(self):
        """AGPL with network-facing + allowed returns MEDIUM (unchanged)."""
        result = self._evaluate_with_policy(
            "AGPL-3.0",
            deployment_model=DeploymentModel.NETWORK_FACING,
            allow_network_copyleft=True,
        )
        assert result is not None
        assert result["severity"] == Severity.MEDIUM.value

    # --- Default policy = backward compatibility ---

    def test_default_policy_matches_old_behavior_weak_copyleft(self):
        """Default LicensePolicy produces same result as old code for weak copyleft."""
        result = self._evaluate_with_policy("LGPL-3.0")
        assert result is not None
        assert result["severity"] == Severity.INFO.value

    def test_default_policy_matches_old_behavior_strong_copyleft(self):
        """Default LicensePolicy produces same result as old code for strong copyleft."""
        result = self._evaluate_with_policy("GPL-3.0")
        assert result is not None
        assert result["severity"] == Severity.HIGH.value

    def test_default_policy_matches_old_behavior_network_copyleft(self):
        """Default LicensePolicy produces same result as old code for network copyleft."""
        result = self._evaluate_with_policy("AGPL-3.0")
        assert result is not None
        assert result["severity"] == Severity.CRITICAL.value

    def test_default_policy_matches_old_behavior_proprietary(self):
        """Default LicensePolicy produces same result as old code for proprietary."""
        result = self._evaluate_with_policy("CC-BY-NC-4.0")
        assert result is not None
        assert result["severity"] == Severity.HIGH.value

    def test_default_policy_matches_old_behavior_permissive(self):
        """Default LicensePolicy produces same result as old code for permissive."""
        result = self._evaluate_with_policy("MIT")
        assert result is None

    # --- context_reason and effective_severity fields ---

    def test_context_reason_absent_when_not_adjusted(self):
        """No context_reason when severity is not adjusted by policy."""
        result = self._evaluate_with_policy("GPL-3.0")
        assert "context_reason" not in result

    def test_effective_severity_absent_when_not_adjusted(self):
        """No effective_severity when severity is not adjusted by policy."""
        result = self._evaluate_with_policy("GPL-3.0")
        assert "effective_severity" not in result

    def test_context_fields_present_when_adjusted(self):
        """Both context_reason and effective_severity present when severity is reduced."""
        result = self._evaluate_with_policy(
            "GPL-3.0", distribution_model=DistributionModel.INTERNAL_ONLY
        )
        assert "context_reason" in result
        assert "effective_severity" in result
        assert result["effective_severity"] == Severity.HIGH.value


class TestSpdxExpressionEvaluation:
    """Tests for SPDX OR/AND expression handling."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def test_parse_simple_or(self):
        """'MIT OR Apache-2.0' splits into two OR alternatives."""
        result = self.analyzer._parse_spdx_expression("MIT OR Apache-2.0")
        assert result == [["MIT"], ["Apache-2.0"]]

    def test_parse_simple_and(self):
        """'GPL-2.0 AND Classpath' stays as one AND group."""
        result = self.analyzer._parse_spdx_expression("GPL-2.0 AND Classpath")
        assert result == [["GPL-2.0", "Classpath"]]

    def test_parse_mixed_or_and(self):
        """'MIT OR GPL-2.0 AND Classpath' splits correctly."""
        result = self.analyzer._parse_spdx_expression("MIT OR GPL-2.0 AND Classpath")
        assert len(result) == 2
        assert ["MIT"] in result

    def test_parse_with_exception(self):
        """WITH clauses are stripped (they modify but don't add licenses)."""
        result = self.analyzer._parse_spdx_expression("GPL-2.0 WITH Classpath-exception-2.0")
        assert result == [["GPL-2.0"]]

    def test_parse_single_license(self):
        result = self.analyzer._parse_spdx_expression("MIT")
        assert result == [["MIT"]]

    def test_evaluate_or_picks_least_restrictive(self):
        """'MIT OR GPL-3.0' should evaluate as MIT (permissive, no finding)."""
        policy = LicensePolicy()
        or_groups = [["MIT"], ["GPL-3.0"]]
        result = self.analyzer._evaluate_expression(
            "test-pkg", "1.0.0", "pkg:pypi/test-pkg@1.0.0", or_groups, policy
        )
        # MIT is permissive → no issue, which is the least restrictive
        assert result is None

    def test_evaluate_or_gpl_or_lgpl_picks_lgpl(self):
        """'GPL-3.0 OR LGPL-3.0' should pick LGPL (INFO) over GPL (HIGH)."""
        policy = LicensePolicy()
        or_groups = [["GPL-3.0"], ["LGPL-3.0"]]
        result = self.analyzer._evaluate_expression(
            "test-pkg", "1.0.0", "pkg:pypi/test-pkg@1.0.0", or_groups, policy
        )
        assert result is not None
        assert result["severity"] == Severity.INFO.value
        assert result["license"] == "LGPL-3.0"

    def test_evaluate_and_picks_most_restrictive(self):
        """'MIT AND GPL-3.0' should evaluate as GPL (most restrictive)."""
        policy = LicensePolicy()
        or_groups = [["MIT", "GPL-3.0"]]
        result = self.analyzer._evaluate_expression(
            "test-pkg", "1.0.0", "pkg:pypi/test-pkg@1.0.0", or_groups, policy
        )
        assert result is not None
        assert result["severity"] == Severity.HIGH.value

    def test_evaluate_or_all_permissive(self):
        """'MIT OR Apache-2.0' → both permissive → no finding."""
        policy = LicensePolicy()
        or_groups = [["MIT"], ["Apache-2.0"]]
        result = self.analyzer._evaluate_expression(
            "test-pkg", "1.0.0", "pkg:pypi/test-pkg@1.0.0", or_groups, policy
        )
        assert result is None

    def test_evaluate_or_respects_policy(self):
        """'GPL-3.0 OR AGPL-3.0' with internal_only picks GPL (INFO)."""
        policy = LicensePolicy(distribution_model=DistributionModel.INTERNAL_ONLY)
        or_groups = [["GPL-3.0"], ["AGPL-3.0"]]
        result = self.analyzer._evaluate_expression(
            "test-pkg", "1.0.0", "pkg:pypi/test-pkg@1.0.0", or_groups, policy
        )
        # Both become INFO with internal_only, but GPL is evaluated first
        assert result is not None
        assert result["severity"] == Severity.INFO.value


class TestTransitiveDependencySeverity:
    """Tests for transitive dependency severity adjustment."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    def test_transitive_critical_downgraded_to_high(self):
        issue = {"severity": Severity.CRITICAL.value, "category": "network_copyleft"}
        self.analyzer._apply_transitive_adjustment(issue, is_transitive=True)
        assert issue["severity"] == Severity.HIGH.value
        assert issue["is_transitive"] is True
        assert "context_reason" in issue

    def test_transitive_high_downgraded_to_medium(self):
        issue = {"severity": Severity.HIGH.value, "category": "strong_copyleft"}
        self.analyzer._apply_transitive_adjustment(issue, is_transitive=True)
        assert issue["severity"] == Severity.MEDIUM.value

    def test_transitive_medium_downgraded_to_low(self):
        issue = {"severity": Severity.MEDIUM.value, "category": "network_copyleft"}
        self.analyzer._apply_transitive_adjustment(issue, is_transitive=True)
        assert issue["severity"] == Severity.LOW.value

    def test_transitive_info_not_downgraded(self):
        issue = {"severity": Severity.INFO.value, "category": "weak_copyleft"}
        self.analyzer._apply_transitive_adjustment(issue, is_transitive=True)
        assert issue["severity"] == Severity.INFO.value

    def test_direct_not_affected(self):
        issue = {"severity": Severity.HIGH.value, "category": "strong_copyleft"}
        self.analyzer._apply_transitive_adjustment(issue, is_transitive=False)
        assert issue["severity"] == Severity.HIGH.value
        assert "is_transitive" not in issue

    def test_transitive_preserves_effective_severity(self):
        issue = {"severity": Severity.HIGH.value, "category": "strong_copyleft"}
        self.analyzer._apply_transitive_adjustment(issue, is_transitive=True)
        assert issue["effective_severity"] == Severity.HIGH.value

    def test_transitive_info_filtered_out(self):
        """INFO findings for transitive deps should be excluded."""
        issue = {"severity": Severity.INFO.value}
        assert self.analyzer._should_include_finding(issue, is_transitive=True) is False

    def test_transitive_low_filtered_out(self):
        """LOW findings for transitive deps should be excluded."""
        issue = {"severity": Severity.LOW.value}
        assert self.analyzer._should_include_finding(issue, is_transitive=True) is False

    def test_transitive_medium_included(self):
        """MEDIUM findings for transitive deps should be included."""
        issue = {"severity": Severity.MEDIUM.value}
        assert self.analyzer._should_include_finding(issue, is_transitive=True) is True

    def test_direct_info_included(self):
        """INFO findings for direct deps should always be included."""
        issue = {"severity": Severity.INFO.value}
        assert self.analyzer._should_include_finding(issue, is_transitive=False) is True


class TestLicenseCompatibility:
    """Tests for cross-dependency license compatibility checking."""

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

    def test_no_conflict_permissive_only(self):
        """No conflicts when all licenses are permissive."""
        components = [
            self._make_component("a", "1.0", "MIT"),
            self._make_component("b", "1.0", "Apache-2.0"),
        ]
        issues = self.analyzer._check_license_compatibility(components, ignore_dev=True)
        assert len(issues) == 0

    def test_gpl2_only_vs_gpl3_only_conflict(self):
        """GPL-2.0-only and GPL-3.0-only are incompatible."""
        components = [
            self._make_component("a", "1.0", "GPL-2.0-only"),
            self._make_component("b", "1.0", "GPL-3.0-only"),
        ]
        issues = self.analyzer._check_license_compatibility(components, ignore_dev=True)
        assert len(issues) == 1
        assert issues[0]["severity"] == Severity.HIGH.value
        assert issues[0]["category"] == "license_incompatibility"

    def test_cddl_vs_gpl_conflict(self):
        """CDDL-1.0 and GPL-2.0 are incompatible."""
        components = [
            self._make_component("a", "1.0", "CDDL-1.0"),
            self._make_component("b", "1.0", "GPL-2.0"),
        ]
        issues = self.analyzer._check_license_compatibility(components, ignore_dev=True)
        assert len(issues) == 1

    def test_dev_dependencies_skipped(self):
        """Dev dependencies are excluded from compatibility checks."""
        components = [
            self._make_component("a", "1.0", "GPL-2.0-only"),
            self._make_component("b", "1.0", "GPL-3.0-only", scope="dev"),
        ]
        issues = self.analyzer._check_license_compatibility(components, ignore_dev=True)
        assert len(issues) == 0

    def test_same_license_no_conflict(self):
        """Same license across components is never a conflict."""
        components = [
            self._make_component("a", "1.0", "GPL-3.0"),
            self._make_component("b", "1.0", "GPL-3.0"),
        ]
        issues = self.analyzer._check_license_compatibility(components, ignore_dev=True)
        assert len(issues) == 0

    def test_duplicate_conflict_deduplicated(self):
        """Same conflict pair reported only once even with multiple components."""
        components = [
            self._make_component("a", "1.0", "GPL-2.0-only"),
            self._make_component("b", "1.0", "GPL-3.0-only"),
            self._make_component("c", "2.0", "GPL-2.0-only"),
        ]
        issues = self.analyzer._check_license_compatibility(components, ignore_dev=True)
        assert len(issues) == 1
