"""Tests for the ResultAggregator - pure functions and merging logic.

Tests are written to verify CORRECT behavior. If tests fail,
the code should be investigated for bugs.
"""

from app.models.finding import Finding, FindingType, Severity
from app.services.aggregator import ResultAggregator


# ── Pure helper functions ────────────────────────────────────────────


class TestParseVersionKey:
    """Tests for _parse_version_key - converts version strings to comparable tuples."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_simple_semver(self):
        assert self.agg._parse_version_key("1.2.3") == (1, 2, 3)

    def test_v_prefix_stripped(self):
        assert self.agg._parse_version_key("v1.2.3") == (1, 2, 3)

    def test_uppercase_v_prefix(self):
        assert self.agg._parse_version_key("V1.2.3") == (1, 2, 3)

    def test_prerelease_label(self):
        result = self.agg._parse_version_key("1.2.3-beta")
        assert result == (1, 2, 3, "beta")

    def test_prerelease_with_number(self):
        result = self.agg._parse_version_key("1.2.3-rc1")
        # "rc1" is alphanumeric, so it stays as one token (not split further)
        assert result == (1, 2, 3, "rc1")

    def test_numeric_parts_are_ints(self):
        result = self.agg._parse_version_key("10.20.30")
        assert all(isinstance(p, int) for p in result)

    def test_comparison_works_correctly(self):
        """Higher versions should compare as greater."""
        v1 = self.agg._parse_version_key("1.2.3")
        v2 = self.agg._parse_version_key("1.2.4")
        assert v2 > v1

    def test_comparison_major_version(self):
        v1 = self.agg._parse_version_key("1.9.9")
        v2 = self.agg._parse_version_key("2.0.0")
        assert v2 > v1

    def test_empty_string(self):
        assert self.agg._parse_version_key("") == ()

    def test_single_number(self):
        assert self.agg._parse_version_key("42") == (42,)


class TestNormalizeVersion:
    """Tests for _normalize_version - strips Go/v prefixes."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_go_prefix_stripped(self):
        assert self.agg._normalize_version("go1.25.4") == "1.25.4"

    def test_v_prefix_stripped(self):
        assert self.agg._normalize_version("v1.25.4") == "1.25.4"

    def test_plain_version_unchanged(self):
        assert self.agg._normalize_version("1.25.4") == "1.25.4"

    def test_empty_returns_unknown(self):
        assert self.agg._normalize_version("") == "unknown"

    def test_none_returns_unknown(self):
        assert self.agg._normalize_version(None) == "unknown"

    def test_go_without_digit_not_stripped(self):
        """'gomodule' should NOT be stripped - only 'go' followed by digit."""
        result = self.agg._normalize_version("gomodule")
        assert result == "gomodule"

    def test_v_without_digit_not_stripped(self):
        """'version' should NOT be stripped - only 'v' followed by digit."""
        result = self.agg._normalize_version("version")
        assert result == "version"

    def test_uppercase_preserved_after_lowering(self):
        """Version strings should be lowercased."""
        assert self.agg._normalize_version("V2.0.0") == "2.0.0"

    def test_whitespace_stripped(self):
        assert self.agg._normalize_version("  1.0.0  ") == "1.0.0"


class TestNormalizeComponent:
    """Tests for _normalize_component."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_lowercases(self):
        assert self.agg._normalize_component("Lodash") == "lodash"

    def test_strips_whitespace(self):
        assert self.agg._normalize_component("  requests  ") == "requests"

    def test_empty_returns_unknown(self):
        assert self.agg._normalize_component("") == "unknown"

    def test_none_returns_unknown(self):
        assert self.agg._normalize_component(None) == "unknown"


class TestIsSameComponentName:
    """Tests for _is_same_component_name - component name matching.

    This function is used when findings already share the same VERSION
    and VULNERABILITIES, so lenient matching is somewhat intentional.
    However, overly loose matching can cause false merges.
    """

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_exact_match(self):
        assert self.agg._is_same_component_name("lodash", "lodash") is True

    def test_case_insensitive(self):
        assert self.agg._is_same_component_name("Lodash", "lodash") is True

    def test_different_names(self):
        assert self.agg._is_same_component_name("lodash", "express") is False

    def test_maven_group_artifact(self):
        """Maven-style 'org.postgresql:postgresql' should match 'postgresql'."""
        assert self.agg._is_same_component_name("org.postgresql:postgresql", "postgresql") is True

    def test_maven_reverse(self):
        assert self.agg._is_same_component_name("postgresql", "org.postgresql:postgresql") is True

    def test_maven_different_artifact(self):
        """'org.postgresql:driver' should NOT match 'postgresql'."""
        assert self.agg._is_same_component_name("org.postgresql:driver", "postgresql") is False

    def test_npm_scoped_package(self):
        """'@angular/core' vs 'core' - this matches due to / suffix check.
        This is a potential false positive in practice (e.g., unrelated 'core' package),
        but the function is only called when version+vulns already match.
        """
        result = self.agg._is_same_component_name("@angular/core", "core")
        assert result is True

    def test_npm_scoped_different_package(self):
        """'@angular/core' should NOT match 'http'."""
        assert self.agg._is_same_component_name("@angular/core", "http") is False

    def test_substring_not_matched(self):
        """'express' should NOT match 'express-validator' (no : or / relation)."""
        assert self.agg._is_same_component_name("express", "express-validator") is False

    def test_colon_partial_not_matched(self):
        """'com.foo:bar' should NOT match 'foo'."""
        assert self.agg._is_same_component_name("com.foo:bar", "foo") is False


class TestCalculateAggregatedFixedVersion:
    """Tests for _calculate_aggregated_fixed_version.

    Input: List of fixed version strings (one per vulnerability).
    Output: Best fix version(s) that cover ALL vulnerabilities.
    """

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_single_fix(self):
        result = self.agg._calculate_aggregated_fixed_version(["1.2.5"])
        assert result == "1.2.5"

    def test_two_vulns_same_major(self):
        """Two vulns fixed in same major line - pick the highest."""
        result = self.agg._calculate_aggregated_fixed_version(["1.2.3", "1.2.5"])
        assert result == "1.2.5"

    def test_two_vulns_different_majors(self):
        """Two vulns with fixes in two major lines - return both."""
        result = self.agg._calculate_aggregated_fixed_version(["1.2.5, 2.0.1", "1.2.6, 2.0.3"])
        # For major 1: max(1.2.5, 1.2.6) = 1.2.6
        # For major 2: max(2.0.1, 2.0.3) = 2.0.3
        assert "1.2.6" in result
        assert "2.0.3" in result

    def test_empty_list_returns_none(self):
        assert self.agg._calculate_aggregated_fixed_version([]) is None

    def test_single_vuln_multiple_major_fixes(self):
        """One vuln with fixes in multiple majors."""
        result = self.agg._calculate_aggregated_fixed_version(["1.5.0, 2.1.0"])
        assert "1.5.0" in result
        assert "2.1.0" in result

    def test_major_must_cover_all_vulns(self):
        """If a major version only covers some vulns, it should be excluded."""
        # Vuln 1: fixed in 1.x and 2.x
        # Vuln 2: fixed only in 2.x
        # -> Only major 2 covers both
        result = self.agg._calculate_aggregated_fixed_version(["1.5.0, 2.0.1", "2.0.3"])
        assert "2.0.3" in result
        # Major 1 should not be in result since it doesn't cover vuln 2
        assert "1.5.0" not in result

    def test_v_prefix_handled(self):
        """Version strings with v prefix should be parsed correctly."""
        result = self.agg._calculate_aggregated_fixed_version(["v1.2.3"])
        assert result is not None


# ── Merging logic ────────────────────────────────────────────────────


class TestMergeVulnerabilityIntoList:
    """Tests for _merge_vulnerability_into_list - deduplicates by ID/aliases."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_new_entry_appended(self):
        target = []
        entry = {"id": "CVE-2023-1234", "severity": "HIGH", "aliases": []}
        self.agg._merge_vulnerability_into_list(target, entry)
        assert len(target) == 1
        assert target[0]["id"] == "CVE-2023-1234"

    def test_duplicate_id_merged(self):
        target = [
            {
                "id": "CVE-2023-1234",
                "severity": "MEDIUM",
                "description": "short",
                "aliases": [],
                "scanners": ["trivy"],
            }
        ]
        entry = {
            "id": "CVE-2023-1234",
            "severity": "HIGH",
            "description": "longer description here",
            "aliases": [],
            "scanners": ["grype"],
        }
        self.agg._merge_vulnerability_into_list(target, entry)
        assert len(target) == 1
        # Severity: higher wins
        assert target[0]["severity"] == "HIGH"
        # Description: longer wins
        assert target[0]["description"] == "longer description here"
        # Scanners: merged
        assert set(target[0]["scanners"]) == {"trivy", "grype"}

    def test_alias_intersection_triggers_merge(self):
        """If target has alias that matches source ID, they should merge."""
        target = [
            {
                "id": "CVE-2023-1234",
                "severity": "HIGH",
                "aliases": ["GHSA-xxxx"],
                "scanners": ["trivy"],
            }
        ]
        entry = {
            "id": "GHSA-xxxx",
            "severity": "MEDIUM",
            "aliases": [],
            "scanners": ["grype"],
        }
        self.agg._merge_vulnerability_into_list(target, entry)
        assert len(target) == 1
        # Should keep the original ID (CVE)
        assert target[0]["id"] == "CVE-2023-1234"
        # GHSA should be in aliases
        assert "GHSA-xxxx" in target[0]["aliases"]

    def test_no_match_creates_new_entry(self):
        target = [{"id": "CVE-2023-1111", "aliases": [], "scanners": []}]
        entry = {"id": "CVE-2023-2222", "aliases": [], "scanners": []}
        self.agg._merge_vulnerability_into_list(target, entry)
        assert len(target) == 2

    def test_cvss_merge_higher_wins(self):
        target = [
            {
                "id": "CVE-1",
                "aliases": [],
                "scanners": [],
                "cvss_score": 5.0,
                "cvss_vector": "old",
            }
        ]
        entry = {
            "id": "CVE-1",
            "aliases": [],
            "scanners": [],
            "cvss_score": 9.8,
            "cvss_vector": "new",
        }
        self.agg._merge_vulnerability_into_list(target, entry)
        assert target[0]["cvss_score"] == 9.8
        assert target[0]["cvss_vector"] == "new"

    def test_fixed_version_not_overwritten_if_present(self):
        target = [
            {
                "id": "CVE-1",
                "aliases": [],
                "scanners": [],
                "fixed_version": "1.2.3",
            }
        ]
        entry = {
            "id": "CVE-1",
            "aliases": [],
            "scanners": [],
            "fixed_version": "1.2.4",
        }
        self.agg._merge_vulnerability_into_list(target, entry)
        # Original fixed_version should be preserved (not overwritten)
        assert target[0]["fixed_version"] == "1.2.3"

    def test_fixed_version_added_if_missing(self):
        target = [
            {
                "id": "CVE-1",
                "aliases": [],
                "scanners": [],
                "fixed_version": None,
            }
        ]
        entry = {
            "id": "CVE-1",
            "aliases": [],
            "scanners": [],
            "fixed_version": "1.2.3",
        }
        self.agg._merge_vulnerability_into_list(target, entry)
        assert target[0]["fixed_version"] == "1.2.3"


class TestAddVulnerabilityFinding:
    """Tests for _add_vulnerability_finding - aggregation by component+version."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def _make_vuln(self, id, component, version, severity="HIGH", fixed_version=None):
        return Finding(
            id=id,
            type=FindingType.VULNERABILITY,
            severity=severity,
            component=component,
            version=version,
            description=f"Vuln {id}",
            scanners=["test"],
            details={"fixed_version": fixed_version},
        )

    def test_first_finding_creates_aggregate(self):
        finding = self._make_vuln("CVE-1", "lodash", "4.17.0")
        self.agg.add_finding(finding)
        assert len(self.agg.findings) == 1
        key = list(self.agg.findings.keys())[0]
        agg = self.agg.findings[key]
        assert agg.component == "lodash"
        assert len(agg.details["vulnerabilities"]) == 1

    def test_same_component_version_aggregated(self):
        """Two CVEs for same component+version should be in same aggregate."""
        self.agg.add_finding(self._make_vuln("CVE-1", "lodash", "4.17.0"))
        self.agg.add_finding(self._make_vuln("CVE-2", "lodash", "4.17.0"))
        assert len(self.agg.findings) == 1
        agg = list(self.agg.findings.values())[0]
        assert len(agg.details["vulnerabilities"]) == 2

    def test_different_components_separate(self):
        self.agg.add_finding(self._make_vuln("CVE-1", "lodash", "4.17.0"))
        self.agg.add_finding(self._make_vuln("CVE-2", "express", "4.17.0"))
        assert len(self.agg.findings) == 2

    def test_severity_escalation(self):
        """Aggregate severity should be the max of all findings."""
        self.agg.add_finding(self._make_vuln("CVE-1", "pkg", "1.0", severity="LOW"))
        self.agg.add_finding(self._make_vuln("CVE-2", "pkg", "1.0", severity="CRITICAL"))
        agg = list(self.agg.findings.values())[0]
        assert agg.severity == "CRITICAL"

    def test_go_version_normalization(self):
        """go1.25.4 and 1.25.4 should be treated as same version."""
        self.agg.add_finding(self._make_vuln("CVE-1", "golang.org/x/net", "go1.25.4"))
        self.agg.add_finding(self._make_vuln("CVE-2", "golang.org/x/net", "1.25.4"))
        assert len(self.agg.findings) == 1
        agg = list(self.agg.findings.values())[0]
        assert len(agg.details["vulnerabilities"]) == 2

    def test_v_prefix_normalization(self):
        """v1.0.0 and 1.0.0 should be same version."""
        self.agg.add_finding(self._make_vuln("CVE-1", "pkg", "v1.0.0"))
        self.agg.add_finding(self._make_vuln("CVE-2", "pkg", "1.0.0"))
        assert len(self.agg.findings) == 1

    def test_source_tracked(self):
        finding = self._make_vuln("CVE-1", "pkg", "1.0")
        self.agg.add_finding(finding, source="sbom.json")
        agg = list(self.agg.findings.values())[0]
        assert "sbom.json" in agg.found_in

    def test_fixed_version_calculated(self):
        self.agg.add_finding(self._make_vuln("CVE-1", "pkg", "1.0", fixed_version="1.2.3"))
        self.agg.add_finding(self._make_vuln("CVE-2", "pkg", "1.0", fixed_version="1.2.5"))
        agg = list(self.agg.findings.values())[0]
        # Should calculate aggregated fix covering both vulns
        assert agg.details.get("fixed_version") is not None


class TestAddQualityFinding:
    """Tests for _add_quality_finding - quality issue aggregation."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_creates_aggregate(self):
        finding = Finding(
            id="SCORECARD-lodash",
            type=FindingType.QUALITY,
            severity=Severity.MEDIUM,
            component="lodash",
            version="4.17.0",
            description="Score: 3.5/10",
            scanners=["deps_dev"],
            details={"overall_score": 3.5},
        )
        self.agg.add_finding(finding)
        assert len(self.agg.findings) == 1

    def test_multiple_quality_issues_aggregated(self):
        """Scorecard + maintainer risk for same component should aggregate."""
        scorecard = Finding(
            id="SCORECARD-pkg",
            type=FindingType.QUALITY,
            severity=Severity.MEDIUM,
            component="pkg",
            version="1.0",
            description="Score: 4.0/10",
            scanners=["deps_dev"],
            details={"overall_score": 4.0},
        )
        maintainer = Finding(
            id="MAINT-pkg",
            type=FindingType.QUALITY,
            severity=Severity.HIGH,
            component="pkg",
            version="1.0",
            description="Stale package",
            scanners=["maintainer_risk"],
            details={"risks": [{"type": "stale_package"}]},
        )
        self.agg.add_finding(scorecard)
        self.agg.add_finding(maintainer)
        assert len(self.agg.findings) == 1
        agg = list(self.agg.findings.values())[0]
        assert len(agg.details["quality_issues"]) == 2
        # Severity should escalate to HIGH
        assert agg.severity == "HIGH"


class TestMergeFindingsData:
    """Tests for _merge_findings_data - merging two findings into one."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_scanners_merged(self):
        target = Finding(
            id="pkg:1.0",
            type=FindingType.VULNERABILITY,
            severity=Severity.HIGH,
            component="pkg",
            version="1.0",
            description="",
            scanners=["trivy"],
            details={"vulnerabilities": [{"id": "CVE-1", "severity": "HIGH", "aliases": [], "scanners": ["trivy"]}]},
        )
        source = Finding(
            id="pkg:1.0",
            type=FindingType.VULNERABILITY,
            severity=Severity.MEDIUM,
            component="pkg",
            version="1.0",
            description="",
            scanners=["grype"],
            details={"vulnerabilities": [{"id": "CVE-2", "severity": "MEDIUM", "aliases": [], "scanners": ["grype"]}]},
        )
        self.agg._merge_findings_data(target, source)
        assert set(target.scanners) == {"trivy", "grype"}

    def test_severity_escalated(self):
        target = Finding(
            id="pkg:1.0",
            type=FindingType.VULNERABILITY,
            severity=Severity.LOW,
            component="pkg",
            version="1.0",
            description="",
            scanners=["a"],
            details={"vulnerabilities": []},
        )
        source = Finding(
            id="pkg:1.0",
            type=FindingType.VULNERABILITY,
            severity=Severity.CRITICAL,
            component="pkg",
            version="1.0",
            description="",
            scanners=["b"],
            details={"vulnerabilities": []},
        )
        self.agg._merge_findings_data(target, source)
        assert target.severity == "CRITICAL"


class TestGetFindings:
    """Tests for get_findings - the main output method with post-processing."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_empty_aggregator_returns_empty(self):
        assert self.agg.get_findings() == []

    def test_single_finding_returned(self):
        self.agg.add_finding(
            Finding(
                id="CVE-1",
                type=FindingType.VULNERABILITY,
                severity=Severity.HIGH,
                component="pkg",
                version="1.0",
                description="test",
                scanners=["trivy"],
                details={"fixed_version": "1.1"},
            )
        )
        findings = self.agg.get_findings()
        assert len(findings) == 1

    def test_non_vuln_non_sast_passed_through(self):
        """Non-vulnerability, non-SAST findings should pass through directly."""
        self.agg.add_finding(
            Finding(
                id="SECRET-1",
                type=FindingType.SECRET,
                severity=Severity.CRITICAL,
                component="config.py",
                version="",
                description="Secret found",
                scanners=["trufflehog"],
            )
        )
        findings = self.agg.get_findings()
        assert len(findings) == 1
        assert findings[0].type == "secret"

    def test_related_findings_linked_by_component(self):
        """Different finding types for same component should be cross-linked."""
        self.agg.add_finding(
            Finding(
                id="CVE-1",
                type=FindingType.VULNERABILITY,
                severity=Severity.HIGH,
                component="lodash",
                version="4.17.0",
                description="vuln",
                scanners=["trivy"],
                details={"fixed_version": "4.17.21"},
            )
        )
        self.agg.add_finding(
            Finding(
                id="OUTDATED-lodash",
                type=FindingType.OUTDATED,
                severity=Severity.INFO,
                component="lodash",
                version="4.17.0",
                description="outdated",
                scanners=["outdated"],
                details={"fixed_version": "4.17.21"},
            )
        )
        findings = self.agg.get_findings()
        assert len(findings) == 2
        # Both should reference each other
        vuln_f = next(f for f in findings if f.type == "vulnerability")
        out_f = next(f for f in findings if f.type == "outdated")
        assert out_f.id in vuln_f.related_findings
        assert vuln_f.id in out_f.related_findings


class TestAggregateDispatch:
    """Tests for the aggregate() dispatcher method."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_unknown_analyzer_ignored(self):
        """Unknown analyzer name should not raise."""
        self.agg.aggregate("nonexistent_scanner", {"some": "data"})
        assert len(self.agg.findings) == 0

    def test_empty_result_ignored(self):
        self.agg.aggregate("trivy", {})
        assert len(self.agg.findings) == 0

    def test_none_result_ignored(self):
        self.agg.aggregate("trivy", None)
        assert len(self.agg.findings) == 0

    def test_error_result_creates_system_warning(self):
        self.agg.aggregate("trivy", {"error": "Scanner crashed"})
        assert len(self.agg.findings) == 1
        f = list(self.agg.findings.values())[0]
        assert f.type == "system_warning"
        assert "trivy" in f.description
