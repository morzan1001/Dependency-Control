"""Tests for the ResultAggregator."""

import pytest

from app.core.constants import MAX_CROSS_LINK_GROUP_SIZE
from app.models.finding import Finding, FindingType, Severity
from app.services.aggregation import ResultAggregator
from app.services.component_identity import (
    extract_artifact_name,
    normalize_component,
)
from app.services.aggregation.merging import (
    merge_findings_data,
    merge_vulnerability_into_list,
)
from app.services.aggregation.versions import (
    aggregate_fixed_version,
    newest_first,
    normalize_version,
    parse_version_key,
)
from app.services.analyzers.maintainer_risk import MaintainerRiskAnalyzer

# One file carrying many SAST hits is a single "component" to the cross-linker.
_CROWDED_FILE = "app/handlers.py"


class TestParseVersionKey:
    @pytest.mark.parametrize("spelling", ["v1.2.3", "V1.2.3", "1.2.3"])
    def test_a_v_prefix_does_not_change_the_key(self, spelling):
        assert parse_version_key(spelling) == parse_version_key("1.2.3")

    def test_an_empty_version_has_an_empty_key(self):
        assert parse_version_key("") == ()

    @pytest.mark.parametrize(
        ("spelling", "same"),
        [
            pytest.param("5.2.20.RELEASE", "5.2.20", id="maven-release-qualifier"),
            pytest.param("4.1.100.Final", "4.1.100", id="maven-final-qualifier"),
            pytest.param("4.1.0", "4.1", id="trailing-zero"),
            pytest.param("1:2.30-1", "2.30-1", id="epoch"),
            pytest.param("2", "2.0.0", id="bare-major"),
        ],
    )
    def test_spellings_of_one_release_share_a_key(self, spelling, same):
        assert parse_version_key(spelling) == parse_version_key(same)

    @pytest.mark.parametrize(
        ("lower", "higher"),
        [
            pytest.param("1.2.3", "1.2.4", id="patch-bump"),
            pytest.param("1.9.9", "2.0.0", id="major-bump"),
            pytest.param("0.6.0+incompatible", "0.7.0", id="go-incompatible-suffix"),
            pytest.param("1.0.0-alpha", "1.0.0", id="prerelease-below-release"),
            pytest.param("3.0.0a1", "3.0.0", id="pep440-prerelease-below-release"),
            pytest.param("5.0.0-beta.2", "5.0.0-rc.1", id="rc-above-beta"),
            pytest.param("1.0.0-rc1", "1.0.0-rc2", id="prerelease-number"),
            pytest.param("1.0.0-rc", "1.0.0.1", id="longer-release-above-prerelease"),
            pytest.param("1.0.0", "1.0.0.1", id="longer-release-above-release"),
            pytest.param("1.0.0-SNAPSHOT", "1.0.0", id="maven-snapshot-below-release"),
            pytest.param("1.0.0-M1", "1.0.0", id="maven-milestone-below-release"),
            pytest.param("5.0.0.CR1", "5.0.0", id="maven-candidate-release-below-release"),
            pytest.param("1.0.dev1", "1.0a1", id="pep440-dev-below-alpha"),
            pytest.param("1.0", "1.0.post1", id="pep440-post-release-above-release"),
            pytest.param("1.0.post1", "1.0.1", id="post-release-below-next-number"),
            pytest.param("2.36-9", "2.36-9+deb12u4", id="debian-security-update-above-its-base"),
            pytest.param("3.4-1", "3.4-1+b6", id="debian-binnmu-above-its-base"),
            pytest.param("3.4-1+b6", "3.4-2", id="debian-binnmu-below-the-next-revision"),
            pytest.param("1.1.1", "1.1.1n", id="openssl-letter-release-above-base"),
            pytest.param("1.1.1", "1.1.1a", id="openssl-letter-a-is-no-alpha"),
            pytest.param("1.1.1n", "1.1.2", id="openssl-letter-release-below-next-patch"),
            pytest.param("0.6.0", "0.6.0+incompatible", id="go-incompatible-above-bare"),
        ],
    )
    def test_higher_version_compares_as_greater(self, lower, higher):
        assert parse_version_key(higher) > parse_version_key(lower)


class TestNewestFirst:
    def test_prereleases_rank_by_tag_below_their_release(self):
        assert newest_first({"5.0.0-beta.2", "5.0.0", "5.0.0-rc.1", "4.9.0"}) == [
            "5.0.0",
            "5.0.0-rc.1",
            "5.0.0-beta.2",
            "4.9.0",
        ]

    def test_a_post_release_ranks_above_its_release(self):
        assert newest_first(["1.0", "1.0.post1"]) == ["1.0.post1", "1.0"]

    def test_a_debian_binnmu_ranks_between_its_base_and_the_next_revision(self):
        assert newest_first(["3.4-1", "3.4-1+b6", "3.4-2"]) == ["3.4-2", "3.4-1+b6", "3.4-1"]

    def test_spellings_of_one_version_order_the_same_whatever_the_input_order(self):
        assert newest_first(["v1.0.0", "1.0.0"]) == newest_first(["1.0.0", "v1.0.0"])


class TestNormalizeVersion:
    """Tests for _normalize_version - strips Go/v prefixes."""

    def setup_method(self):
        self.agg = ResultAggregator()

    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            pytest.param("go1.25.4", "1.25.4", id="go-prefix-stripped"),
            pytest.param("v1.25.4", "1.25.4", id="v-prefix-stripped"),
            pytest.param("1.25.4", "1.25.4", id="plain-version-unchanged"),
            pytest.param("", "unknown", id="empty-returns-unknown"),
            pytest.param(None, "unknown", id="none-returns-unknown"),
            # Only a prefix followed by a digit is a version prefix.
            pytest.param("gomodule", "gomodule", id="go-without-digit-not-stripped"),
            pytest.param("version", "version", id="v-without-digit-not-stripped"),
            pytest.param("V2.0.0", "2.0.0", id="uppercase-lowered"),
            pytest.param("  1.0.0  ", "1.0.0", id="whitespace-stripped"),
        ],
    )
    def test_version_normalizes_to_expected_string(self, version, expected):
        assert normalize_version(version) == expected


class TestNormalizeComponent:
    """Tests for _normalize_component."""

    def setup_method(self):
        self.agg = ResultAggregator()

    @pytest.mark.parametrize(
        ("component", "expected"),
        [
            pytest.param("Lodash", "lodash", id="lowercased"),
            pytest.param("  requests  ", "requests", id="whitespace-stripped"),
            pytest.param("", "unknown", id="empty-returns-unknown"),
            pytest.param(None, "unknown", id="none-returns-unknown"),
        ],
    )
    def test_component_normalizes_to_expected_string(self, component, expected):
        assert normalize_component(component) == expected


class TestExtractArtifactName:
    """Tests for _extract_artifact_name - artifact extraction for grouping."""

    def setup_method(self):
        self.agg = ResultAggregator()

    @pytest.mark.parametrize(
        ("component", "expected"),
        [
            pytest.param("lodash", "lodash", id="plain-name"),
            pytest.param("org.postgresql:postgresql", "postgresql", id="maven-group-artifact"),
            pytest.param("com.google.guava:guava", "guava", id="maven-only-last-segment-after-colon"),
            pytest.param("@angular/core", "@angular/core", id="npm-scope-is-part-of-the-name"),
            pytest.param("vendor/lib/core.js", "core.js", id="path-keeps-its-basename"),
            pytest.param("Lodash", "lodash", id="case-insensitive"),
            pytest.param("  lodash  ", "lodash", id="whitespace-stripped"),
            pytest.param("", "unknown", id="empty-returns-unknown"),
            pytest.param(None, "unknown", id="none-returns-unknown"),
        ],
    )
    def test_artifact_name_extracted_from_component(self, component, expected):
        assert extract_artifact_name(component) == expected


def _entries(*fixes):
    return [{"fixed_version": fix} for fix in fixes]


class TestAggregateFixedVersion:
    @pytest.mark.parametrize(
        ("fixes", "expected"),
        [
            pytest.param(["1.2.5"], "1.2.5", id="single-fix"),
            pytest.param(["1.2.3", "1.2.5"], "1.2.5", id="two-vulns-same-major-picks-highest"),
        ],
    )
    def test_one_major_line_answers_with_one_version(self, fixes, expected):
        assert aggregate_fixed_version(_entries(*fixes), None) == expected

    @pytest.mark.parametrize(
        ("fixes", "expected"),
        [
            # Per major line the highest fix wins: max(1.2.5, 1.2.6) and max(2.0.1, 2.0.3).
            pytest.param(["1.2.5, 2.0.1", "1.2.6, 2.0.3"], "1.2.6, 2.0.3", id="two-vulns-two-majors"),
            pytest.param(["1.5.0, 2.1.0"], "1.5.0, 2.1.0", id="one-vuln-two-majors"),
        ],
    )
    def test_every_major_line_that_covers_all_vulns_is_returned(self, fixes, expected):
        assert aggregate_fixed_version(_entries(*fixes), None) == expected

    def test_no_entries_returns_none(self):
        assert aggregate_fixed_version([], None) is None

    @pytest.mark.parametrize(
        ("fixes", "expected"),
        [
            pytest.param(["2.0.0-rc1, 2.0.0"], "2.0.0", id="release-beside-its-rc"),
            pytest.param(["1.2.3rc1, 1.2.4"], "1.2.4", id="release-over-a-lower-rc"),
            pytest.param(["3.0.0a1"], "3.0.0a1", id="prerelease-when-no-release-fixes"),
            pytest.param(["1.0.0-M1, 1.0.1"], "1.0.1", id="release-over-a-milestone"),
            pytest.param(["5.2.20.RELEASE, 5.3.18"], "5.2.20.RELEASE", id="maven-qualifier-is-a-release"),
            pytest.param(["2.36-9", "2.36-9+deb12u4"], "2.36-9+deb12u4", id="debian-security-update-fixes-both"),
        ],
    )
    def test_a_release_fix_is_preferred_over_a_prerelease(self, fixes, expected):
        assert aggregate_fixed_version(_entries(*fixes), None) == expected

    def test_major_must_cover_all_vulns(self):
        assert aggregate_fixed_version(_entries("1.5.0, 2.0.1", "2.0.3"), None) == "2.0.3"

    def test_an_advisory_without_a_fix_leaves_the_record_unfixed(self):
        entries = [{"id": "CVE-A", "fixed_version": None}, {"id": "CVE-B", "fixed_version": "3.0.11-1~deb12u2"}]
        assert aggregate_fixed_version(entries, "3.0.9-1") is None

    @pytest.mark.parametrize(
        ("installed", "fixes", "expected"),
        [
            pytest.param("2.13.0", ["2.12.7.1, 2.13.4.2"], "2.13.4.2", id="jackson-backport-below-install"),
            pytest.param("2.14.1", ["2.15.0, 2.12.2, 2.3.1", "2.16.0, 2.12.2, 2.3.1"], "2.16.0", id="log4j-two-cves"),
            pytest.param("9.9.9", ["1.2.3"], "1.2.3", id="no-candidate-above-install-keeps-the-list"),
        ],
    )
    def test_fixes_below_the_installed_release_are_not_upgrade_targets(self, installed, fixes, expected):
        assert aggregate_fixed_version(_entries(*fixes), installed) == expected

    def test_mixed_numeric_and_named_majors_sort_numerically(self):
        assert aggregate_fixed_version(_entries("9.1.0, 10.2.0, r5"), None) == "9.1.0, 10.2.0, r5"

    @pytest.mark.parametrize(
        "fixes",
        [
            pytest.param(["v1.2.3"], id="v-prefix"),
            pytest.param(["3.0.0a1", "3.0.1"], id="alphanumeric-prerelease"),
            pytest.param(["1.2.3rc1, 2.0.0", "1.2.4, 2.0.1"], id="rc-against-release"),
        ],
    )
    def test_unusual_version_shapes_still_answer_a_fix(self, fixes):
        assert aggregate_fixed_version(_entries(*fixes), None) is not None


class TestMergeVulnerabilityIntoList:
    """Tests for _merge_vulnerability_into_list - deduplicates by ID/aliases."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_new_entry_appended(self):
        target = []
        entry = {"id": "CVE-2023-1234", "severity": "HIGH", "aliases": []}
        merge_vulnerability_into_list(target, entry)
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
        merge_vulnerability_into_list(target, entry)
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
        merge_vulnerability_into_list(target, entry)
        assert len(target) == 1
        # Should keep the original ID (CVE)
        assert target[0]["id"] == "CVE-2023-1234"
        # GHSA should be in aliases
        assert "GHSA-xxxx" in target[0]["aliases"]

    def test_no_match_creates_new_entry(self):
        target = [{"id": "CVE-2023-1111", "aliases": [], "scanners": []}]
        entry = {"id": "CVE-2023-2222", "aliases": [], "scanners": []}
        merge_vulnerability_into_list(target, entry)
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
        merge_vulnerability_into_list(target, entry)
        assert target[0]["cvss_score"] == 9.8
        assert target[0]["cvss_vector"] == "new"

    @pytest.mark.parametrize(
        ("target_fixed", "entry_fixed", "expected"),
        [
            pytest.param("1.2.3", "1.2.4", "1.2.4", id="one-release-line-keeps-the-higher-claim"),
            pytest.param("1.2.6", "1.2.5", "1.2.6", id="higher-claim-wins-in-either-order"),
            pytest.param("1.2.5, 2.0.1", "1.2.6", "1.2.6, 2.0.1", id="distinct-lines-are-kept"),
            pytest.param("2.21.4, 2.18.8", "2.21.4, 2.2.0", "2.2.0, 2.18.8, 2.21.4", id="deduplicated-and-ordered"),
            pytest.param(None, "1.2.3", "1.2.3", id="added-when-target-has-none"),
            pytest.param("4.17.21, 4.17.12", "4.17.21, 4.17.12", "4.17.12, 4.17.21", id="identical-lists-are-kept"),
            pytest.param("4.17.12", "4.17.21, 4.17.12", "4.17.12, 4.17.21", id="agreeing-lowest-keeps-both"),
            pytest.param("1.2.5", "1.2.3.4, 1.2.5", "1.2.5", id="below-the-higher-lowest-is-dropped"),
            pytest.param("2.0.0", "2.0.1", "2.0.1", id="zero-patch-shares-its-release-line"),
            pytest.param("1.2.5, 3.0.0", "3.0.2", "1.2.5, 3.0.2", id="zero-patch-beside-another-line"),
            pytest.param("3.0.0-rc1", "3.0.1", "3.0.1", id="zero-patch-prerelease-shares-its-release-line"),
            pytest.param("2", "2.0.1", "2.0.1", id="bare-major-shares-its-release-line"),
        ],
    )
    def test_fixed_versions_of_both_entries_are_merged(self, target_fixed, entry_fixed, expected):
        target = [{"id": "CVE-1", "aliases": [], "scanners": [], "fixed_version": target_fixed}]
        entry = {"id": "CVE-1", "aliases": [], "scanners": [], "fixed_version": entry_fixed}
        merge_vulnerability_into_list(target, entry)
        assert target[0]["fixed_version"] == expected


def _grype_ghsa_entry():
    return {
        "id": "GHSA-3pjw-73gf-8qr5",
        "severity": "HIGH",
        "description": "jackson-databind vulnerable to deep wrapper array nesting",
        "fixed_version": "2.21.4",
        "cvss_score": 7.7,
        "cvss_vector": None,
        "references": [],
        "aliases": [],
        "scanners": ["grype"],
        "details": {},
    }


def _trivy_cve_entry():
    return {
        "id": "CVE-2026-59888",
        "severity": "HIGH",
        "description": "jackson-databind: DoS via deeply nested wrapper arrays",
        "fixed_version": "2.18.8, 2.21.4",
        "cvss_score": 7.5,
        "cvss_vector": None,
        "references": [],
        "aliases": [],
        "scanners": ["trivy"],
        "details": {},
    }


def _osv_ghsa_entry_with_cve_alias():
    return {
        "id": "GHSA-3pjw-73gf-8qr5",
        "severity": "HIGH",
        "description": "Deeply nested wrapper array nesting in jackson-databind",
        "fixed_version": "2.21.4",
        "cvss_score": None,
        "cvss_vector": None,
        "references": [],
        "aliases": ["CVE-2026-59888"],
        "scanners": ["osv"],
        "details": {},
    }


class TestConvergentVulnerabilityMerge:
    """Entries linked by an alias contributed later must collapse into one (C10)."""

    def test_late_alias_collapses_previously_split_entries(self):
        target = []
        merge_vulnerability_into_list(target, _grype_ghsa_entry())
        merge_vulnerability_into_list(target, _trivy_cve_entry())
        assert len(target) == 2

        merge_vulnerability_into_list(target, _osv_ghsa_entry_with_cve_alias())

        assert len(target) == 1
        merged = target[0]
        assert merged["id"] == "CVE-2026-59888"
        assert set(merged["aliases"]) == {"GHSA-3pjw-73gf-8qr5"}
        assert set(merged["scanners"]) == {"grype", "trivy", "osv"}
        assert merged["cvss_score"] == 7.7
        assert merged["fixed_version"] == "2.18.8, 2.21.4"

    def test_all_analyzer_orders_converge_on_one_cve_keyed_entry(self):
        import itertools

        builders = (_grype_ghsa_entry, _trivy_cve_entry, _osv_ghsa_entry_with_cve_alias)
        for order in itertools.permutations(builders):
            target = []
            for build in order:
                merge_vulnerability_into_list(target, build())
            names = [b.__name__ for b in order]
            assert len(target) == 1, names
            assert target[0]["id"] == "CVE-2026-59888", names
            assert set(target[0]["scanners"]) == {"grype", "trivy", "osv"}, names
            assert target[0]["fixed_version"] == "2.18.8, 2.21.4", names

    def test_aggregator_collapses_entries_linked_by_late_alias(self):
        agg = ResultAggregator()
        for vuln_id, aliases, scanner, fixed in (
            ("GHSA-3pjw-73gf-8qr5", [], "grype", "2.21.4"),
            ("CVE-2026-59888", [], "trivy", "2.18.8, 2.21.4"),
            ("GHSA-3pjw-73gf-8qr5", ["CVE-2026-59888"], "osv", "2.21.4"),
        ):
            agg.add_finding(
                Finding(
                    id=vuln_id,
                    type=FindingType.VULNERABILITY,
                    severity="HIGH",
                    component="jackson-databind",
                    version="2.15.0",
                    description=f"Vuln {vuln_id}",
                    scanners=[scanner],
                    aliases=aliases,
                    details={"fixed_version": fixed},
                )
            )

        assert len(agg.findings) == 1
        aggregate = next(iter(agg.findings.values()))
        vulns = aggregate.details["vulnerabilities"]
        assert len(vulns) == 1
        assert vulns[0]["id"] == "CVE-2026-59888"
        assert set(vulns[0]["scanners"]) == {"grype", "trivy", "osv"}


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
        key = next(iter(self.agg.findings.keys()))
        agg = self.agg.findings[key]
        assert agg.component == "lodash"
        assert len(agg.details["vulnerabilities"]) == 1

    @pytest.mark.parametrize(
        ("component", "first_version", "second_version"),
        [
            pytest.param("lodash", "4.17.0", "4.17.0", id="identical-version"),
            pytest.param("golang.org/x/net", "go1.25.4", "1.25.4", id="go-prefixed-version"),
        ],
    )
    def test_two_cves_on_one_component_version_share_an_aggregate(self, component, first_version, second_version):
        self.agg.add_finding(self._make_vuln("CVE-1", component, first_version))
        self.agg.add_finding(self._make_vuln("CVE-2", component, second_version))
        assert len(self.agg.findings) == 1
        agg = next(iter(self.agg.findings.values()))
        assert len(agg.details["vulnerabilities"]) == 2

    def test_different_components_separate(self):
        self.agg.add_finding(self._make_vuln("CVE-1", "lodash", "4.17.0"))
        self.agg.add_finding(self._make_vuln("CVE-2", "express", "4.17.0"))
        assert len(self.agg.findings) == 2

    def test_severity_escalation(self):
        """Aggregate severity should be the max of all findings."""
        self.agg.add_finding(self._make_vuln("CVE-1", "pkg", "1.0", severity="LOW"))
        self.agg.add_finding(self._make_vuln("CVE-2", "pkg", "1.0", severity="CRITICAL"))
        agg = next(iter(self.agg.findings.values()))
        assert agg.severity == "CRITICAL"

    def test_v_prefix_normalization(self):
        """v1.0.0 and 1.0.0 should be same version."""
        self.agg.add_finding(self._make_vuln("CVE-1", "pkg", "v1.0.0"))
        self.agg.add_finding(self._make_vuln("CVE-2", "pkg", "1.0.0"))
        assert len(self.agg.findings) == 1

    def test_source_tracked(self):
        finding = self._make_vuln("CVE-1", "pkg", "1.0")
        self.agg.add_finding(finding, source="sbom.json")
        agg = next(iter(self.agg.findings.values()))
        assert "sbom.json" in agg.found_in

    def test_fixed_version_covers_every_advisory(self):
        self.agg.add_finding(self._make_vuln("CVE-1", "pkg", "1.0", fixed_version="1.2.3"))
        self.agg.add_finding(self._make_vuln("CVE-2", "pkg", "1.0", fixed_version="1.2.5"))
        [finding] = self.agg.get_findings()
        assert finding.details["fixed_version"] == "1.2.5"

    def test_single_and_multi_scanner_aggregates_agree_on_the_fixed_version(self):
        single = ResultAggregator()
        single.add_finding(self._make_vuln("CVE-1", "lodash", "4.17.0", fixed_version="4.17.21, 4.17.12"))
        double = ResultAggregator()
        double.add_finding(self._make_vuln("CVE-1", "lodash", "4.17.0", fixed_version="4.17.21, 4.17.12"))
        double.add_finding(self._make_vuln("CVE-1", "lodash", "4.17.0", fixed_version="4.17.12"))

        [only] = single.get_findings()
        [merged] = double.get_findings()
        assert only.details["fixed_version"] == merged.details["fixed_version"] == "4.17.12"

    @pytest.mark.parametrize(
        ("component", "installed", "fixes", "expected"),
        [
            pytest.param("lodash", "4.17.15", "4.17.21, 4.17.12", "4.17.21", id="backport-below-installed"),
            pytest.param("foo", "1.2.4", "1.2.3.4, 1.2.5", "1.2.5", id="four-part-backport-below-installed"),
        ],
    )
    def test_reporting_a_cve_twice_keeps_the_upgrade_above_the_installed_version(
        self, component, installed, fixes, expected
    ):
        single = ResultAggregator()
        single.add_finding(self._make_vuln("CVE-1", component, installed, fixed_version=fixes), source="a.json")
        double = ResultAggregator()
        for sbom in ("a.json", "b.json"):
            double.add_finding(self._make_vuln("CVE-1", component, installed, fixed_version=fixes), source=sbom)

        [only] = single.get_findings()
        [merged] = double.get_findings()
        assert only.details["fixed_version"] == merged.details["fixed_version"] == expected

    def test_a_cve_without_a_fix_leaves_the_component_without_one(self):
        self.agg.add_finding(self._make_vuln("CVE-A", "libssl3", "3.0.9-1", severity="CRITICAL"))
        self.agg.add_finding(self._make_vuln("CVE-B", "libssl3", "3.0.9-1", "LOW", fixed_version="3.0.11-1~deb12u2"))
        [finding] = self.agg.get_findings()
        assert finding.severity == "CRITICAL"
        assert finding.details["fixed_version"] is None

    def test_fixed_version_is_derived_once_per_final_finding(self, monkeypatch):
        from app.services.aggregation import aggregator as aggregator_module

        calls = []
        real = aggregator_module.aggregate_fixed_version
        monkeypatch.setattr(
            aggregator_module, "aggregate_fixed_version", lambda *args: calls.append(args) or real(*args)
        )
        for n in range(5):
            self.agg.add_finding(self._make_vuln(f"CVE-{n}", "linux-libc-dev", "6.1.0", fixed_version=f"6.1.{n + 1}"))
        self.agg.get_findings()
        assert len(calls) == 1


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
        agg = next(iter(self.agg.findings.values()))
        assert len(agg.details["quality_issues"]) == 2
        # Severity should escalate to HIGH
        assert agg.severity == "HIGH"


class TestMaintenanceIssueFlag:
    @staticmethod
    def _quality_for(risks):
        issue = {
            "component": "jetty-util",
            "version": "9.4.0",
            "risks": risks,
            "severity": MaintainerRiskAnalyzer()._calculate_overall_severity(risks),
        }
        agg = ResultAggregator()
        agg.aggregate("maintainer_risk", {"maintainer_issues": [issue]})
        [quality] = agg.get_findings()
        return quality

    def test_an_inactive_repository_alone_is_a_maintenance_issue(self):
        """Outside npm/PyPI the GitHub push date is the only staleness signal."""
        risks, _ = MaintainerRiskAnalyzer()._assess_all_risks(
            {"github_info": {"days_since_push": 1200, "pushed_at": "2023-06-01T00:00:00Z"}}, "maven"
        )
        assert [r["type"] for r in risks] == ["inactive_repo"]

        assert self._quality_for(risks).details["has_maintenance_issues"] is True

    @pytest.mark.parametrize(
        ("risk_type", "expected"),
        [
            ("stale_package", True),
            ("infrequent_updates", True),
            ("archived_repo", True),
            ("inactive_repo", True),
            ("unaddressed_issues", False),
            ("single_maintainer", False),
            ("free_email_maintainer", False),
        ],
    )
    def test_every_emitted_risk_type_has_a_decided_flag(self, risk_type, expected):
        risks = [{"type": risk_type, "severity_score": 2, "message": risk_type}]

        assert self._quality_for(risks).details["has_maintenance_issues"] is expected


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
        merge_findings_data(target, source)
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
        merge_findings_data(target, source)
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

    def test_cross_format_component_names_merged(self):
        """Findings for 'org.postgresql:postgresql' and 'postgresql' with same
        version should be merged in get_findings() instead of appearing as duplicates."""
        self.agg.add_finding(
            Finding(
                id="CVE-1",
                type=FindingType.VULNERABILITY,
                severity=Severity.HIGH,
                component="org.postgresql:postgresql",
                version="42.7.3",
                description="vuln from trivy",
                scanners=["trivy"],
                details={"fixed_version": "42.7.4"},
            )
        )
        self.agg.add_finding(
            Finding(
                id="CVE-1",
                type=FindingType.VULNERABILITY,
                severity=Severity.HIGH,
                component="postgresql",
                version="42.7.3",
                description="vuln from grype",
                scanners=["grype"],
                details={"fixed_version": "42.7.4"},
            )
        )
        findings = self.agg.get_findings()
        vuln_findings = [f for f in findings if f.type == "vulnerability"]
        # Should be merged into one finding, not two
        assert len(vuln_findings) == 1
        # Both scanners should be present
        assert set(vuln_findings[0].scanners) >= {"trivy", "grype"}

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

    def test_cross_format_related_findings_linked(self):
        """Quality for 'org.postgresql:postgresql' and Vulnerability for 'postgresql'
        should be linked as related findings via artifact name normalization."""
        self.agg.add_finding(
            Finding(
                id="CVE-1",
                type=FindingType.VULNERABILITY,
                severity=Severity.HIGH,
                component="postgresql",
                version="42.7.3",
                description="vuln",
                scanners=["trivy"],
                details={"fixed_version": "42.7.4"},
            )
        )
        self.agg.add_finding(
            Finding(
                id="OUTDATED-postgresql",
                type=FindingType.OUTDATED,
                severity=Severity.INFO,
                component="org.postgresql:postgresql",
                version="42.7.3",
                description="outdated",
                scanners=["outdated"],
                details={"fixed_version": "42.8.0"},
            )
        )
        findings = self.agg.get_findings()
        vuln_f = next(f for f in findings if f.type == "vulnerability")
        out_f = next(f for f in findings if f.type == "outdated")
        # Should be linked despite different component name formats
        assert out_f.id in vuln_f.related_findings
        assert vuln_f.id in out_f.related_findings

    def test_findings_are_returned_in_ascending_sort_key_order(self):
        """adhoc's finding cap slices this list and documents the direction it relies on."""
        self.agg.add_finding(
            Finding(
                id="SECRET-1",
                type=FindingType.SECRET,
                severity=Severity.CRITICAL,
                component="zzz-config.yaml",
                version="",
                description="Secret found",
                scanners=["trufflehog"],
            )
        )
        for component in ("zlib", "alpha", "mbedtls"):
            self.agg.add_finding(
                Finding(
                    id=f"CVE-{component}",
                    type=FindingType.VULNERABILITY,
                    severity=Severity.HIGH,
                    component=component,
                    version="1.0",
                    description="vuln",
                    scanners=["trivy"],
                    details={"fixed_version": "2.0"},
                )
            )

        findings = self.agg.get_findings()

        assert [f.component for f in findings] == ["zzz-config.yaml", "alpha", "mbedtls", "zlib"]

    def test_vulnerability_entries_are_ordered_by_id(self):
        """The chat tool quotes the first five entries, so arrival order must not pick them."""
        for cve in ("CVE-2026-9", "CVE-2026-1", "CVE-2026-5"):
            self.agg.add_finding(
                Finding(
                    id=cve,
                    type=FindingType.VULNERABILITY,
                    severity=Severity.HIGH,
                    component="openssl",
                    version="3.0.0",
                    description="vuln",
                    scanners=["trivy"],
                    details={"fixed_version": "3.0.1"},
                )
            )

        entries = self.agg.get_findings()[0].details["vulnerabilities"]

        assert [e["id"] for e in entries] == ["CVE-2026-1", "CVE-2026-5", "CVE-2026-9"]

    def _add_sast_findings_on_one_file(self, count):
        self.agg.aggregate(
            "opengrep",
            {
                "results": [
                    {
                        "check_id": f"rules.python.eval-{index}",
                        "path": _CROWDED_FILE,
                        "start": {"line": index + 1, "col": 1},
                        "end": {"line": index + 1, "col": 20},
                        "extra": {"severity": "WARNING", "message": "eval() detected", "metadata": {}},
                    }
                    for index in range(count)
                ]
            },
        )

    def _add_secret_on_the_crowded_file(self):
        self.agg.aggregate(
            "trufflehog",
            {
                "findings": [
                    {
                        "DetectorType": "2",
                        "Raw": "AKIAIOSFODNN7EXAMPLE",
                        "Verified": True,
                        "SourceMetadata": {"Data": {"Filesystem": {"file": _CROWDED_FILE}}},
                    }
                ]
            },
        )

    def test_same_type_hits_in_one_file_are_counted_not_linked(self):
        """Pairwise ids of one file's SAST hits grow quadratically and exchange no context."""
        self._add_sast_findings_on_one_file(MAX_CROSS_LINK_GROUP_SIZE)

        findings = self.agg.get_findings()

        assert len(findings) == MAX_CROSS_LINK_GROUP_SIZE
        assert all(f.related_findings == [] for f in findings)
        assert all(f.related_findings_omitted == MAX_CROSS_LINK_GROUP_SIZE - 1 for f in findings)

    def test_different_types_in_one_file_link_to_each_other(self):
        self._add_sast_findings_on_one_file(2)
        self._add_secret_on_the_crowded_file()

        findings = self.agg.get_findings()

        [secret] = [f for f in findings if f.type == FindingType.SECRET]
        sast = [f for f in findings if f.type == FindingType.SAST]
        assert sorted(secret.related_findings) == sorted(f.id for f in sast)
        assert secret.related_findings_omitted is None
        assert secret.details["additional_finding_types"] == [{"type": "sast", "severity": "MEDIUM"}]
        for hit in sast:
            assert hit.related_findings == [secret.id]
            assert hit.related_findings_omitted == 1
            assert hit.details["additional_finding_types"] == [{"type": "secret", "severity": "CRITICAL"}]

    def test_a_group_past_the_cap_keeps_its_badges(self):
        self._add_sast_findings_on_one_file(MAX_CROSS_LINK_GROUP_SIZE)
        self._add_secret_on_the_crowded_file()

        findings = self.agg.get_findings()

        [secret] = [f for f in findings if f.type == FindingType.SECRET]
        assert secret.related_findings == []
        assert secret.details["additional_finding_types"] == [{"type": "sast", "severity": "MEDIUM"}]

    def test_a_group_past_the_cap_is_left_unlinked(self):
        """Pairwise linking of one crowded file is quadratic and tells a reader nothing."""
        self._add_sast_findings_on_one_file(MAX_CROSS_LINK_GROUP_SIZE + 1)

        findings = self.agg.get_findings()

        assert len(findings) == MAX_CROSS_LINK_GROUP_SIZE + 1
        assert all(f.related_findings == [] for f in findings)

    def test_a_group_past_the_cap_says_how_many_it_did_not_link(self):
        """An empty related_findings otherwise reads exactly like a finding with no siblings."""
        self._add_sast_findings_on_one_file(MAX_CROSS_LINK_GROUP_SIZE + 1)

        findings = self.agg.get_findings()

        assert all(f.related_findings_omitted == MAX_CROSS_LINK_GROUP_SIZE for f in findings)

    def test_a_lone_finding_omits_nothing(self):
        self._add_sast_findings_on_one_file(1)

        findings = self.agg.get_findings()

        assert findings[0].related_findings == []
        assert findings[0].related_findings_omitted is None


class TestAggregateDispatch:
    """Tests for the aggregate() dispatcher method."""

    def setup_method(self):
        self.agg = ResultAggregator()

    @pytest.mark.parametrize(
        ("analyzer", "result"),
        [
            pytest.param("nonexistent_scanner", {"some": "data"}, id="unknown-analyzer"),
            pytest.param("trivy", {}, id="empty-result"),
            pytest.param("trivy", None, id="none-result"),
        ],
    )
    def test_nothing_to_dispatch_is_ignored(self, analyzer, result):
        self.agg.aggregate(analyzer, result)
        assert len(self.agg.findings) == 0

    def test_error_result_creates_system_warning(self):
        self.agg.aggregate("trivy", {"error": "Scanner crashed"})
        assert len(self.agg.findings) == 1
        f = next(iter(self.agg.findings.values()))
        assert f.type == "system_warning"
        assert "trivy" in f.description

    @pytest.mark.parametrize("order", [(0, 1), (1, 0)])
    def test_every_failure_of_one_analyzer_stays_in_the_description(self, order):
        # cli_base shapes: a timeout on one SBOM, an exception on another.
        failures = [
            ({"error": "osv analysis failed", "details": "osv timed out after 300 seconds"}, "sbom-a"),
            ({"error": "Exception during osv analysis: 503 Service Unavailable"}, "sbom-b"),
        ]
        for i in order:
            result, source = failures[i]
            self.agg.aggregate("osv", result, source=source)

        [f] = self.agg.get_findings()
        assert f.description == (
            "Scanner 'osv' failed: Exception during osv analysis: 503 Service Unavailable; "
            "Scanner 'osv' failed: osv analysis failed"
        )
        assert {e["source"] for e in f.details["errors"]} == {"sbom-a", "sbom-b"}


class TestStoredEntryShape:
    """Each advisory entry stores a field once, at the level its readers use."""

    def test_lifted_scanner_fields_are_not_copied_into_the_entry_details(self):
        agg = ResultAggregator()
        agg.add_finding(
            Finding(
                id="CVE-2024-1",
                type=FindingType.VULNERABILITY,
                severity="HIGH",
                component="foo",
                version="1.2.0",
                description="d",
                scanners=["trivy"],
                details={
                    "fixed_version": "1.2.6",
                    "cvss_score": 7.5,
                    "cvss_vector": "T",
                    "references": ["https://a"],
                    "ecosystem_specific": {"imports": []},
                    "published_date": "2024-01-01",
                },
            ),
            source="sbom-a.json",
        )
        [finding] = agg.get_findings()
        [entry] = finding.details["vulnerabilities"]

        assert entry["fixed_version"] == "1.2.6"
        assert entry["cvss_score"] == 7.5
        assert entry["details"] == {"published_date": "2024-01-01"}
        assert "description_source" not in entry
        assert "source" not in entry

    def test_quality_entries_leave_the_sbom_to_found_in(self):
        agg = ResultAggregator()
        for sbom in ("sbom-a.json", "sbom-b.json"):
            agg.add_finding(
                Finding(
                    id="MAINT-lodash",
                    type=FindingType.QUALITY,
                    severity=Severity.MEDIUM,
                    component="lodash",
                    version="4.17.0",
                    description="unmaintained",
                    scanners=["maintainer_risk"],
                ),
                source=sbom,
            )
        [finding] = agg.get_findings()
        assert finding.found_in == ["sbom-a.json", "sbom-b.json"]
        assert "source" not in finding.details["quality_issues"][0]
