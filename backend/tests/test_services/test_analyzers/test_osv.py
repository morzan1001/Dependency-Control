"""Unit tests for the OSV analyzer's pure helpers (CVSS-score extraction, withdrawn handling, per-component data)."""

from typing import Any

import pytest

from app.services.analyzers.osv import OSVAnalyzer
from tests.helpers.osv import (
    ALPINE_OPENSSL,
    DEBIAN_OPENSSL,
    DJANGO_REDOS,
    GO_RAPID_RESET,
    LOG4SHELL,
    MALWARE_COMBINEZONE,
    REQUEST_SSRF,
    UBUNTU_OPENSSL,
    URLLIB3_CRLF,
)


def _purl(purl: str) -> dict[str, Any]:
    return {"package": {"purl": purl}}


_LODASH = _purl("pkg:npm/lodash@4.17.11")
_DJANGO_4_2_0 = _purl("pkg:pypi/django@4.2.0")
_LOG4J_CORE_2_14_1 = _purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
_OPENSSL_ON_ALPINE_3_17 = {"package": {"ecosystem": "Alpine:v3.17", "name": "openssl"}, "version": "3.0.8-r0"}
_OPENSSL_ON_DEBIAN_12 = {"package": {"ecosystem": "Debian:12", "name": "openssl"}, "version": "3.0.9-1"}
_OPENSSL_ON_UBUNTU_20_04 = _purl("pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.24")


def _normalized(record: dict[str, Any], query: dict[str, Any]) -> dict[str, Any]:
    return OSVAnalyzer()._normalize_vulnerabilities([record], query)[0]


def _without_purls(record: dict[str, Any]) -> dict[str, Any]:
    """The record as a source without ``package.purl`` serves it; the OSV schema makes the field optional."""
    affected = [
        {**entry, "package": {k: v for k, v in entry["package"].items() if k != "purl"}} for entry in record["affected"]
    ]
    return {**record, "affected": affected}


class TestParseCvssScore:
    """_parse_cvss_score: numeric scores pass through, vectors are scored."""

    def setup_method(self):
        self.analyzer = OSVAnalyzer()

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            pytest.param("7.5", 7.5, id="numeric-passthrough"),
            pytest.param("0.0", 0.0, id="zero"),
            # OSV rates with a vector and no number; returning None here discards the rating.
            pytest.param("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, id="bare-v3-vector"),
            # 9.3 as published by FIRST's own calculator for this vector.
            pytest.param("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, id="bare-v4-vector"),
        ],
    )
    def test_a_rated_input_yields_its_score(self, raw, expected):
        assert self.analyzer._parse_cvss_score(raw) == expected

    def test_v2_vector_returns_none(self):
        # No source in the corpus carries v2; it stays unscored rather than mis-scored as v3.
        assert self.analyzer._parse_cvss_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None

    def test_garbage_input_returns_none(self):
        assert self.analyzer._parse_cvss_score("not-a-cvss-score") is None
        assert self.analyzer._parse_cvss_score("") is None


class TestWithdrawnVulnerabilities:
    """Vulnerabilities carrying a `withdrawn` timestamp are dropped."""

    def setup_method(self):
        self.analyzer = OSVAnalyzer()

    def test_withdrawn_vulnerabilities_are_dropped(self):
        vulns = [
            {"id": "GHSA-active", "summary": "live", "severity": [{"type": "CVSS_V3", "score": "7.5"}]},
            {
                "id": "GHSA-withdrawn",
                "summary": "retracted",
                "withdrawn": "2024-06-01T00:00:00Z",
                "severity": [{"type": "CVSS_V3", "score": "9.0"}],
            },
        ]
        normalized = self.analyzer._normalize_vulnerabilities(vulns, _LODASH)
        ids = [v["id"] for v in normalized]
        assert "GHSA-active" in ids
        assert "GHSA-withdrawn" not in ids

    @pytest.mark.parametrize(
        "vuln",
        [
            pytest.param({"id": "GHSA-x", "summary": "active"}, id="no-withdrawn-field"),
            # An empty string isn't a valid withdrawn timestamp; keep the vuln.
            pytest.param({"id": "GHSA-x", "summary": "active", "withdrawn": ""}, id="empty-withdrawn-field"),
        ],
    )
    def test_a_vuln_without_a_withdrawn_timestamp_is_kept(self, vuln):
        normalized = self.analyzer._normalize_vulnerabilities([vuln], _LODASH)
        assert len(normalized) == 1


class TestNormalizedEntryShape:
    """The fields normalize_osv reads, resolved from the raw record."""

    def test_an_entry_carries_the_resolved_fields_of_the_record(self):
        assert _normalized(DJANGO_REDOS, _DJANGO_4_2_0) == {
            "id": "GHSA-vm8q-m57g-pff3",
            "aliases": ["BIT-django-2024-27351", "CVE-2024-27351", "PYSEC-2024-47"],
            "summary": "Regular expression denial-of-service in Django",
            "severity": "MEDIUM",
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H",
            "fixed_version": "4.2.11",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-27351"],
            "published": "2024-03-15T21:30:43Z",
            "modified": "2026-09-10T03:50:10.784705170Z",
        }

    def test_the_details_stand_in_for_a_missing_summary(self):
        entry = _normalized(ALPINE_OPENSSL, _OPENSSL_ON_ALPINE_3_17)
        assert entry["summary"] == ""
        assert entry["details"] == ALPINE_OPENSSL["details"]

    def test_a_malware_entry_lists_the_affected_versions(self):
        entry = _normalized(MALWARE_COMBINEZONE, _purl("pkg:npm/combinezone@7.14.2"))
        assert entry["affected_versions"] == ["7.14.2"]

    def test_a_component_entry_holds_the_component_and_its_vulnerabilities(self):
        component = {"name": "django", "version": "4.2.0", "purl": "pkg:pypi/django@4.2.0"}
        vulnerabilities = OSVAnalyzer()._normalize_vulnerabilities([DJANGO_REDOS], _DJANGO_4_2_0)
        assert OSVAnalyzer()._result_entry(component, vulnerabilities) == {
            "component": "django",
            "version": "4.2.0",
            "purl": "pkg:pypi/django@4.2.0",
            "vulnerabilities": vulnerabilities,
        }


class TestFixedVersion:
    """The fix closing the affected interval the installed version is in, from the queried package's entries."""

    @pytest.mark.parametrize(
        ("record", "query", "expected"),
        [
            pytest.param(DJANGO_REDOS, _DJANGO_4_2_0, "4.2.11", id="installed-release-line"),
            pytest.param(DJANGO_REDOS, _purl("pkg:pypi/Django@5.0"), "5.0.3", id="pep503-name"),
            pytest.param(DJANGO_REDOS, _purl("pkg:pypi/django@4.2.11"), None, id="installed-is-the-fix"),
            pytest.param(DJANGO_REDOS, _purl("pkg:pypi/django@4.1"), None, id="outside-every-range"),
            pytest.param(URLLIB3_CRLF, _purl("pkg:pypi/urllib3@1.24"), "1.25.9", id="git-commit-skipped"),
            pytest.param(REQUEST_SSRF, _purl("pkg:npm/request@2.88.2"), None, id="last-affected-has-no-fix"),
            pytest.param(REQUEST_SSRF, _purl("pkg:npm/%40cypress/request@2.88.10"), "3.0.0", id="scoped-package"),
            pytest.param(GO_RAPID_RESET, _purl("pkg:golang/stdlib@1.21.1"), "1.21.3", id="second-interval"),
            pytest.param(GO_RAPID_RESET, _purl("pkg:golang/golang.org/x/net@v0.16.0"), "0.17.0", id="other-module"),
            pytest.param(LOG4SHELL, _LOG4J_CORE_2_14_1, "2.15.0", id="maven"),
            pytest.param(ALPINE_OPENSSL, _OPENSSL_ON_ALPINE_3_17, "3.0.12-r1", id="os-release-of-the-query"),
            pytest.param(DEBIAN_OPENSSL, _OPENSSL_ON_DEBIAN_12, "3.0.13-1~deb12u1", id="debian-revision"),
            pytest.param(
                UBUNTU_OPENSSL, _OPENSSL_ON_UBUNTU_20_04, "1.1.1f-1ubuntu2.24+esm2", id="ubuntu-listing-entry"
            ),
        ],
    )
    def test_the_fix_is_the_one_for_the_installed_version(self, record, query, expected):
        assert _normalized(record, query)["fixed_version"] == expected

    @pytest.mark.parametrize(
        ("record", "query", "expected"),
        [
            pytest.param(DJANGO_REDOS, _purl("pkg:pypi/Django@4.2.0"), "4.2.11", id="pep503-name"),
            pytest.param(DJANGO_REDOS, _purl("pkg:npm/django@4.2.0"), None, id="other-ecosystem"),
            pytest.param(REQUEST_SSRF, _purl("pkg:npm/%40cypress/request@2.88.10"), "3.0.0", id="scoped-package"),
            pytest.param(GO_RAPID_RESET, _purl("pkg:golang/golang.org/x/net@v0.16.0"), "0.17.0", id="module-path"),
            pytest.param(LOG4SHELL, _LOG4J_CORE_2_14_1, "2.15.0", id="maven-group-artifact"),
            pytest.param(
                LOG4SHELL,
                _purl("pkg:maven/com.guicedee.services/log4j-core@2.14.1"),
                None,
                id="same-artifact-other-group",
            ),
        ],
    )
    def test_an_entry_without_a_purl_matches_by_ecosystem_and_name(self, record, query, expected):
        assert _normalized(_without_purls(record), query)["fixed_version"] == expected


class TestEcosystemSpecific:
    """Symbol-level reachability matches these symbols, so they must be the queried package's own."""

    def test_the_symbols_are_those_of_the_queried_module(self):
        entry = _normalized(GO_RAPID_RESET, _purl("pkg:golang/golang.org/x/net@v0.16.0"))
        assert entry["ecosystem_specific"] == GO_RAPID_RESET["affected"][1]["ecosystem_specific"]

    @pytest.mark.parametrize(
        ("record", "query"),
        [
            pytest.param(ALPINE_OPENSSL, _OPENSSL_ON_ALPINE_3_17, id="empty"),
            pytest.param(DEBIAN_OPENSSL, _OPENSSL_ON_DEBIAN_12, id="no-symbols"),
        ],
    )
    def test_an_entry_without_symbols_has_no_ecosystem_specific(self, record, query):
        assert "ecosystem_specific" not in _normalized(record, query)


class TestCvssScoreAndVector:
    """The rating the severity band would come from, kept for risk scoring even when the band comes from elsewhere."""

    def test_the_newest_standard_rating_is_kept(self):
        v4 = "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        record = {
            "id": "CVE-2024-56326",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
                {"type": "CVSS_V4", "score": v4},
            ],
        }
        entry = _normalized(record, _purl("pkg:pypi/jinja2@3.1.4"))
        assert (entry["cvss_score"], entry["cvss_vector"]) == (5.4, v4)

    def test_a_bare_number_is_a_score_without_a_vector(self):
        entry = _normalized({"id": "GHSA-x", "severity": [{"type": "CVSS_V3", "score": "9.8"}]}, _LODASH)
        assert (entry["cvss_score"], entry["cvss_vector"]) == (9.8, None)

    def test_an_unrated_record_has_no_cvss(self):
        entry = _normalized(GO_RAPID_RESET, _purl("pkg:golang/stdlib@1.21.1"))
        assert (entry["cvss_score"], entry["cvss_vector"]) == (None, None)


class TestCvssVersionAwareSeverity:
    """CVSS v2 has no CRITICAL bucket (top tier is HIGH); the mapper must respect the source version."""

    def setup_method(self):
        self.analyzer = OSVAnalyzer()

    @pytest.mark.parametrize(
        ("severity_array", "expected"),
        [
            # v2 spec: 7.0-10.0 = HIGH; there is no CRITICAL bucket.
            pytest.param([{"type": "CVSS_V2", "score": "9.5"}], "HIGH", id="v2-top-score-is-high"),
            pytest.param([{"type": "CVSS_V3", "score": "9.5"}], "CRITICAL", id="v3-critical-score"),
            # Both v2 and v3 present: prefer the newer standard -> 5.0 -> MEDIUM.
            pytest.param(
                [{"type": "CVSS_V2", "score": "9.5"}, {"type": "CVSS_V3", "score": "5.0"}],
                "MEDIUM",
                id="v3-preferred-over-v2",
            ),
            # CVSS v4 supersedes v3 — pick the newest available standard.
            pytest.param(
                [{"type": "CVSS_V3", "score": "9.5"}, {"type": "CVSS_V4", "score": "5.0"}],
                "MEDIUM",
                id="v4-preferred-over-v3",
            ),
            # CVSS scores are bounded at 10.0; a bogus 15.0 clamps into range.
            pytest.param([{"type": "CVSS_V3", "score": "15.0"}], "CRITICAL", id="score-above-10-clamped"),
            pytest.param([{"type": "CVSS_V3", "score": "-1.0"}], "LOW", id="score-below-zero-clamped"),
            # 9.0 is the inclusive floor of the CRITICAL band and a score NVD publishes often.
            pytest.param([{"type": "CVSS_V3", "score": "9.0"}], "CRITICAL", id="v3-exactly-nine"),
            pytest.param([{"type": "CVSS_V3", "score": "8.9"}], "HIGH", id="v3-just-below-nine"),
        ],
    )
    def test_the_severity_comes_from_the_newest_rating_in_range(self, severity_array, expected):
        assert self.analyzer._severity_from_cvss_array(severity_array) == expected


class TestParseCvssScoreNonFinite:
    """float() accepts "nan"/"inf"; NaN survives _cvss_to_severity's clamp as 10.0 because no
    comparison against it is true, so it would land in CRITICAL despite the clamp."""

    @pytest.mark.parametrize("score", ["nan", "NaN", "inf", "-inf", "infinity"])
    def test_non_finite_scores_do_not_produce_a_severity(self, score):
        assert OSVAnalyzer()._parse_cvss_score(score) is None

    def test_a_nan_severity_entry_leaves_the_record_unrated(self):
        record = {"id": "CVE-2026-1", "severity": [{"type": "CVSS_V3", "score": "nan"}]}
        assert OSVAnalyzer()._extract_severity(record) == "UNKNOWN"

    def test_a_finite_out_of_range_score_is_still_clamped(self):
        assert OSVAnalyzer()._cvss_to_severity(42.0) == "CRITICAL"
        assert OSVAnalyzer()._cvss_to_severity(-5.0) == "LOW"


class TestV4OnlyRecords:
    """A live census of 369 OSV records fetched for production findings found 28 rated only by
    a CVSS:4.0 vector with no database_specific.severity — 28 of the 44 that derived UNKNOWN."""

    @pytest.mark.parametrize(
        ("record", "expected"),
        [
            # CVE-2025-55163, exactly as OSV serves it.
            pytest.param(
                {
                    "id": "CVE-2025-55163",
                    "severity": [
                        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"}
                    ],
                },
                "HIGH",
                id="v4-only-record",
            ),
            # _CVSS_TYPE_PREFERENCE puts v4 first: v4 scores 5.4 (MEDIUM), the v3 vector 7.8 (HIGH).
            pytest.param(
                {
                    "id": "CVE-2024-56326",
                    "severity": [
                        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
                        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
                    ],
                },
                "MEDIUM",
                id="v4-preferred-over-v3",
            ),
            pytest.param(
                {
                    "id": "CVE-2026-2",
                    "severity": [
                        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L"},
                        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                    ],
                },
                "CRITICAL",
                id="unparseable-v4-falls-through-to-v3",
            ),
            pytest.param({"id": "CVE-2026-3", "severity": []}, "UNKNOWN", id="unrated-record"),
        ],
    )
    def test_the_record_is_rated_from_its_newest_usable_vector(self, record, expected):
        assert OSVAnalyzer()._extract_severity(record) == expected
