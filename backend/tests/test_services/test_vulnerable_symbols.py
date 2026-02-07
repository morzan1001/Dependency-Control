"""Tests for vulnerable symbols extraction."""

from app.services.vulnerable_symbols import (
    extract_symbols_from_vulnerability,
    get_symbols_for_finding,
)


class TestExtractSymbolsFromVulnerability:
    def test_osv_ecosystem_symbols(self):
        vuln = {
            "id": "CVE-2023-1234",
            "package": "requests",
            "ecosystem_specific": {
                "symbols": ["unsafe_function", "vulnerable_method"],
            },
        }
        result = extract_symbols_from_vulnerability(vuln)
        assert result.symbols == ["unsafe_function", "vulnerable_method"]
        assert result.confidence == "high"
        assert result.extraction_method == "osv_ecosystem"
        assert result.cve == "CVE-2023-1234"
        assert result.package == "requests"

    def test_go_osv_imports(self):
        vuln = {
            "id": "GO-2023-0001",
            "package": "golang.org/x/net",
            "ecosystem_specific": {
                "imports": [
                    {"path": "net/http", "symbols": ["Handle", "ListenAndServe"]},
                    {"path": "net/url", "symbols": ["Parse"]},
                ],
            },
        }
        result = extract_symbols_from_vulnerability(vuln)
        assert set(result.symbols) == {"Handle", "ListenAndServe", "Parse"}
        assert result.confidence == "high"
        assert result.extraction_method == "osv_go_imports"

    def test_affected_symbols(self):
        vuln = {
            "id": "CVE-2023-5678",
            "component": "lodash",
            "affected_symbols": ["merge", "template"],
        }
        result = extract_symbols_from_vulnerability(vuln)
        assert result.symbols == ["merge", "template"]
        assert result.confidence == "high"
        assert result.extraction_method == "scanner_provided"

    def test_no_symbols_found(self):
        vuln = {"id": "CVE-2023-0000", "package": "pkg"}
        result = extract_symbols_from_vulnerability(vuln)
        assert result.symbols == []
        assert result.confidence == "low"
        assert result.extraction_method == "none"

    def test_empty_vuln(self):
        result = extract_symbols_from_vulnerability({})
        assert result.symbols == []
        assert result.cve == ""
        assert result.package == ""

    def test_ecosystem_specific_not_dict(self):
        vuln = {"id": "CVE-1", "ecosystem_specific": "not a dict"}
        result = extract_symbols_from_vulnerability(vuln)
        assert result.symbols == []

    def test_cve_from_cve_key(self):
        vuln = {"cve": "CVE-2023-1111"}
        result = extract_symbols_from_vulnerability(vuln)
        assert result.cve == "CVE-2023-1111"

    def test_package_from_component_key(self):
        vuln = {"component": "flask"}
        result = extract_symbols_from_vulnerability(vuln)
        assert result.package == "flask"

    def test_go_imports_without_symbols_key(self):
        vuln = {
            "id": "GO-1",
            "ecosystem_specific": {
                "imports": [{"path": "net/http"}],
            },
        }
        result = extract_symbols_from_vulnerability(vuln)
        # No symbols key in imports -> falls through
        assert result.symbols == []

    def test_osv_symbols_prioritized_over_affected_symbols(self):
        vuln = {
            "id": "CVE-1",
            "ecosystem_specific": {"symbols": ["osv_func"]},
            "affected_symbols": ["other_func"],
        }
        result = extract_symbols_from_vulnerability(vuln)
        assert result.symbols == ["osv_func"]
        assert result.extraction_method == "osv_ecosystem"


class TestGetSymbolsForFinding:
    def test_with_vulnerabilities(self):
        finding = {
            "component": "requests",
            "details": {
                "vulnerabilities": [
                    {"id": "CVE-2023-1", "affected_symbols": ["func_a"]},
                    {"id": "CVE-2023-2", "affected_symbols": ["func_b"]},
                ],
            },
        }
        result = get_symbols_for_finding(finding)
        assert set(result.symbols) == {"func_a", "func_b"}
        assert result.confidence == "high"
        assert result.package == "requests"
        assert "CVE-2023-1" in result.cve
        assert "CVE-2023-2" in result.cve

    def test_no_vulnerabilities(self):
        finding = {"component": "pkg", "details": {}}
        result = get_symbols_for_finding(finding)
        assert result.symbols == []
        assert result.confidence == "low"

    def test_empty_finding(self):
        result = get_symbols_for_finding({})
        assert result.symbols == []
        assert result.package == ""

    def test_deduplicates_symbols(self):
        finding = {
            "component": "pkg",
            "details": {
                "vulnerabilities": [
                    {"id": "CVE-1", "affected_symbols": ["func_a", "func_b"]},
                    {"id": "CVE-2", "affected_symbols": ["func_b", "func_c"]},
                ],
            },
        }
        result = get_symbols_for_finding(finding)
        assert len(result.symbols) == 3
        assert set(result.symbols) == {"func_a", "func_b", "func_c"}

    def test_confidence_tracks_best(self):
        finding = {
            "details": {
                "vulnerabilities": [
                    {"id": "CVE-1"},  # no symbols -> low
                    {"id": "CVE-2", "affected_symbols": ["func"]},  # high
                ],
            },
        }
        result = get_symbols_for_finding(finding)
        assert result.confidence == "high"

    def test_cves_joined(self):
        finding = {
            "details": {
                "vulnerabilities": [
                    {"id": "CVE-A"},
                    {"id": "CVE-B"},
                    {"id": "CVE-C"},
                ],
            },
        }
        result = get_symbols_for_finding(finding)
        assert result.cve == "CVE-A,CVE-B,CVE-C"

    def test_no_details_key(self):
        result = get_symbols_for_finding({"component": "pkg"})
        assert result.symbols == []
