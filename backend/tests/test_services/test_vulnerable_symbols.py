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
        assert extract_symbols_from_vulnerability(vuln) == ["unsafe_function", "vulnerable_method"]

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
        assert extract_symbols_from_vulnerability(vuln) == ["Handle", "ListenAndServe", "Parse"]

    def test_no_symbols_found(self):
        assert extract_symbols_from_vulnerability({"id": "CVE-2023-0000", "package": "pkg"}) == []

    def test_empty_vuln(self):
        assert extract_symbols_from_vulnerability({}) == []

    def test_ecosystem_specific_not_dict(self):
        assert extract_symbols_from_vulnerability({"id": "CVE-1", "ecosystem_specific": "not a dict"}) == []

    def test_go_imports_without_symbols_key(self):
        vuln = {
            "id": "GO-1",
            "ecosystem_specific": {
                "imports": [{"path": "net/http"}],
            },
        }
        assert extract_symbols_from_vulnerability(vuln) == []

    def test_symbols_prioritized_over_imports(self):
        vuln = {
            "id": "CVE-1",
            "ecosystem_specific": {
                "symbols": ["osv_func"],
                "imports": [{"path": "net/http", "symbols": ["other_func"]}],
            },
        }
        assert extract_symbols_from_vulnerability(vuln) == ["osv_func"]


class TestGetSymbolsForFinding:
    def test_no_vulnerabilities(self):
        assert get_symbols_for_finding({"component": "pkg", "details": {}}) == []

    def test_empty_finding(self):
        assert get_symbols_for_finding({}) == []

    def test_entries_without_symbols_add_nothing(self):
        finding = {
            "details": {
                "vulnerabilities": [
                    {"id": "CVE-1"},
                    {"id": "CVE-2", "ecosystem_specific": {"symbols": ["func"]}},
                ],
            },
        }
        assert get_symbols_for_finding(finding) == ["func"]

    def test_returns_the_sorted_union(self):
        finding = {
            "details": {
                "vulnerabilities": [
                    {"id": "GO-1", "ecosystem_specific": {"symbols": ["Server.ServeConn", "ConfigureServer"]}},
                    {"id": "GO-2", "ecosystem_specific": {"imports": [{"path": "x/http2", "symbols": ["Transport"]}]}},
                    {"id": "GO-3", "ecosystem_specific": {"symbols": ["ConfigureServer"]}},
                ],
            },
        }

        assert get_symbols_for_finding(finding) == ["ConfigureServer", "Server.ServeConn", "Transport"]
