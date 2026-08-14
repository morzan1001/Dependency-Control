"""Trivy aliases must come from structured data, never from free-text reference URLs.

Advisory pages (Go vuln DB, RHSA, Debian DSA) list many unrelated CVEs; scraping them
turned every co-mentioned CVE into an authoritative alias, which merged a different
scanner's genuinely separate vulnerability into the polluted entry and dropped its fix
version. Fixtures reproduce prod scan 9eee14fe (stdlib 1.23.12).
"""

from app.services.aggregation import ResultAggregator


def _trivy_stdlib_result() -> dict:
    return {
        "Results": [
            {
                "Target": "app",
                "Class": "lang-pkgs",
                "Type": "gobinary",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2025-68121",
                        "PkgName": "stdlib",
                        "InstalledVersion": "1.23.12",
                        "FixedVersion": "1.23.13",
                        "Severity": "CRITICAL",
                        "Title": "net/http: request smuggling",
                        "Description": "A flaw in net/http.",
                        "References": [
                            "https://go.dev/cl/700123",
                            "https://pkg.go.dev/vuln/GO-2026-4001",
                            "https://nvd.nist.gov/vuln/detail/CVE-2026-25679",
                        ],
                    }
                ],
            }
        ]
    }


def _grype_stdlib_result() -> dict:
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2026-25679",
                    "severity": "High",
                    "description": "A different flaw in crypto/tls.",
                    "fix": {"versions": ["1.23.14"], "state": "fixed"},
                    "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2026-25679"],
                },
                "artifact": {"name": "stdlib", "version": "1.23.12"},
            }
        ]
    }


def _entries(aggregator: ResultAggregator) -> list[dict]:
    findings = [f for f in aggregator.get_findings() if f.type == "vulnerability"]
    assert len(findings) == 1
    return findings[0].details["vulnerabilities"]


class TestReferenceScrapingDoesNotSwallowVulnerabilities:
    def test_a_co_mentioned_cve_keeps_its_own_entry_and_fix_version(self):
        agg = ResultAggregator()
        agg.aggregate("trivy", _trivy_stdlib_result())
        agg.aggregate("grype", _grype_stdlib_result())

        by_id = {e["id"]: e for e in _entries(agg)}
        assert set(by_id) == {"CVE-2025-68121", "CVE-2026-25679"}
        assert by_id["CVE-2025-68121"]["fixed_version"] == "1.23.13"
        assert by_id["CVE-2026-25679"]["fixed_version"] == "1.23.14"

    def test_referenced_cves_are_not_recorded_as_aliases(self):
        agg = ResultAggregator()
        agg.aggregate("trivy", _trivy_stdlib_result())

        entry = _entries(agg)[0]
        assert entry["id"] == "CVE-2025-68121"
        assert entry["aliases"] == []
        assert "https://nvd.nist.gov/vuln/detail/CVE-2026-25679" in entry["references"]

    def test_non_cve_trivy_id_is_not_rewritten_from_a_reference(self):
        agg = ResultAggregator()
        agg.aggregate(
            "trivy",
            {
                "Results": [
                    {
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "GHSA-xxxx-yyyy-zzzz",
                                "PkgName": "pkg",
                                "InstalledVersion": "1.0",
                                "Severity": "HIGH",
                                "Description": "test",
                                "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-9999"],
                            }
                        ]
                    }
                ]
            },
        )

        entry = _entries(agg)[0]
        assert entry["id"] == "GHSA-xxxx-yyyy-zzzz"
        assert entry["aliases"] == []
