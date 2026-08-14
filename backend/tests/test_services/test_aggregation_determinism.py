"""Analyzers finish concurrently, so the aggregator sees them in an arbitrary order.

Identical scanner output must therefore produce byte-identical findings regardless of the
order the results arrive in; otherwise two scans of unchanged code disagree and the scan
delta fabricates churn. Fixtures mirror real grype/trivy/osv payloads for prod's
brace-expansion 2.0.2 and stdlib 1.23.12.
"""

import itertools
import json

from app.services.aggregation import ResultAggregator

TRIVY = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2026-13149",
                    "PkgName": "brace-expansion",
                    "InstalledVersion": "2.0.2",
                    "FixedVersion": "2.0.3",
                    "Severity": "LOW",
                    "Title": "brace-expansion: ReDoS",
                    "Description": "Regular expression denial of service.",
                    "References": ["https://github.com/juliangruber/brace-expansion/pull/65"],
                    "CVSS": {"nvd": {"V3Score": 3.1, "V3Vector": "CVSS:3.1/AV:N/AC:H"}},
                },
                {
                    "VulnerabilityID": "CVE-2025-68121",
                    "PkgName": "org.postgresql:postgresql",
                    "InstalledVersion": "42.7.3",
                    "FixedVersion": "42.7.4",
                    "Severity": "HIGH",
                    "Description": "SQL injection.",
                    "References": ["https://nvd.nist.gov/vuln/detail/CVE-2025-68121"],
                },
            ],
        }
    ]
}

GRYPE = {
    "matches": [
        {
            "vulnerability": {
                "id": "GHSA-3jxr-9vmj-r5cp",
                "severity": "Low",
                "description": "brace-expansion is vulnerable to a regular expression denial of service.",
                "fix": {"versions": ["2.0.3", "1.1.12"], "state": "fixed"},
                "urls": ["https://github.com/advisories/GHSA-3jxr-9vmj-r5cp"],
                "relatedVulnerabilities": [{"id": "CVE-2026-13149"}],
                "cvss": [{"metrics": {"baseScore": 3.1}, "vector": "CVSS:3.1/AV:N/AC:H", "version": "3.1"}],
            },
            "artifact": {"name": "brace-expansion", "version": "2.0.2"},
        },
        {
            "vulnerability": {
                "id": "CVE-2025-68121",
                "severity": "High",
                "description": "SQLi.",
                "fix": {"versions": ["42.7.4"], "state": "fixed"},
                "urls": [],
            },
            "artifact": {"name": "postgresql", "version": "42.7.3"},
        },
    ]
}

OSV = {
    "osv_vulnerabilities": [
        {
            "component": "brace-expansion",
            "version": "2.0.2",
            "vulnerabilities": [
                {
                    "id": "GHSA-3jxr-9vmj-r5cp",
                    "aliases": ["CVE-2026-13149"],
                    "summary": "brace-expansion ReDoS",
                    "details": "",
                    "severity": "LOW",
                    "message": "brace-expansion ReDoS",
                    "references": ["https://github.com/advisories/GHSA-3jxr-9vmj-r5cp"],
                    "affected": [{"ranges": [{"events": [{"introduced": "1.0.0"}, {"fixed": "2.0.3"}]}]}],
                }
            ],
        }
    ]
}

OUTDATED = {
    "outdated_dependencies": [
        {
            "component": "brace-expansion",
            "current_version": "2.0.2",
            "latest_version": "5.0.0",
            "severity": "INFO",
            "message": "brace-expansion is 3 major versions behind",
        }
    ]
}

LICENSE_COMPLIANCE = {
    "component_licenses": [
        {"component": "brace-expansion", "version": "2.0.2", "license": "MIT", "category": "permissive"},
        {"component": "org.postgresql:postgresql", "version": "42.7.3", "license": "BSD-2-Clause"},
    ],
    "license_issues": [
        {
            "component": "org.postgresql:postgresql",
            "version": "42.7.3",
            "license": "BSD-2-Clause",
            "severity": "LOW",
            "category": "permissive",
            "message": "License requires attribution",
            "obligations": ["attribution"],
        }
    ],
}

OPENGREP = {
    "results": [
        {
            "check_id": "python.lang.security.audit.exec-detected",
            "path": "src/app.py",
            "start": {"line": 42, "col": 1},
            "end": {"line": 42, "col": 20},
            "extra": {"severity": "ERROR", "message": "exec detected", "metadata": {"cwe": ["CWE-95"]}},
        }
    ]
}

RESULTS = {
    "trivy": TRIVY,
    "grype": GRYPE,
    "osv": OSV,
    "outdated_packages": OUTDATED,
    "license_compliance": LICENSE_COMPLIANCE,
    "opengrep": OPENGREP,
}


def _aggregate(order: tuple[str, ...]) -> str:
    aggregator = ResultAggregator()
    for analyzer in order:
        aggregator.aggregate(analyzer, RESULTS[analyzer], source="app")
    return json.dumps([f.model_dump() for f in aggregator.get_findings()], sort_keys=True, default=str)


class TestAggregationIsOrderIndependent:
    def test_every_analyzer_permutation_yields_the_same_findings(self):
        outcomes = {order: _aggregate(order) for order in itertools.permutations(RESULTS)}
        distinct = set(outcomes.values())
        assert len(distinct) == 1, f"{len(distinct)} distinct outcomes across {len(outcomes)} permutations"

    def test_merged_entry_keeps_the_cve_id_and_the_union_of_fixes(self):
        aggregator = ResultAggregator()
        for analyzer in ("grype", "osv", "trivy"):
            aggregator.aggregate(analyzer, RESULTS[analyzer], source="app")

        brace = next(f for f in aggregator.get_findings() if f.component == "brace-expansion")
        entries = brace.details["vulnerabilities"]
        assert [e["id"] for e in entries] == ["CVE-2026-13149"]
        assert entries[0]["fixed_version"] == "1.1.12, 2.0.3"
        assert entries[0]["scanners"] == ["grype", "osv", "trivy"]
