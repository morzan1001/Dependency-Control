"""Analyzers finish concurrently, so the aggregator sees them in an arbitrary order.

Identical scanner output must therefore produce byte-identical findings regardless of the
order the results arrive in; otherwise two scans of unchanged code disagree and the scan
delta fabricates churn. Fixtures mirror real grype/trivy/osv payloads for prod's
brace-expansion 2.0.2 and stdlib 1.23.12.
"""

import itertools
import json

from app.services.aggregation import ResultAggregator
from app.services.aggregation import aggregator as aggregator_module

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
                "cvss": [{"metrics": {"baseScore": 3.1}, "vector": "CVSS:3.1/AV:N/AC:H", "version": "3.1"}],
            },
            "relatedVulnerabilities": [{"id": "CVE-2026-13149"}],
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


class TestDetailConflictTieBreak:
    """Two alias-linked entries can share their lowest scanner name; arrival must still not decide."""

    @staticmethod
    def _entry(vuln_id: str, aliases: list[str], scanners: list[str], fixed: str, published: str) -> dict:
        return {
            "id": vuln_id,
            "severity": "HIGH",
            "description": "same length ....",
            "aliases": aliases,
            "scanners": scanners,
            "references": [],
            "details": {"fixed_version": fixed, "published_date": published},
        }

    def test_same_lowest_scanner_resolves_identically_in_both_directions(self):
        from app.services.aggregation.merging import dedupe_vulnerability_entries

        def _merge(first: dict, second: dict) -> dict:
            entries: list = [json.loads(json.dumps(first)), json.loads(json.dumps(second))]
            dedupe_vulnerability_entries(entries)
            assert len(entries) == 1
            return entries[0]

        a = self._entry("CVE-2026-1", ["CVE-2026-2"], ["grype", "trivy"], "1.0", "2026-01-01")
        b = self._entry("CVE-2026-2", ["CVE-2026-1"], ["grype", "osv"], "1.0", "2026-02-02")

        assert _merge(a, b) == _merge(b, a)


MAINTAINER_RISK = {
    "maintainer_issues": [
        {
            "component": "left-pad",
            "version": "1.0.0",
            "purl": "pkg:npm/left-pad@1.0.0",
            "risks": [{"type": "stale_package", "severity": "MEDIUM", "message": "No release in 1200 days"}],
            "severity": "MEDIUM",
        }
    ]
}


def _crypto_result(locations: list[str]) -> dict:
    from app.models.crypto_asset import CryptoAsset
    from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
    from app.schemas.crypto_policy import CryptoRule
    from app.services.analyzers.crypto.base import _build_finding_dedup

    asset = CryptoAsset(
        project_id="p",
        scan_id="s",
        bom_ref="crypto/algorithm/md5",
        name="MD5",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.HASH,
        occurrence_locations=locations,
    )
    rule = CryptoRule(
        rule_id="nist-131a-md5",
        name="MD5 is disallowed",
        description="MD5 is broken",
        finding_type="crypto_weak_algorithm",
        default_severity="HIGH",
        source="nist-sp-800-131a",
    )
    return {"findings": [_build_finding_dedup(asset, [rule], "crypto_weak_algorithm")]}


class TestMultiSbomArrivalOrder:
    @staticmethod
    def _identity(sources: list[str]) -> tuple[str, str, str]:
        from app.services.analytics.findings_delta import finding_identity_key

        aggregator = ResultAggregator()
        for source in sources:
            aggregator.aggregate("maintainer_risk", MAINTAINER_RISK, source=source)
        [finding] = aggregator.get_findings()
        return finding_identity_key(finding.model_dump())

    def test_sbom_order_does_not_change_a_quality_finding_identity(self):
        assert self._identity(["sbom-a", "sbom-b"]) == self._identity(["sbom-b", "sbom-a"])

    def test_a_merged_crypto_finding_keeps_both_sboms_occurrence_paths(self):
        aggregator = ResultAggregator()
        aggregator.aggregate("crypto_weak_algorithm", _crypto_result(["src/a.py"]), source="sbom-a")
        aggregator.aggregate("crypto_weak_algorithm", _crypto_result(["src/b.py"]), source="sbom-b")
        [finding] = aggregator.get_findings()

        assert finding.found_in == ["src/a.py", "sbom-a", "src/b.py", "sbom-b"]


# trivy spells a Go toolchain version with a "v" prefix, grype (like the syft SBOM) with "go".
STDLIB = {
    "trivy": {
        "Results": [
            {
                "Target": "usr/local/bin/app",
                "Class": "lang-pkgs",
                "Type": "gobinary",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-24790",
                        "PkgName": "stdlib",
                        "InstalledVersion": "v1.21.5",
                        "FixedVersion": "1.21.11, 1.22.4",
                        "Severity": "CRITICAL",
                        "Description": "net/netip: Unexpected behavior from Is methods for IPv4-mapped IPv6 addresses",
                    }
                ],
            }
        ]
    },
    "grype": {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-24790",
                    "severity": "Critical",
                    "description": "net/netip: Unexpected behavior from Is methods for IPv4-mapped IPv6 addresses",
                    "fix": {"versions": ["1.21.11", "1.22.4"], "state": "fixed"},
                    "urls": [],
                },
                "artifact": {"name": "stdlib", "version": "go1.21.5"},
            }
        ]
    },
}


def _maintainer_risk(component: str) -> dict:
    [issue] = MAINTAINER_RISK["maintainer_issues"]
    return {"maintainer_issues": [{**issue, "component": component}]}


class TestSurvivingSpelling:
    @staticmethod
    def _vulnerability(order: tuple[str, ...]) -> tuple[str, str, str | None]:
        aggregator = ResultAggregator()
        for analyzer in order:
            aggregator.aggregate(analyzer, STDLIB[analyzer], source="app")
        [finding] = aggregator.get_findings()
        return finding.id, finding.component, finding.version

    @staticmethod
    def _quality(spellings: tuple[str, ...]) -> tuple[str, str, str | None]:
        aggregator = ResultAggregator()
        for i, component in enumerate(spellings):
            aggregator.aggregate("maintainer_risk", _maintainer_risk(component), source=f"sbom-{i}")
        [finding] = aggregator.get_findings()
        return finding.id, finding.component, finding.version

    def test_the_vulnerability_spelling_does_not_depend_on_analyzer_order(self):
        assert self._vulnerability(("trivy", "grype")) == self._vulnerability(("grype", "trivy"))
        assert self._vulnerability(("trivy", "grype")) == ("stdlib:go1.21.5", "stdlib", "go1.21.5")

    def test_the_quality_spelling_does_not_depend_on_sbom_order(self):
        assert self._quality(("left-pad", "Left-Pad")) == self._quality(("Left-Pad", "left-pad"))


_GRYPE_WITHOUT_CVE_LINK = {"matches": [{**GRYPE["matches"][0], "relatedVulnerabilities": []}]}
_OSV_QUALIFIED_GHSA = {
    "osv_vulnerabilities": [
        {
            "component": "org.postgresql:postgresql",
            "version": "42.7.3",
            "vulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2025-0001"], "severity": "HIGH"}],
        }
    ]
}
# A CVE-less entry matches either CVE sharing its GHSA, so which one absorbs it depends on the fold order.
_GRYPE_BARE_GHSA = {
    "matches": [
        {
            "vulnerability": {"id": "GHSA-aaaa-bbbb-cccc", "severity": "Medium"},
            "artifact": {"name": "postgresql", "version": "42.7.3"},
        },
        {
            "vulnerability": {"id": "CVE-2025-0002", "severity": "Low"},
            "relatedVulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc"}],
            "artifact": {"name": "postgresql", "version": "42.7.3"},
        },
    ]
}
_SBOMS = (
    ("SBOM #1", (("trivy", TRIVY), ("grype", _GRYPE_WITHOUT_CVE_LINK))),
    ("SBOM #2", (("osv", OSV), ("grype", GRYPE))),
    ("SBOM #3", (("grype", GRYPE), ("osv", OSV), ("trivy", TRIVY))),
    ("SBOM #4", (("osv", _OSV_QUALIFIED_GHSA), ("grype", _GRYPE_BARE_GHSA))),
)


def _scan(sboms: tuple, fold_per_sbom: bool) -> str:
    aggregator = ResultAggregator()
    for source, results in sboms:
        for analyzer, result in results:
            aggregator.aggregate(analyzer, result, source=source)
        if fold_per_sbom:
            aggregator.fold_vulnerability_entries()
    return json.dumps([f.model_dump() for f in aggregator.get_findings()], sort_keys=True, default=str)


class TestPerSbomFold:
    def test_folding_after_each_sbom_leaves_the_findings_unchanged(self):
        for order in itertools.permutations(_SBOMS):
            sources = [source for source, _ in order]
            assert _scan(order, fold_per_sbom=True) == _scan(order, fold_per_sbom=False), sources

    def test_a_fold_revisits_only_the_packages_that_received_entries(self, monkeypatch):
        folded: list[int] = []
        real = aggregator_module.dedupe_vulnerability_entries
        monkeypatch.setattr(
            aggregator_module,
            "dedupe_vulnerability_entries",
            lambda entries: folded.append(len(entries)) or real(entries),
        )
        aggregator = ResultAggregator()
        for n in range(20):
            vulns = [
                {"VulnerabilityID": f"CVE-2026-{n:02}{i}", "PkgName": f"service-{n}", "InstalledVersion": "1.0.0"}
                for i in range(2)
            ]
            aggregator.aggregate("trivy", {"Results": [{"Target": "go.mod", "Vulnerabilities": vulns}]}, f"SBOM #{n}")
            aggregator.fold_vulnerability_entries()
        assert sum(folded) == 20 * 2
