"""Every card each generator builds, field for field, against the recorded cards.jsonl.

After an intended change to a card, record it again with DC_RECORD_CARDS=1 and review the diff.
"""

import json
import os
from pathlib import Path

from app.services.aggregation import ResultAggregator
from app.services.recommendation import (
    crypto,
    dependencies,
    graph,
    iac,
    incidents,
    insights,
    licenses,
    optimization,
    quality,
    risks,
    sast,
    secrets,
    trends,
    vulnerabilities,
)
from app.services.recommendation.common import AFFECTED_COMPONENTS_SHOWN
from tests.helpers.findings import stored_vulnerability

_RECORDED = Path(__file__).parents[2] / "fixtures" / "recommendations" / "cards.jsonl"
# More than one card lists, so every sampled list is cut.
_CROWD = AFFECTED_COMPONENTS_SHOWN + 4


def _produced(analyzer, result):
    aggregator = ResultAggregator()
    aggregator.aggregate(analyzer, result)
    return [finding.model_dump() for finding in aggregator.get_findings()]


def _vuln(component, version, *advisories):
    return stored_vulnerability(component, version, list(advisories))


def _advisory(cve, severity="HIGH", fixed_version=None, **marks):
    return {"id": cve, "severity": severity, "fixed_version": fixed_version, **marks}


def _row(name, version, *, direct=False, purl=None, **fields):
    return {"name": name, "version": version, "direct": direct, "purl": purl or f"pkg:npm/{name}@{version}", **fields}


def _vulnerability_cards():
    findings = [
        *(
            _vuln(f"libssl-{i:02d}", "1.1.1", _advisory(f"CVE-2023-{i:04d}", "CRITICAL", "1.1.1w"))
            for i in range(_CROWD)
        ),
        _vuln(
            "log4j-core",
            "2.14.1",
            _advisory("CVE-2021-44228", "CRITICAL", "2.17.1", in_kev=True, epss_score=0.97),
            _advisory("CVE-2021-45046", "CRITICAL", "2.17.1"),
            _advisory("CVE-2021-45105", "HIGH", "2.17.1"),
        ),
        _vuln("minimist", "0.0.8", _advisory("CVE-2021-44906", "CRITICAL", "1.2.6")),
        _vuln("abandoned", "0.1.0", _advisory("CVE-2024-0001", "CRITICAL"), _advisory("CVE-2024-0002", "HIGH")),
    ]
    rows = [
        *(
            _row(
                f"libssl-{i:02d}",
                "1.1.1",
                purl=f"pkg:deb/debian/libssl-{i:02d}@1.1.1",
                source_type="image",
                source_target="registry.example.com/app:1.4.2@sha256:abc",
            )
            for i in range(_CROWD)
        ),
        _row("log4j-core", "2.14.1", direct=True, purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
        _row("minimist", "0.0.8"),
    ]
    return [
        *vulnerabilities.process_vulnerabilities(findings, rows),
        *optimization.identify_quick_wins(findings, rows),
        *incidents.detect_known_exploits(findings),
    ]


def _exploited_cards():
    findings = [
        _vuln(f"pkg-{i:02d}", "1.0.0", _advisory(f"CVE-2022-{i:04d}", "HIGH", "1.0.1", **marks))
        for i, marks in enumerate(
            [{"in_kev": True, "kev_ransomware_use": True}, {"in_kev": True}, {"epss_score": 0.8}] * (_CROWD // 3 + 1)
        )
    ]
    return incidents.detect_known_exploits(findings)


def _incident_cards():
    malware_info = {"malicious": True, "threats": ["credential-theft"], "description": "Exfiltrates npm tokens"}
    malware = [
        {"component": f"evil-{i:02d}", "version": "1.0.0", "severity": "CRITICAL", "malware_info": malware_info}
        for i in range(_CROWD)
    ]
    typosquats = [
        {
            "component": f"reqeusts-{i:02d}",
            "version": "1.0.0",
            "imitated_package": "requests",
            "similarity": 0.9,
            "severity": "HIGH",
            "message": "Possible typosquatting detected!",
        }
        for i in range(_CROWD)
    ]
    mismatches = [
        {
            "component": f"pkg-{i:02d}",
            "version": "1.0.0",
            "registry": "npm",
            "algorithm": "SHA-512",
            "sbom_hash": "3f1a",
            "expected_hashes": ["9c2e"],
            "severity": "CRITICAL",
            "message": "Hash mismatch detected! Package may be tampered.",
        }
        for i in range(_CROWD)
    ]
    return [
        *incidents.process_malware(_produced("os_malware", {"malware_issues": malware})),
        *incidents.process_typosquatting(_produced("typosquatting", {"typosquatting_issues": typosquats})),
        *incidents.process_hash_mismatch(_produced("hash_verification", {"hash_issues": mismatches})),
    ]


def _secret(component, severity, detector_name):
    return {
        "type": "secret",
        "severity": severity,
        "component": component,
        "details": {"detector": "2", "detector_name": detector_name, "verified": severity != "LOW"},
        "id": f"secret-{component}-{severity}",
    }


def _sast(rule_id, severity="HIGH"):
    entry = {
        "id": rule_id,
        "scanner": "opengrep",
        "severity": severity,
        "title": "sql-injection",
        "description": "",
        "details": {"rule_id": rule_id, "category": "sql-injection", "cwe_ids": ["89"]},
    }
    return {
        "type": "sast",
        "severity": severity,
        "component": f"src/{rule_id}.py",
        "details": {"sast_findings": [entry], "file": f"src/{rule_id}.py", "line": 1},
        "id": rule_id,
    }


def _iac(component, platform, title, severity="HIGH"):
    return {
        "type": "iac",
        "severity": severity,
        "component": component,
        "details": {"platform": platform, "title": title, "rule_id": title},
        "id": f"iac-{component}-{title}",
    }


def _code_cards():
    return [
        *secrets.process_secrets(
            [_secret(f"config/{i:02d}.env", "HIGH", "AWS") for i in range(_CROWD)]
            + [_secret("old/settings.py", "LOW", "Slack"), _secret("old/settings.py", "LOW", "GitHub")]
        ),
        *sast.process_sast([_sast(f"rule-{i:02d}") for i in range(_CROWD)]),
        *iac.process_iac(
            [_iac(f"k8s/deploy-{i:02d}.yaml", "kubernetes", "Privileged container") for i in range(_CROWD)]
            + [_iac("Dockerfile", "docker", "Healthcheck missing", "MEDIUM")] * 3
        ),
    ]


def _license(component, license_name, severity="HIGH"):
    return {
        "type": "license",
        "severity": severity,
        "component": component,
        "details": {"license": license_name},
        "id": f"license-{component}",
    }


def _licensed(name, license_name, category):
    return _row(name, "1.0.0", license=license_name, license_category=category)


def _license_cards():
    findings = [_license(f"gpl-lib-{i:02d}", "GPL-3.0") for i in range(_CROWD)]
    findings += [_license("agpl-lib", "AGPL-3.0", "CRITICAL"), _license("mit-lib", "MIT", "INFO")]
    previous = [_licensed(f"drifted-{i:02d}", "MIT", "permissive") for i in range(_CROWD)]
    current = [_licensed(f"drifted-{i:02d}", "GPL-3.0", "strong_copyleft") for i in range(_CROWD)]
    return [*licenses.process_licenses(findings), *licenses.detect_license_drift(current, previous)]


def _quality(component, score, critical_issues=(), failed_checks=(), maintained=True):
    return {
        "type": "quality",
        "severity": "MEDIUM",
        "component": component,
        "version": "1.0.0",
        "details": {
            "overall_score": score,
            "has_maintenance_issues": not maintained,
            "issue_count": 1,
            "quality_issues": [
                {
                    "id": f"SCORECARD-{component}",
                    "type": "scorecard",
                    "severity": "MEDIUM",
                    "details": {
                        "overall_score": score,
                        "critical_issues": list(critical_issues),
                        "failed_checks": list(failed_checks),
                        "project_url": f"https://github.com/example/{component}",
                    },
                }
            ],
        },
        "id": f"quality-{component}",
    }


def _quality_cards():
    findings = [
        *(_quality(f"stale-{i:02d}", 2.0, ["Maintained"], maintained=False) for i in range(_CROWD)),
        *(_quality(f"weak-{i:02d}", 3.5, ["Vulnerabilities"]) for i in range(_CROWD)),
        *(_quality(f"unreviewed-{i:02d}", 6.0, failed_checks=[{"name": "Code-Review"}]) for i in range(_CROWD)),
    ]
    vulns = [_vuln(f"stale-{i:02d}", "1.0.0", _advisory(f"CVE-2020-{i:04d}", "CRITICAL")) for i in range(_CROWD)]
    return [
        *quality.process_quality(findings),
        *insights.correlate_scorecard_with_vulnerabilities(vulns, findings),
    ]


def _crypto(finding_type, asset, index, **details):
    return {
        "type": finding_type,
        "severity": "HIGH",
        "component": asset,
        "description": f"{asset} at call site {index}",
        "details": {"asset_name": asset, "bom_ref": f"ref-{asset}-{index}", "rule_id": f"rule-{index}", **details},
        "id": f"crypto-{finding_type}-{asset}-{index}",
    }


def _crypto_cards():
    findings = [
        *(_crypto("crypto_weak_algorithm", "MD5", i) for i in range(_CROWD)),
        _crypto("crypto_weak_key", "RSA", 0, key_size_bits=1024),
        _crypto("crypto_weak_protocol", "TLSv1.0", 0),
        _crypto("crypto_quantum_vulnerable", "ECDSA", 0),
        _crypto("crypto_cert_expired", "CN=api.example.com", 0),
        _crypto("crypto_key_management", "hardcoded-key", 0),
    ]
    return crypto.process_crypto(findings)


def _dependency_cards():
    fragmented = [_row("lodash", f"4.17.{patch}") for patch in range(_CROWD)]
    dev = [_row(f"eslint-plugin-{i:02d}", "1.0.0") for i in range(_CROWD)]
    eol_info = {"cycle": "16", "eol": "2023-09-11", "latest": "16.20.2"}
    eol = [
        {"component": f"runtime-{i:02d}", "version": "16.0.0", "severity": "HIGH", "eol_info": eol_info}
        for i in range(_CROWD)
    ]
    duplicates = [_row(name, "1.0.0", direct=True) for name in ("axios", "got", "moment", "dayjs", "luxon")]
    return [
        *dependencies.analyze_version_fragmentation(fragmented),
        *dependencies.analyze_dev_in_production(dev),
        *dependencies.analyze_end_of_life(_produced("end_of_life", {"eol_issues": eol})),
        *graph.analyze_duplicate_packages(duplicates),
    ]


def _outdated_cards():
    installs = [(f"lib-{i:02d}", "1.0.0", "2.4.1", True) for i in range(_CROWD)]
    installs += [(f"sub-{i:02d}", "0.9.0", "1.0.0", False) for i in range(5)]
    outdated = [
        {"component": name, "current_version": current, "latest_version": latest, "severity": "INFO"}
        for name, current, latest, _ in installs
    ]
    ahead = [{"component": "urllib3", "current_version": "2.3.0", "default_version": "2.2.3", "severity": "INFO"}]
    findings = _produced("outdated_packages", {"outdated_dependencies": outdated, "ahead_of_default": ahead})
    vulnerable = [_vuln("lib-00", "1.0.0", _advisory("CVE-2024-1111", "HIGH", "1.0.1"))]
    rows = [_row(name, current, direct=direct) for name, current, _, direct in installs]
    return dependencies.analyze_outdated_dependencies(findings, vulnerable, rows)


def _graph_cards():
    chain = [_row("step-00", "1.0.0", direct=True)] + [
        _row(f"step-{step:02d}", "1.0.0", parent_components=[f"pkg:npm/step-{step - 1:02d}@1.0.0"])
        for step in range(1, _CROWD + 8)
    ]
    cycle = [
        _row("ring-a", "1.0.0", direct=True, parent_components=["pkg:npm/ring-b@1.0.0"]),
        _row("ring-b", "1.0.0", parent_components=["pkg:npm/ring-a@1.0.0"]),
    ]
    return graph.analyze_deep_dependency_chains(chain + cycle, max_dependency_depth=5)


def _trend_cards():
    previous = trends.PreviousScan()
    previous.add(_vuln("lodash", "4.17.20", _advisory("CVE-2020-8203", "HIGH")))
    current = [
        _vuln(f"pkg-{i:02d}", "1.0.0", _advisory(f"CVE-2024-{i:04d}", "CRITICAL" if i % 2 else "HIGH"))
        for i in range(_CROWD)
    ]
    licence_churn = [_license(f"new-lib-{i:02d}", "GPL-3.0") for i in range(12)]
    recurrence = {
        f"CVE-2023-{i:04d}": trends.CveRecurrence(
            scans={f"scan-{s}" for s in range(4)}, components={f"pkg-{i:02d}"}, severity="CRITICAL"
        )
        for i in range(_CROWD)
    }
    return [
        *trends.analyze_regressions(current, previous),
        *trends.analyze_regressions(licence_churn, trends.PreviousScan()),
        *trends.analyze_recurring_issues(recurrence, 10),
    ]


def _cross_project_cards():
    projects = [
        {
            "project_id": f"p{i}",
            "project_name": f"App{i}",
            "cves": ["CVE-2021-44228", "CVE-2022-22965"],
            "total_critical": 6 + i,
            "total_high": i,
        }
        for i in range(4)
    ]
    shared = [
        {"name": f"shared-{i:02d}", "versions": ["1.0.0", "2.0.0"], "version_count": 2, "project_count": 3}
        for i in range(_CROWD)
    ]
    return insights.analyze_cross_project_patterns(
        {"projects": projects, "shared_packages": shared, "total_projects": 6}
    )


def _risk_cards():
    findings = [
        _vuln("log4j-core", "2.14.1", _advisory("CVE-2021-44228", "CRITICAL", "2.17.1", in_kev=True)),
        _vuln("old-xml", "1.0.0", _advisory("CVE-2019-0001", "HIGH", "1.2.0"), _advisory("CVE-2019-0002", "HIGH")),
        {"type": "eol", "severity": "HIGH", "component": "old-xml", "version": "1.0.0", "details": {}, "id": "eol-1"},
        _quality("old-xml", 2.0, maintained=False),
    ]
    rows = [
        _row("app", "1.0.0", direct=True),
        _row("old-xml", "1.0.0", parent_components=["pkg:npm/app@1.0.0"]),
        _row("log4j-core", "2.14.1", direct=True),
    ]
    large_tree = [_row(f"dep-{i:03d}", "1.0.0", direct=i < 10) for i in range(501)]
    packages = risks.roll_up_packages(findings)
    return [
        *risks.detect_critical_hotspots(packages),
        *risks.detect_toxic_dependencies(packages),
        *risks.analyze_attack_surface(rows, findings),
        *risks.analyze_attack_surface(large_tree, []),
    ]


def _cards():
    return [
        card.to_dict()
        for build in (
            _vulnerability_cards,
            _exploited_cards,
            _incident_cards,
            _code_cards,
            _license_cards,
            _quality_cards,
            _crypto_cards,
            _dependency_cards,
            _outdated_cards,
            _graph_cards,
            _trend_cards,
            _cross_project_cards,
            _risk_cards,
        )
        for card in build()
    ]


def test_every_card_keeps_its_fields():
    lines = [json.dumps(card, sort_keys=True) for card in _cards()]
    if os.environ.get("DC_RECORD_CARDS") == "1":
        _RECORDED.parent.mkdir(exist_ok=True)
        _RECORDED.write_text("\n".join(lines) + "\n")

    assert lines == _RECORDED.read_text().splitlines()
