"""Evidence inside a recommendation's action block is what a reader acts on.

Each of these lists is cut to a sample; without the population beside it the sample reads as
everything the card found, and the card has no chart next to it to disagree with.
"""

import pytest

from app.schemas.recommendation import RecommendationType
from app.services.aggregation import ResultAggregator
from app.services.recommendation.common import AFFECTED_COMPONENTS_SHOWN, sampled
from app.services.recommendation.crypto import _EVIDENCE_SAMPLED, process_crypto
from app.services.recommendation.dependencies import (
    analyze_dev_in_production,
    analyze_end_of_life,
    analyze_outdated_dependencies,
    analyze_version_fragmentation,
)
from app.services.recommendation.graph import _DEEPEST_CHAINS_SAMPLED, analyze_deep_dependency_chains
from app.services.recommendation.incidents import (
    detect_known_exploits,
    process_hash_mismatch,
    process_malware,
    process_typosquatting,
)
from app.services.recommendation.sast import _RULES_SAMPLED, process_sast
from app.services.recommendation.vulnerabilities import _CVES_SAMPLED, process_vulnerabilities

_OVER_THE_SAMPLE = 4
_POPULATION = AFFECTED_COMPONENTS_SHOWN + _OVER_THE_SAMPLE
_MAX_DEPTH = 5
_FRAGMENTED_VERSIONS = 9
_NEWEST_VERSION = "9.0.0"


class TestSampled:
    def test_a_cut_list_carries_its_population(self):
        assert sampled("cves", ["a", "b", "c"], 2) == {"cves": ["a", "b"], "cves_total": 3}

    def test_a_complete_list_carries_its_population_too(self):
        """A reader must not have to infer completeness from the absence of a number."""
        assert sampled("cves", ["a"], 2) == {"cves": ["a"], "cves_total": 1}


def _vulnerability(index):
    """One record per advisory on the same installed copy, which is how the generator groups
    the CVEs it lists in the update action."""
    cve = f"CVE-2021-{index:05d}"
    return {
        "type": "vulnerability",
        "severity": "HIGH",
        "component": "log4j-core",
        "version": "2.14.1",
        "details": {"fixed_version": "2.17.0", "vulnerabilities": [{"id": cve, "fixed_version": "2.17.0"}]},
        "id": cve,
    }


@pytest.mark.parametrize(("direct", "action_type"), [(True, "update_dependency"), (False, "update_transitive")])
def test_the_update_action_names_how_many_advisories_it_sampled(direct, action_type):
    population = _CVES_SAMPLED + _OVER_THE_SAMPLE

    installed = {"name": "log4j-core", "version": "2.14.1", "direct": direct}

    recs = process_vulnerabilities([_vulnerability(index) for index in range(population)], [installed])

    action = next(r for r in recs if r.action.get("type") == action_type).action
    assert len(action["cves"]) == _CVES_SAMPLED
    assert action["cves_total"] == population


def _sast_finding(rule_id):
    entry = {
        "id": rule_id,
        "scanner": "opengrep",
        "severity": "HIGH",
        "title": "sql-injection",
        "description": "",
        "details": {"rule_id": rule_id, "category": "sql-injection"},
    }
    return {
        "type": "sast",
        "severity": "HIGH",
        "component": f"{rule_id}.py",
        "details": {"sast_findings": [entry], "file": f"{rule_id}.py", "line": 1},
        "id": rule_id,
    }


def test_the_fix_code_action_names_how_many_rules_it_sampled():
    population = _RULES_SAMPLED + _OVER_THE_SAMPLE

    recs = process_sast([_sast_finding(f"rule-{index:03d}") for index in range(population)])

    action = recs[0].action
    assert len(action["rules"]) == _RULES_SAMPLED
    assert action["rules_total"] == population


def _crypto_finding(index):
    return {
        "type": "crypto_weak_algorithm",
        "severity": "HIGH",
        "component": "rsa-1024",
        "description": f"weak algorithm at call site {index}",
        "details": {"asset_name": "rsa-1024", "bom_ref": f"ref-{index}", "rule_id": f"rule-{index}"},
        "id": f"crypto-{index}",
    }


def test_the_crypto_action_names_how_much_evidence_it_sampled():
    population = _EVIDENCE_SAMPLED + _OVER_THE_SAMPLE

    recs = process_crypto([_crypto_finding(index) for index in range(population)])

    action = recs[0].action
    assert len(action["evidence"]) == _EVIDENCE_SAMPLED
    assert action["evidence_total"] == population


def _chain(length):
    return [{"name": "step-0", "version": "1.0.0", "purl": "pkg:npm/step-0@1.0.0", "direct": True}] + [
        {
            "name": f"step-{step}",
            "version": "1.0.0",
            "purl": f"pkg:npm/step-{step}@1.0.0",
            "parent_components": [f"pkg:npm/step-{step - 1}@1.0.0"],
        }
        for step in range(1, length)
    ]


def test_the_deep_chain_action_names_how_many_chains_it_detailed():
    population = _DEEPEST_CHAINS_SAMPLED + _OVER_THE_SAMPLE

    recs = analyze_deep_dependency_chains(_chain(_MAX_DEPTH + population), max_dependency_depth=_MAX_DEPTH)

    action = next(r for r in recs if r.action.get("type") == "reduce_chain_depth").action
    assert len(action["deepest_chains"]) == _DEEPEST_CHAINS_SAMPLED
    assert action["deepest_chains_total"] == population


def test_the_deduplication_action_ranks_versions_before_sampling_them():
    """The version set has no order, so an unranked sample is a different five between runs."""
    dependencies = [
        {"name": "lodash", "version": f"{major}.0.0", "purl": f"pkg:npm/lodash@{major}.0.0"}
        for major in range(1, _FRAGMENTED_VERSIONS + 1)
    ]

    action = analyze_version_fragmentation(dependencies)[0].action

    assert action["packages"][0]["versions"][0] == _NEWEST_VERSION
    assert action["packages"][0]["version_count"] == _FRAGMENTED_VERSIONS
    assert action["packages_total"] == len(action["packages"])


def test_the_crypto_action_names_how_many_refs_and_rules_it_sampled():
    action = process_crypto([_crypto_finding(index) for index in range(_POPULATION)])[0].action

    for key in ("bom_refs", "rule_ids"):
        assert len(action[key]) == AFFECTED_COMPONENTS_SHOWN
        assert action[f"{key}_total"] == _POPULATION


def _produced(analyzer, result):
    aggregator = ResultAggregator()
    aggregator.aggregate(analyzer, result)
    return [f.model_dump() for f in aggregator.get_findings()]


def _malware_card():
    malware_info = {"malicious": True, "threats": ["credential-theft"], "description": "Exfiltrates npm tokens"}
    issues = [
        {"component": f"evil-{i:02d}", "version": "1.0.0", "severity": "CRITICAL", "malware_info": malware_info}
        for i in range(_POPULATION)
    ]
    return process_malware(_produced("os_malware", {"malware_issues": issues}))[0]


def _typosquat_card():
    issues = [
        {
            "component": f"reqeusts-{i:02d}",
            "version": "1.0.0",
            "imitated_package": "requests",
            "similarity": 0.9,
            "severity": "HIGH",
            "message": "Possible typosquatting detected!",
        }
        for i in range(_POPULATION)
    ]
    return process_typosquatting(_produced("typosquatting", {"typosquatting_issues": issues}))[0]


def _hash_mismatch_card():
    issues = [
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
        for i in range(_POPULATION)
    ]
    return process_hash_mismatch(_produced("hash_verification", {"hash_issues": issues}))[0]


def _eol_card():
    eol_info = {"cycle": "16", "eol": "2023-09-11", "latest": "16.20.2"}
    issues = [
        {"component": f"runtime-{i:02d}", "version": "16.0.0", "severity": "HIGH", "eol_info": eol_info}
        for i in range(_POPULATION)
    ]
    return analyze_end_of_life(_produced("end_of_life", {"eol_issues": issues}))[0]


def _outdated_card():
    dependencies = [
        {"name": f"lib-{i:02d}", "version": "1.0.0", "latest_version": "2.0.0", "direct": True}
        for i in range(_POPULATION)
    ]
    return analyze_outdated_dependencies(dependencies)[0]


@pytest.mark.parametrize("card", [_malware_card, _typosquat_card, _hash_mismatch_card, _eol_card, _outdated_card])
def test_a_package_action_names_how_many_packages_it_sampled(card):
    action = card().action

    assert len(action["packages"]) == AFFECTED_COMPONENTS_SHOWN
    assert action["packages_total"] == _POPULATION


def _trivy_findings_marked(**marks):
    """One advisory per package, marked the way enrichment marks it."""
    vulnerabilities = [
        {
            "VulnerabilityID": f"CVE-2021-{i:05d}",
            "PkgName": f"pkg-{i:02d}",
            "InstalledVersion": "1.0.0",
            "Severity": "HIGH",
        }
        for i in range(_POPULATION)
    ]
    findings = _produced("trivy", {"Results": [{"Target": "app", "Vulnerabilities": vulnerabilities}]})
    for finding in findings:
        for advisory in finding["details"]["vulnerabilities"]:
            advisory.update(marks)
    return findings


@pytest.mark.parametrize(
    ("marks", "rec_type"),
    [
        ({"in_kev": True, "kev_ransomware_use": True}, RecommendationType.RANSOMWARE_RISK),
        ({"in_kev": True}, RecommendationType.KNOWN_EXPLOIT),
        ({"epss_score": 0.9}, RecommendationType.ACTIVELY_EXPLOITED),
    ],
)
def test_an_exploit_action_names_how_many_cves_and_packages_it_sampled(marks, rec_type):
    [rec] = detect_known_exploits(_trivy_findings_marked(**marks))

    assert rec.type == rec_type
    for key in ("cves", "packages"):
        assert len(rec.action[key]) == AFFECTED_COMPONENTS_SHOWN
        assert rec.action[f"{key}_total"] == _POPULATION


def test_the_dev_dependency_action_names_each_package_once():
    dependencies = [
        {"name": f"eslint-plugin-{i:02d}", "version": version, "purl": f"pkg:npm/eslint-plugin-{i:02d}@{version}"}
        for i in range(_POPULATION)
        for version in ("1.0.0", "2.0.0")
    ]

    action = analyze_dev_in_production(dependencies)[0].action

    assert len(set(action["packages"])) == len(action["packages"]) == AFFECTED_COMPONENTS_SHOWN
    assert action["packages_total"] == _POPULATION
