"""Evidence inside a recommendation's action block is what a reader acts on.

Each of these lists is cut to a sample; without the population beside it the sample reads as
everything the card found, and the card has no chart next to it to disagree with.
"""

from app.services.recommendation.common import sampled
from app.services.recommendation.crypto import _EVIDENCE_SAMPLED, process_crypto
from app.services.recommendation.dependencies import analyze_version_fragmentation
from app.services.recommendation.graph import _PARENTS_SAMPLED, analyze_deep_dependency_chains
from app.services.recommendation.sast import _RULES_SAMPLED, process_sast
from app.services.recommendation.vulnerabilities import _CVES_SAMPLED, process_vulnerabilities

_OVER_THE_SAMPLE = 4
_DEEP_DEPTH = 12
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
    """One aggregated record per advisory on the same package, which is how the generator
    groups the CVEs it lists in the update action."""
    cve = f"CVE-2021-{index:05d}"
    return {
        "type": "vulnerability",
        "severity": "HIGH",
        "component": "log4j-core",
        "version": f"2.14.{index}",
        "details": {"fixed_version": "2.17.0", "vulnerabilities": [{"id": cve, "fixed_version": "2.17.0"}]},
        "id": f"log4j-core:2.14.{index}",
    }


def test_the_update_action_names_how_many_advisories_it_sampled():
    population = _CVES_SAMPLED + _OVER_THE_SAMPLE

    recs = process_vulnerabilities([_vulnerability(index) for index in range(population)], {}, [], None)

    action = next(r for r in recs if r.action.get("type") == "update_dependency").action
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


def _chain_to_a_leaf_with(parent_count):
    """A chain deep enough to be flagged, whose leaf also hangs off several direct packages."""
    extras = [
        {"name": f"root-{index}", "version": "1.0.0", "purl": f"pkg:npm/root-{index}@1.0.0", "direct": True}
        for index in range(parent_count - 1)
    ]
    chain = [{"name": "root", "version": "1.0.0", "purl": "pkg:npm/root@1.0.0", "direct": True}]
    previous = "pkg:npm/root@1.0.0"
    for step in range(_DEEP_DEPTH):
        purl = f"pkg:npm/step-{step}@1.0.0"
        chain.append(
            {"name": f"step-{step}", "version": "1.0.0", "purl": purl, "parent_components": [previous]}
        )
        previous = purl
    leaf = {
        "name": "leaf",
        "version": "1.0.0",
        "purl": "pkg:npm/leaf@1.0.0",
        "parent_components": [previous, *(e["purl"] for e in extras)],
    }
    return [*chain, *extras, leaf]


def test_the_deep_chain_action_names_how_many_parents_it_previewed():
    population = _PARENTS_SAMPLED + _OVER_THE_SAMPLE

    recs = analyze_deep_dependency_chains(_chain_to_a_leaf_with(population), max_dependency_depth=_MAX_DEPTH)

    action = next(r for r in recs if r.action.get("type") == "reduce_chain_depth").action
    leaf = next(chain for chain in action["deepest_chains"] if chain["package"] == "leaf")
    assert leaf["parents_total"] == population
    assert action["deepest_chains_total"] > len(action["deepest_chains"])


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
