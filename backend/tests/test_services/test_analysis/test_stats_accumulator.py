"""Permanent pins for StatsAccumulator rules a differential corpus cannot express."""

import copy
from typing import Any

import pytest

from app.core.constants import (
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
    EPSS_ACTIVE_EXPLOITATION_THRESHOLD,
    EPSS_MEDIUM_THRESHOLD,
    EPSS_VERY_HIGH_THRESHOLD,
    REACHABILITY_HIGH_CONFIDENCE_THRESHOLD,
    REACHABILITY_LEVEL_IMPORT,
    REACHABILITY_LEVEL_SYMBOL,
)
from app.services.analysis.stats import (
    StatsAccumulator,
    _stats_projection,
    calculate_comprehensive_stats,
    compute_stats,
)
from app.services.reachability_enrichment import component_language_map
from tests.mocks.fake_mongo import FakeDatabase


def _finding(ftype="vulnerability", severity="HIGH", **details):
    return {"type": ftype, "severity": severity, "component": "pkg", "details": dict(details), "waived": False}


class TestVulnerabilityGate:
    def test_non_vulnerability_findings_never_count_as_deprioritized(self):
        """Secrets and SAST carry no EPSS; without the type gate every one of them qualifies."""
        findings = [_finding(ftype="secret"), _finding(ftype="sast"), _finding(ftype="license")]
        stats = compute_stats(findings, {})
        assert stats.prioritized.deprioritized_count == 0
        assert stats.prioritized.total == 0

    def test_unreachable_kev_vulnerability_is_deprioritized(self):
        doc = _finding(**{DETAILS_KEY_IN_KEV: True, "epss_score": 0.9})
        doc["reachable"] = False
        stats = compute_stats([doc], {})
        assert stats.prioritized.deprioritized_count == 1
        assert stats.prioritized.actionable_total == 0

    def test_actionable_severity_split_only_counts_critical_and_high(self):
        findings = [
            _finding(severity="CRITICAL", **{DETAILS_KEY_IN_KEV: True}),
            _finding(severity="HIGH", **{DETAILS_KEY_IN_KEV: True}),
            _finding(severity="MEDIUM", **{DETAILS_KEY_IN_KEV: True}),
        ]
        stats = compute_stats(findings, {})
        assert (stats.prioritized.actionable_critical, stats.prioritized.actionable_high) == (1, 1)
        assert stats.prioritized.actionable_total == 3

    def test_waived_findings_are_skipped_before_any_counter(self):
        findings = [_finding(severity="CRITICAL"), {**_finding(severity="CRITICAL"), "waived": True}]
        stats = compute_stats(findings, {})
        assert stats.critical == 1
        assert stats.prioritized.total == 1


class TestSecretGate:
    def test_tree_state_buckets_are_mutually_exclusive(self):
        findings = [
            _finding(ftype="secret", verified=True, in_current_tree=True),
            _finding(ftype="secret", verified=False, in_current_tree=False),
            _finding(ftype="secret", verified=None, in_current_tree=None),
        ]
        s = compute_stats(findings, {}).secret_priority
        assert (s.in_current_tree_count, s.historical_only_count, s.unknown_tree_count) == (1, 1, 1)
        assert s.in_current_tree_count + s.historical_only_count + s.unknown_tree_count == s.total

    def test_absent_tree_key_counts_as_unknown_not_historical(self):
        s = compute_stats([_finding(ftype="secret", verified=True)], {}).secret_priority
        assert (s.unknown_tree_count, s.historical_only_count) == (1, 0)

    def test_a_junk_tree_value_lands_in_no_bucket(self):
        """Mongo's three $eq branches all miss a non-boolean; the fold must miss it too."""
        s = compute_stats([_finding(ftype="secret", verified=True, in_current_tree="maybe")], {}).secret_priority
        assert (s.in_current_tree_count, s.historical_only_count, s.unknown_tree_count) == (0, 0, 0)
        assert s.total == 1

    def test_vulnerabilities_never_enter_the_secret_counters(self):
        s = compute_stats([_finding(verified=True, in_current_tree=True)], {}).secret_priority
        assert s.total == 0


class TestEpssTyping:
    """Every persisted shape of epss_score: missing, null, 0.0, int, float, bool, string, list, dict.
    A non-numeric one is treated as absent — decided, not inherited: the pipeline ranks
    bool and string above every number and then dies at sum(epss_scores)."""

    @pytest.mark.parametrize("junk", ["0.9", True, False, [], {}, "n/a"])
    def test_non_numeric_epss_is_treated_as_missing(self, junk):
        t = compute_stats([_finding(epss_score=junk)], {}).threat_intel
        assert t.high_epss_count == 0
        assert t.medium_epss_count == 0
        assert t.avg_epss_score is None
        assert t.max_epss_score is None
        assert t.active_exploitation_count == 0

    def test_non_numeric_epss_leaves_the_finding_deprioritized(self):
        p = compute_stats([_finding(epss_score="0.9")], {}).prioritized
        assert p.deprioritized_count == 1
        assert p.actionable_total == 0

    @pytest.mark.parametrize("details", [{"epss_score": None}, {}])
    def test_an_explicit_null_epss_is_indistinguishable_from_an_absent_key(self, details):
        """Both shapes persist today; Mongo's $gte: [null, 0.1] is false, so neither may score."""
        stats = compute_stats([_finding(**details)], {})
        assert stats.threat_intel.avg_epss_score is None
        assert stats.threat_intel.max_epss_score is None
        assert (stats.threat_intel.high_epss_count, stats.threat_intel.medium_epss_count) == (0, 0)
        assert stats.threat_intel.active_exploitation_count == 0
        assert stats.prioritized.deprioritized_count == 1

    def test_zero_epss_is_a_real_value_not_a_missing_one(self):
        t = compute_stats([_finding(epss_score=0.0)], {}).threat_intel
        assert t.avg_epss_score == 0.0
        assert t.max_epss_score == 0.0

    def test_integer_epss_is_accepted(self):
        t = compute_stats([_finding(epss_score=1)], {}).threat_intel
        assert t.max_epss_score == 1.0
        assert t.high_epss_count == 1


class TestThreatIntelBoundaries:
    def test_epss_buckets_are_exclusive_at_the_high_edge(self):
        t = compute_stats([_finding(epss_score=0.1)], {}).threat_intel
        assert (t.high_epss_count, t.medium_epss_count) == (1, 0)

    def test_weaponized_needs_kev_alongside_very_high_epss(self):
        assert compute_stats([_finding(epss_score=0.9)], {}).threat_intel.weaponized_count == 0
        assert (
            compute_stats([_finding(epss_score=0.9, **{DETAILS_KEY_IN_KEV: True})], {}).threat_intel.weaponized_count
            == 1
        )

    def test_ransomware_alone_is_weaponized(self):
        t = compute_stats([_finding(**{DETAILS_KEY_KEV_RANSOMWARE: True})], {}).threat_intel
        assert t.weaponized_count == 1

    def test_kev_and_epss_counters_ignore_the_finding_type(self):
        t = compute_stats([_finding(ftype="secret", **{DETAILS_KEY_IN_KEV: True})], {}).threat_intel
        assert t.kev_count == 1
        assert t.active_exploitation_count == 1

    def test_in_kev_truthy_non_true_does_not_count(self):
        """in_kev must be True (not just truthy); matches Mongo where $eq [1, true] is false."""
        t = compute_stats([_finding(**{DETAILS_KEY_IN_KEV: 1})], {}).threat_intel
        assert t.kev_count == 0
        assert t.active_exploitation_count == 0

    def test_medium_epss_threshold_exactly_0_01_counts(self):
        """EPSS_MEDIUM_THRESHOLD = 0.01 is inclusive on the lower bound."""
        t = compute_stats([_finding(epss_score=0.01)], {}).threat_intel
        assert t.medium_epss_count == 1
        assert t.high_epss_count == 0

    def test_very_high_epss_threshold_exactly_0_5_counts_as_weaponized(self):
        """EPSS_VERY_HIGH_THRESHOLD = 0.5 is inclusive for weaponized (with KEV)."""
        t = compute_stats([_finding(epss_score=0.5, **{DETAILS_KEY_IN_KEV: True})], {}).threat_intel
        assert t.weaponized_count == 1

    def test_active_exploitation_threshold_exactly_0_7_counts(self):
        """EPSS_ACTIVE_EXPLOITATION_THRESHOLD = 0.7 is inclusive."""
        t = compute_stats([_finding(epss_score=0.7)], {}).threat_intel
        assert t.active_exploitation_count == 1


class TestReachabilityTriState:
    def test_unanalysed_finding_counts_as_neither_reachable_nor_unreachable(self):
        r = compute_stats([_finding(), {**_finding(), "reachable": None}], {}).reachability
        assert (r.reachable_count, r.unreachable_count, r.analyzed_count) == (0, 0, 0)
        assert r.unknown_count == 2

    def test_reachable_without_a_level_is_reachable_but_in_no_tier(self):
        """reachable_count != confirmed + likely, and that is correct."""
        r = compute_stats([{**_finding(), "reachable": True}], {}).reachability
        assert r.reachable_count == 1
        assert r.confirmed_reachable_count == 0
        assert r.likely_reachable_count == 0

    def test_truthy_non_boolean_reachable_is_analysed_but_not_reachable(self):
        r = compute_stats([{**_finding(), "reachable": 1}], {}).reachability
        assert r.analyzed_count == 1
        assert (r.reachable_count, r.unreachable_count) == (0, 0)

    def test_level_alone_never_produces_a_tier(self):
        r = compute_stats([{**_finding(), "reachability_level": REACHABILITY_LEVEL_SYMBOL}], {}).reachability
        assert r.confirmed_reachable_count == 0

    def test_unknown_count_is_measured_against_vulnerabilities_only(self):
        findings = [_finding(ftype="license") for _ in range(5)] + [_finding(), _finding()]
        assert compute_stats(findings, {}).reachability.unknown_count == 2


class TestHighConfidenceGate:
    @staticmethod
    def _with_confidence(confidence, reachable=True, severity="CRITICAL"):
        doc = _finding(severity=severity)
        doc["reachable"] = reachable
        doc["reachability_level"] = REACHABILITY_LEVEL_SYMBOL
        doc["details"]["reachability"] = {"confidence_score": confidence}
        return doc

    def test_threshold_is_inclusive(self):
        r = compute_stats([self._with_confidence(REACHABILITY_HIGH_CONFIDENCE_THRESHOLD)], {}).reachability
        assert r.reachable_count_high_confidence == 1
        assert r.reachable_critical_high_confidence == 1

    def test_just_below_the_threshold_is_excluded(self):
        r = compute_stats([self._with_confidence(REACHABILITY_HIGH_CONFIDENCE_THRESHOLD - 0.01)], {}).reachability
        assert r.reachable_count_high_confidence == 0

    def test_missing_confidence_is_not_high_confidence(self):
        doc = _finding()
        doc["reachable"] = True
        assert compute_stats([doc], {}).reachability.reachable_count_high_confidence == 0

    def test_non_numeric_confidence_is_not_high_confidence(self):
        r = compute_stats([self._with_confidence("0.9")], {}).reachability
        assert r.reachable_count_high_confidence == 0

    def test_a_non_dict_reachability_block_does_not_raise(self):
        doc = _finding()
        doc["reachable"] = True
        doc["details"]["reachability"] = "unavailable"
        assert compute_stats([doc], {}).reachability.reachable_count_high_confidence == 0

    def test_unreachable_finding_is_never_high_confidence(self):
        r = compute_stats([self._with_confidence(0.9, reachable=False)], {}).reachability
        assert r.reachable_count_high_confidence == 0
        assert r.unreachable_count == 1


class TestCoverableCount:
    _LANGS = {"lodash": frozenset({"javascript"}), "requests": frozenset({"python"})}

    def test_counts_only_components_a_callgraph_could_analyse(self):
        findings = [
            {**_finding(), "component": "lodash"},
            {**_finding(), "component": "libssl3"},
            {**_finding(), "component": "requests"},
        ]
        assert compute_stats(findings, self._LANGS).reachability.coverable_count == 2

    def test_non_vulnerability_findings_are_not_coverable(self):
        findings = [{**_finding(ftype="secret"), "component": "lodash"}]
        assert compute_stats(findings, self._LANGS).reachability.coverable_count == 0

    def test_waived_findings_are_not_coverable(self):
        findings = [{**_finding(), "component": "lodash", "waived": True}, {**_finding(), "component": "requests"}]
        assert compute_stats(findings, self._LANGS).reachability.coverable_count == 1

    def test_an_empty_language_map_short_circuits_to_zero(self):
        from unittest.mock import patch

        findings = [{**_finding(), "component": "lodash"}]
        with patch("app.services.analysis.stats.lookup_component") as mock_lookup:
            compute_stats(findings, {})
            mock_lookup.assert_not_called()

    def test_a_findings_qualified_component_resolves_to_the_bare_inventory_name(self):
        langs = component_language_map([{"name": "json", "type": "npm"}])
        findings = [{**_finding(), "component": "org.acme:json"}]
        assert compute_stats(findings, langs).reachability.coverable_count == 1


class TestComponentLanguageMap:
    def test_derives_languages_from_type_then_purl(self):
        deps = [
            {"name": "requests", "type": "pypi"},
            {"name": "left-pad", "type": "npm"},
            {"name": "viapurl", "purl": "pkg:pypi/viapurl@1.0"},
            {"name": "rpmpkg", "type": "rpm"},
            {"type": "npm"},
        ]
        m = component_language_map(deps)
        assert m["requests"] == frozenset({"python"})
        assert m["left-pad"] == frozenset({"javascript", "typescript"})
        assert m["viapurl"] == frozenset({"python"})
        assert "rpmpkg" not in m

    def test_a_name_listed_twice_unions_its_languages(self):
        m = component_language_map([{"name": "x", "type": "npm"}, {"name": "x", "type": "pypi"}])
        assert m["x"] == frozenset({"javascript", "typescript", "python"})


class TestDriverReadsOneCursor:
    @pytest.mark.asyncio
    async def test_driver_hints_the_scan_id_type_index_and_does_not_prefilter_waived(self):
        """The waived rule lives in add(); severity and waived are mutated after insert, so the
        hint must sit on (scan_id, type), the only pair that is immutable post-insert."""
        db = FakeDatabase()
        captured: list[tuple] = []
        original = db.findings.find

        def _spy(query=None, projection=None, **kwargs):
            captured.append((query, projection, kwargs.get("hint")))
            return original(query, projection, **kwargs)

        db.findings.find = _spy  # type: ignore[method-assign]
        await db.findings.insert_one({"_id": "f1", "scan_id": "s1", "type": "vulnerability", "severity": "HIGH"})

        await calculate_comprehensive_stats(db, "s1")

        stats_call = next(c for c in captured if c[0] == {"scan_id": "s1"})
        assert "waived" not in stats_call[0]
        assert stats_call[1] == _stats_projection()
        assert stats_call[2] == [("scan_id", 1), ("type", 1)]

    @pytest.mark.asyncio
    async def test_driver_still_excludes_waived_findings(self):
        db = FakeDatabase()
        await db.findings.insert_one(
            {"_id": "f1", "scan_id": "s1", "type": "vulnerability", "severity": "CRITICAL", "waived": True}
        )
        await db.findings.insert_one(
            {"_id": "f2", "scan_id": "s1", "type": "vulnerability", "severity": "CRITICAL", "waived": False}
        )
        stats = await calculate_comprehensive_stats(db, "s1")
        assert stats.critical == 1

    @pytest.mark.asyncio
    async def test_driver_resolves_coverable_from_the_scans_dependencies(self):
        db = FakeDatabase()
        await db.dependencies.insert_one({"_id": "d1", "scan_id": "s1", "name": "lodash", "type": "npm"})
        await db.findings.insert_one(
            {"_id": "f1", "scan_id": "s1", "type": "vulnerability", "severity": "HIGH", "component": "lodash"}
        )
        stats = await calculate_comprehensive_stats(db, "s1")
        assert stats.reachability.coverable_count == 1
        # The seeded finding carries no ``reachable`` key, so coverable is independent of analysis.
        assert stats.reachability.analyzed_count == 0


_ORACLE_SCAN_ID = "oracle-scan"
_ORACLE_NPM_COMPONENT = "lodash"
_ORACLE_PYPI_COMPONENT = "requests"
_ORACLE_OS_COMPONENT = "openssl"
_ORACLE_DEPENDENCIES: list[dict[str, Any]] = [
    {"scan_id": _ORACLE_SCAN_ID, "name": _ORACLE_NPM_COMPONENT, "type": "npm"},
    {"scan_id": _ORACLE_SCAN_ID, "name": _ORACLE_PYPI_COMPONENT, "type": "pypi"},
    {"scan_id": _ORACLE_SCAN_ID, "name": _ORACLE_OS_COMPONENT, "type": "rpm"},
]
_LOW_CONFIDENCE = REACHABILITY_HIGH_CONFIDENCE_THRESHOLD / 2
# No counter reads these; they make a projection that fails to trim distinguishable from one that does.
_UNREAD_FIELDS: dict[str, Any] = {"finding_id": "unread", "title": "unread", "details_extra": {"nested": "unread"}}
_EXPECTED_HIGH_CONFIDENCE = 2
_EXPECTED_HIGH_CONFIDENCE_CRITICAL = 1
_EXPECTED_HIGH_CONFIDENCE_HIGH = 1


def _oracle_documents() -> list[dict[str, Any]]:
    """One document per shape the fold branches on, so that every REQUIRED_PATH moves a counter."""
    shapes: list[dict[str, Any]] = [
        {
            "_id": "o1",
            "type": "vulnerability",
            "severity": "CRITICAL",
            "component": _ORACLE_NPM_COMPONENT,
            "waived": False,
            "reachable": True,
            "reachability_level": REACHABILITY_LEVEL_SYMBOL,
            "details": {
                "epss_score": EPSS_VERY_HIGH_THRESHOLD,
                DETAILS_KEY_IN_KEV: True,
                DETAILS_KEY_KEV_RANSOMWARE: True,
                "reachability": {"confidence_score": REACHABILITY_HIGH_CONFIDENCE_THRESHOLD},
            },
        },
        {
            "_id": "o2",
            "type": "vulnerability",
            "severity": "HIGH",
            "component": _ORACLE_PYPI_COMPONENT,
            "waived": False,
            "reachable": True,
            "reachability_level": REACHABILITY_LEVEL_IMPORT,
            "details": {
                "epss_score": EPSS_ACTIVE_EXPLOITATION_THRESHOLD,
                DETAILS_KEY_IN_KEV: True,
                DETAILS_KEY_KEV_RANSOMWARE: False,
                "reachability": {"confidence_score": REACHABILITY_HIGH_CONFIDENCE_THRESHOLD},
            },
        },
        {
            # Reachable below the confidence bar: separates reachable_* from the *_high_confidence trio.
            "_id": "o3",
            "type": "vulnerability",
            "severity": "CRITICAL",
            "component": _ORACLE_NPM_COMPONENT,
            "waived": False,
            "reachable": True,
            "reachability_level": REACHABILITY_LEVEL_SYMBOL,
            "details": {
                "epss_score": EPSS_MEDIUM_THRESHOLD,
                "reachability": {"confidence_score": _LOW_CONFIDENCE},
            },
        },
        {
            "_id": "o4",
            "type": "vulnerability",
            "severity": "HIGH",
            "component": _ORACLE_OS_COMPONENT,
            "waived": False,
            "reachable": False,
            "reachability_level": REACHABILITY_LEVEL_SYMBOL,
            "details": {DETAILS_KEY_IN_KEV: True},
        },
        {
            # Unanalysed: no reachable key at all, so the tri-state None branch is folded.
            "_id": "o5",
            "type": "vulnerability",
            "severity": "MEDIUM",
            "component": _ORACLE_PYPI_COMPONENT,
            "waived": False,
            "details": {},
        },
        {
            "_id": "o6",
            "type": "vulnerability",
            "severity": "CRITICAL",
            "component": _ORACLE_NPM_COMPONENT,
            "waived": True,
            "reachable": True,
            "reachability_level": REACHABILITY_LEVEL_SYMBOL,
            "details": {
                DETAILS_KEY_IN_KEV: True,
                "reachability": {"confidence_score": REACHABILITY_HIGH_CONFIDENCE_THRESHOLD},
            },
        },
        {
            "_id": "o7",
            "type": "secret",
            "severity": "LOW",
            "waived": False,
            "details": {"verified": True, "in_current_tree": True},
        },
        {
            "_id": "o8",
            "type": "secret",
            "severity": "NEGLIGIBLE",
            "waived": False,
            "details": {"verified": False, "in_current_tree": False},
        },
        {"_id": "o9", "type": "secret", "severity": "INFO", "waived": False, "details": {}},
        {
            # Unbucketed severity on a non-vulnerability type carrying reachability.
            "_id": "o10",
            "type": "sast",
            "severity": "BLOCKER",
            "waived": False,
            "reachable": True,
            "reachability_level": REACHABILITY_LEVEL_IMPORT,
            "details": {},
        },
    ]
    return [{**shape, **_UNREAD_FIELDS, "scan_id": _ORACLE_SCAN_ID} for shape in shapes]


def _without_path(doc: dict[str, Any], path: str) -> dict[str, Any]:
    """``doc`` with one dotted path removed, standing in for a projection that forgot it."""
    stripped = copy.deepcopy(doc)
    parent: Any = stripped
    head, _, rest = path.partition(".")
    while rest:
        parent = parent.get(head)
        if not isinstance(parent, dict):
            return stripped
        head, _, rest = rest.partition(".")
    parent.pop(head, None)
    return stripped


async def _seeded_oracle_db() -> tuple[FakeDatabase, list[dict[str, Any]]]:
    db = FakeDatabase()
    for dependency in _ORACLE_DEPENDENCIES:
        await db.dependencies.insert_one(copy.deepcopy(dependency))
    documents = _oracle_documents()
    for document in documents:
        await db.findings.insert_one(copy.deepcopy(document))
    return db, documents


class TestProjectionOracle:
    """The projected read and the unprojected fold must agree.

    The derived-projection assertions all compare REQUIRED_PATHS against a dict built from
    REQUIRED_PATHS; none of them can see a path the accumulator reads but the set omits.
    """

    @pytest.mark.asyncio
    async def test_the_projected_driver_matches_the_unprojected_fold(self):
        db, documents = await _seeded_oracle_db()
        languages = component_language_map(_ORACLE_DEPENDENCIES)
        projected = await calculate_comprehensive_stats(db, _ORACLE_SCAN_ID)
        assert projected.model_dump() == compute_stats(documents, languages).model_dump()

    @pytest.mark.asyncio
    async def test_the_corpus_reaches_the_two_level_confidence_path_through_the_projection(self):
        """Nothing else in the suite folds details.reachability.confidence_score through a projection,
        so a zero here would leave the comparison above blind to the only nested path."""
        db, _ = await _seeded_oracle_db()
        reachability = (await calculate_comprehensive_stats(db, _ORACLE_SCAN_ID)).reachability
        assert reachability.reachable_count_high_confidence == _EXPECTED_HIGH_CONFIDENCE
        assert reachability.reachable_critical_high_confidence == _EXPECTED_HIGH_CONFIDENCE_CRITICAL
        assert reachability.reachable_high_high_confidence == _EXPECTED_HIGH_CONFIDENCE_HIGH

    @pytest.mark.parametrize("path", sorted(StatsAccumulator.REQUIRED_PATHS))
    def test_every_required_path_moves_a_counter_in_this_corpus(self, path):
        """Coverage guard for the comparison above: a path the corpus never exercises could be
        dropped from the projection without the oracle noticing."""
        documents = _oracle_documents()
        languages = component_language_map(_ORACLE_DEPENDENCIES)
        stripped = [_without_path(document, path) for document in documents]
        assert compute_stats(stripped, languages).model_dump() != compute_stats(documents, languages).model_dump()
