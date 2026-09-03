"""Pipeline-vs-fold equality over a cartesian finding corpus.

Temporary by construction: it compares two implementations and is deleted in the same
change that deletes the Mongo pipeline. Its job is to prove the translation, not to
guard it afterwards.
"""

import itertools

import pytest

from app.core.constants import (
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
    REACHABILITY_LEVEL_IMPORT,
    REACHABILITY_LEVEL_SYMBOL,
)
from app.models.stats import Stats
from app.services.analysis.stats import calculate_comprehensive_stats, compute_stats
from app.services.reachability_enrichment import _build_component_language_map
from tests.mocks.fake_mongo import FakeDatabase

_SCAN = "scan-differential"

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "INFO", "UNKNOWN")
_TYPES = ("vulnerability", "secret", "sast")
_REACHABLE = (True, False, None)
_LEVELS = (REACHABILITY_LEVEL_SYMBOL, REACHABILITY_LEVEL_IMPORT)
# One value below, ON, and above every EPSS threshold the pipeline tests: 0.01, 0.1, 0.5, 0.7.
# The on-threshold values are what keep a `>` from passing as the pipeline's `$gte`.
_EPSS = (None, 0.005, 0.01, 0.05, 0.1, 0.2, 0.5, 0.55, 0.7, 0.75)
_KEV = (False, True)
# Every branch of the secret predicates: actionable, historical, deprioritized, unknown tree.
_VERIFIED_TREE = ((True, True), (True, False), (False, True), (False, False), (None, None), (None, False))

# Half the components resolve to a callgraph language; the other half are OS packages.
_COMPONENTS = tuple(f"pkg{i}" for i in range(17))
_LANGS = {name: frozenset({"python"}) for i, name in enumerate(_COMPONENTS) if i % 2 == 0}


def build_corpus() -> list[dict]:
    """7 x 3 x 3 x 2 x 10 x 2 x 6 = 15120 findings; do not shorten it."""
    docs: list[dict] = []
    combos = itertools.product(_SEVERITIES, _TYPES, _REACHABLE, _LEVELS, _EPSS, _KEV, _VERIFIED_TREE)
    for i, (sev, ftype, reachable, level, epss, kev, (verified, in_tree)) in enumerate(combos):
        # itertools.product varies the rightmost axis fastest, so a selector keyed on a modulus
        # sharing a factor with the axis sizes collapses onto one axis: i % 2 and i % 3 would
        # just re-read _VERIFIED_TREE. 11, 13 and 19 are coprime with the 15120-element product,
        # so each of these choices takes every value against every axis value.
        spin, alt, waiver = i % 11, i % 13, i % 19

        details: dict = {}
        if epss is not None:
            details["epss_score"] = epss
        if kev:
            details[DETAILS_KEY_IN_KEV] = True
            details[DETAILS_KEY_KEV_RANSOMWARE] = spin % 2 == 0
        # Straddles REACHABILITY_HIGH_CONFIDENCE_THRESHOLD (0.6) from below, on, and above.
        details["reachability"] = {"confidence_score": (0.4, 0.6, 0.9)[spin % 3]}
        # Both persisted shapes of "no value": an explicit null and an absent key.
        if verified is not None or alt % 2 == 0:
            details["verified"] = verified
        if in_tree is not None or alt % 3 == 0:
            details["in_current_tree"] = in_tree

        doc: dict = {
            "_id": f"f{i}",
            "scan_id": _SCAN,
            "type": ftype,
            "severity": sev,
            "component": _COMPONENTS[i % len(_COMPONENTS)],
            "version": "1.0.0",
            "details": details,
        }
        # Three persisted shapes of the waiver flag. ``waived: 1`` is deliberately absent:
        # FakeDatabase excludes it under ``$ne: True`` where a real server keeps it.
        if waiver % 7 == 0:
            doc["waived"] = True
        elif waiver % 7 != 1:
            doc["waived"] = False
        if reachable is not None or alt % 5 == 0:
            doc["reachable"] = reachable
        # Some documents drop the level: reachable=True with no tier must count as reachable
        # while landing in neither confirmed nor likely.
        if spin % 5 != 0:
            doc["reachability_level"] = level
        docs.append(doc)
    return docs


async def seeded_db(docs: list[dict]) -> FakeDatabase:
    db = FakeDatabase()
    await db.findings.insert_many(docs)
    await db.dependencies.insert_many(
        [
            {"_id": f"d{i}", "scan_id": _SCAN, "name": name, "type": "pypi" if i % 2 == 0 else "deb"}
            for i, name in enumerate(_COMPONENTS)
        ]
    )
    return db


# One FakeDatabase aggregation over 15120 documents costs a couple of seconds; pay it once.
_MEMO: dict[str, tuple[Stats, Stats]] = {}


async def both() -> tuple[Stats, Stats]:
    """(pipeline result, fold result) over the shared corpus."""
    if "pair" not in _MEMO:
        docs = build_corpus()
        db = await seeded_db(docs)
        _MEMO["pair"] = (await calculate_comprehensive_stats(db, _SCAN), compute_stats(docs, _LANGS))
    return _MEMO["pair"]


@pytest.mark.asyncio
async def test_corpus_size_is_the_full_cartesian_product():
    assert len(build_corpus()) == 15120


def test_corpus_covers_every_persisted_shape():
    """Guards the coprime selectors: a shape the corpus never takes is a rule never compared."""
    docs = build_corpus()
    details = [doc["details"] for doc in docs]

    for field in ("verified", "in_current_tree"):
        assert any(field not in d for d in details), f"{field} is never absent"
        assert any(field in d and d[field] is None for d in details), f"{field} is never an explicit null"

    assert any("reachable" not in doc for doc in docs), "reachable is never absent"
    assert any("reachable" in doc and doc["reachable"] is None for doc in docs), "reachable is never an explicit null"
    assert any("reachability_level" not in doc for doc in docs), "the untiered-reachable case is never built"
    assert {doc.get("waived", "absent") for doc in docs} == {True, False, "absent"}

    ransomware_confidences = {
        doc["details"]["reachability"]["confidence_score"]
        for doc in docs
        if doc["details"].get(DETAILS_KEY_KEV_RANSOMWARE) is True
    }
    assert ransomware_confidences == {0.4, 0.6, 0.9}, "KEV ransomware is pinned to one confidence value"


@pytest.mark.asyncio
async def test_seeded_language_map_matches_the_db_derived_one():
    """The literal map handed to the fold must equal what the pipeline side derives from Mongo."""
    db = await seeded_db(build_corpus())
    assert await _build_component_language_map(db, _SCAN) == _LANGS


@pytest.mark.asyncio
async def test_severity_buckets_match():
    pipeline, fold = await both()
    fields = ("critical", "high", "medium", "low", "negligible", "info", "unknown", "risk_score")
    assert [getattr(fold, f) for f in fields] == [getattr(pipeline, f) for f in fields]


@pytest.mark.asyncio
async def test_adjusted_risk_score_matches():
    pipeline, fold = await both()
    assert fold.adjusted_risk_score == pipeline.adjusted_risk_score
    # A corpus that never exercises a modifier would pass vacuously.
    assert fold.adjusted_risk_score != fold.risk_score


@pytest.mark.asyncio
async def test_prioritized_matches():
    pipeline, fold = await both()
    assert fold.prioritized == pipeline.prioritized
    assert pipeline.prioritized.actionable_total > 0
    assert pipeline.prioritized.deprioritized_count > 0


@pytest.mark.asyncio
async def test_full_stats_match():
    pipeline, fold = await both()
    assert fold.model_dump() == pipeline.model_dump()


@pytest.mark.asyncio
async def test_secret_priority_matches():
    pipeline, fold = await both()
    assert fold.secret_priority == pipeline.secret_priority
    assert pipeline.secret_priority.total > 0
    assert pipeline.secret_priority.unknown_tree_count > 0


@pytest.mark.asyncio
async def test_threat_intel_matches():
    pipeline, fold = await both()
    assert fold.threat_intel == pipeline.threat_intel
    assert pipeline.threat_intel.kev_count > 0
    assert pipeline.threat_intel.high_epss_count > 0
    assert pipeline.threat_intel.medium_epss_count > 0
    assert pipeline.threat_intel.active_exploitation_count > 0
    assert pipeline.threat_intel.weaponized_count > 0
    assert pipeline.threat_intel.avg_epss_score is not None
