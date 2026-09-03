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
# One value on each side of every EPSS threshold the pipeline tests: 0.01, 0.1, 0.5, 0.7.
_EPSS = (None, 0.005, 0.05, 0.2, 0.55, 0.75)
_KEV = (False, True)
# Every branch of the secret predicates: actionable, historical, deprioritized, unknown tree.
_VERIFIED_TREE = ((True, True), (True, False), (False, True), (False, False), (None, None), (None, False))

# Half the components resolve to a callgraph language; the other half are OS packages.
_COMPONENTS = tuple(f"pkg{i}" for i in range(17))
_LANGS = {name: frozenset({"python"}) for i, name in enumerate(_COMPONENTS) if i % 2 == 0}


def build_corpus() -> list[dict]:
    """7 x 3 x 3 x 2 x 6 x 2 x 6 = 9072 findings; do not shorten it."""
    docs: list[dict] = []
    combos = itertools.product(_SEVERITIES, _TYPES, _REACHABLE, _LEVELS, _EPSS, _KEV, _VERIFIED_TREE)
    for i, (sev, ftype, reachable, level, epss, kev, (verified, in_tree)) in enumerate(combos):
        details: dict = {}
        if epss is not None:
            details["epss_score"] = epss
        if kev:
            details[DETAILS_KEY_IN_KEV] = True
            details[DETAILS_KEY_KEV_RANSOMWARE] = i % 3 == 0
        # Straddles REACHABILITY_HIGH_CONFIDENCE_THRESHOLD (0.6) from below, on, and above.
        details["reachability"] = {"confidence_score": (0.4, 0.6, 0.9)[i % 3]}
        # Both persisted shapes of "no value": an explicit null and an absent key.
        if verified is not None or i % 2 == 0:
            details["verified"] = verified
        if in_tree is not None or i % 2 == 0:
            details["in_current_tree"] = in_tree

        doc: dict = {
            "_id": f"f{i}",
            "scan_id": _SCAN,
            "type": ftype,
            "severity": sev,
            "component": _COMPONENTS[i % len(_COMPONENTS)],
            "version": "1.0.0",
            "details": details,
            "waived": False,
        }
        if reachable is not None or i % 2 == 0:
            doc["reachable"] = reachable
        # Every fifth document drops the level: reachable=True with no tier must count as
        # reachable while landing in neither confirmed nor likely.
        if i % 5 != 0:
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


# One FakeDatabase aggregation over 9072 documents costs about a second; pay it once.
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
    assert len(build_corpus()) == 9072


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
async def test_full_stats_match():
    pipeline, fold = await both()
    assert fold.model_dump() == pipeline.model_dump()
