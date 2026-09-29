"""The stats projection on a real server: advisory fields read out of an array of subdocuments."""

import copy

import pytest

from app.services.analysis.stats import _STATS_CURSOR_HINT, calculate_comprehensive_stats, compute_stats
from app.services.reachability_enrichment import component_language_map
from tests.test_services.test_analysis.test_stats_accumulator import (
    _ORACLE_DEPENDENCIES,
    _ORACLE_SCAN_ID,
    _oracle_documents,
)

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]


async def test_the_projected_read_matches_the_unprojected_fold(db):
    documents = _oracle_documents()
    await db.findings.create_index(_STATS_CURSOR_HINT)
    await db.dependencies.insert_many(copy.deepcopy(_ORACLE_DEPENDENCIES))
    await db.findings.insert_many(copy.deepcopy(documents))

    projected = await calculate_comprehensive_stats(db, _ORACLE_SCAN_ID)

    assert projected == compute_stats(documents, component_language_map(_ORACLE_DEPENDENCIES))
