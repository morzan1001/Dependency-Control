"""The release gate for dropping the derivation: no stored document may disagree with its scalar,
and no owner may be listed that no provenance entry names.

The gate has to be exactly as strict as the migration itself, so the two are checked against one
corpus rather than each other's description. It also has to survive the runbook: an operator who
pastes the mongosh spellings must run the filters the script runs.
"""

import json
import pathlib
from unittest.mock import AsyncMock

import pytest

import scripts.backfill_project_team_ids as backfill
from scripts.backfill_project_team_ids import (
    EXIT_DRIFT_FOUND,
    count_drift,
    count_provenance_gaps,
    drift_filter,
    plan_team_id_expansion,
    provenance_gap_filter,
    run_verify,
)
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.mongo_array_cases import DRIFT_DOCS

_RUNBOOK = pathlib.Path(__file__).parents[2] / "scripts" / "README-deploy-multi-team-phase-1.md"
_COUNT_CALL = "db.projects.countDocuments("
_GATE_SECTION = "### 6b."

_CLEAN = {
    "_id": "clean",
    "team_id": "t1",
    "team_source": "manual",
    "team_ids": ["t1"],
    "team_sources": {"t1": "manual"},
}
# A transfer that wrote the scalar and nothing else — invisible while the model still derives.
_TRANSFERRED = {
    "_id": "transferred",
    "team_id": "t_new",
    "team_source": "github",
    "team_ids": ["t_old"],
    "team_sources": {"t_old": "github"},
}


async def _seeded(*docs) -> FakeDatabase:
    db = FakeDatabase()
    for doc in docs:
        await db.projects.insert_one(doc)
    return db


@pytest.mark.asyncio
async def test_the_gate_passes_only_when_nothing_disagrees():
    assert await count_drift(await _seeded(_CLEAN)) == 0


@pytest.mark.asyncio
async def test_the_gate_catches_a_transfer_that_wrote_the_scalar_only():
    assert await count_drift(await _seeded(_CLEAN, _TRANSFERRED)) == 1


@pytest.mark.asyncio
async def test_the_gate_catches_provenance_that_disagrees_while_the_owner_matches():
    drifted = {**_CLEAN, "_id": "p", "team_sources": {"t1": "gitlab"}}

    assert await count_drift(await _seeded(drifted)) == 1


@pytest.mark.asyncio
async def test_the_gate_catches_a_project_the_backfill_never_reached():
    assert await count_drift(await _seeded({"_id": "p", "team_id": "t1", "team_source": "manual"})) == 1


@pytest.mark.asyncio
async def test_the_gate_catches_a_null_list():
    """team_ids: null is the one stored shape that no longer loads into the model at all."""
    assert await count_drift(await _seeded({"_id": "p", "team_ids": None, "team_sources": {}})) == 1


@pytest.mark.asyncio
async def test_the_gate_agrees_with_the_migration_over_the_whole_corpus():
    """A count of 0 has to mean a re-run of the backfill would plan nothing, or it proves nothing."""
    docs = [{"_id": f"p{index}", **doc} for index, doc in enumerate(DRIFT_DOCS)]
    db = await _seeded(*docs)

    selected = sorted(doc["_id"] for doc in await db.projects.find(drift_filter(), {"_id": 1}).to_list(None))

    assert selected == sorted(update.project_id for update in plan_team_id_expansion(docs))
    assert selected, "the corpus must contain disagreeing documents, or the comparison is vacuous"


@pytest.mark.asyncio
async def test_verify_reports_success_only_on_a_clean_database():
    assert await run_verify(await _seeded(_CLEAN)) == 0
    assert await run_verify(await _seeded(_CLEAN, _TRANSFERRED)) == EXIT_DRIFT_FOUND


def _published_filters() -> list[dict]:
    """Every ``countDocuments`` argument the runbook's gate section publishes, in order."""
    body = _RUNBOOK.read_text()
    cursor = body.index(_GATE_SECTION)
    # Bounded to the gate's own section: later sections publish counts of their own, and reading
    # those as gate filters would compare the gate against a query it never runs.
    body = body[: body.index("\n## ", cursor)]
    filters = []
    while (call := body.find(_COUNT_CALL, cursor)) != -1:
        start = call + len(_COUNT_CALL)
        end = body.index("\n})", start) + 2  # keep the closing brace, drop the call's own paren
        filters.append(json.loads(body[start:end]))
        cursor = end
    return filters


def test_the_runbook_publishes_the_filters_the_script_runs():
    """An operator pastes the mongosh spellings; if they drift from the script they check nothing."""
    assert _published_filters() == [drift_filter(), provenance_gap_filter()]


@pytest.mark.asyncio
async def test_the_gate_catches_an_owner_no_provenance_names():
    """An entry no team_sources key names belongs to no provider, so no sync can retire it."""
    db = await _seeded({"_id": "p", "team_ids": ["A"], "team_sources": {}})

    assert await count_provenance_gaps(db) == 1


@pytest.mark.asyncio
async def test_a_fully_provenanced_project_has_no_gap():
    db = await _seeded(_CLEAN, {"_id": "empty", "team_ids": [], "team_sources": {}})

    assert await count_provenance_gaps(db) == 0


@pytest.mark.asyncio
async def test_the_gate_answers_to_a_gap_on_its_own(monkeypatch):
    """Past the cutover a co-owned project disagrees with its scalar by design, so §7 retires the
    scalar comparison — while an owner no provenance names is still one no sync can retire. The
    gate has to fail on that count alone, or the check goes with the comparison."""
    db = await _seeded({"_id": "p", "team_ids": ["A"], "team_sources": {}})
    monkeypatch.setattr(backfill, "count_drift", AsyncMock(return_value=0))

    assert await run_verify(db) == EXIT_DRIFT_FOUND
