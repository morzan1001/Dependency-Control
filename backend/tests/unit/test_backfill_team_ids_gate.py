"""The release gate for dropping the derivation: no stored document may disagree with its scalar.

The gate has to be exactly as strict as the migration itself, so the two are checked against one
corpus rather than each other's description. It also has to survive the runbook: an operator who
pastes the mongosh spelling must run the same filter the script runs.
"""

import json
import pathlib

import pytest

from scripts.backfill_project_team_ids import (
    EXIT_DRIFT_FOUND,
    count_drift,
    drift_filter,
    plan_team_id_expansion,
    run_verify,
)
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.mongo_array_cases import DRIFT_DOCS

_RUNBOOK = pathlib.Path(__file__).parents[2] / "scripts" / "README-deploy-multi-team-phase-1.md"
_COUNT_CALL = "db.projects.countDocuments("
_GATE_SECTION = "### 6b."

_CLEAN = {"_id": "clean", "team_id": "t1", "team_source": "manual", "team_ids": ["t1"], "team_sources": {"t1": "manual"}}
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


def test_the_runbook_publishes_the_filter_the_script_runs():
    """An operator pastes the mongosh spelling; if it drifts from the script it checks nothing."""
    body = _RUNBOOK.read_text()
    section = body.index(_GATE_SECTION)
    start = body.index(_COUNT_CALL, section) + len(_COUNT_CALL)
    end = body.index("\n})", start) + 2  # keep the closing brace, drop the call's own paren

    assert json.loads(body[start:end]) == drift_filter()
