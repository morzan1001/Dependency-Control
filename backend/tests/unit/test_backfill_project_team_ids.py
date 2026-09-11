"""The expand migration turns the scalar team fields into the multi-team ones."""

import copy
from typing import Any

import pytest

from scripts.backfill_project_team_ids import (
    TeamIdsUpdate,
    apply_plan,
    plan_team_id_expansion,
    run_expand,
)
from tests.mocks.fake_mongo import FakeDatabase

_BATCH_SIZE = 10
_NO_SLEEP_MS = 0
_COLLECTIONS = ("projects",)


_MISSING = object()


def _project(
    project_id: str,
    *,
    team_id: Any = _MISSING,
    team_source: str | None = None,
    team_ids: list[str] | None = None,
    team_sources: dict[str, str] | None = None,
) -> dict[str, Any]:
    doc: dict[str, Any] = {"_id": project_id}
    if team_id is not _MISSING:
        doc["team_id"] = team_id
    if team_source is not None:
        doc["team_source"] = team_source
    if team_ids is not None:
        doc["team_ids"] = team_ids
    if team_sources is not None:
        doc["team_sources"] = team_sources
    return doc


async def _snapshot(db: FakeDatabase) -> dict[str, dict[str, Any]]:
    return {
        name: {doc["_id"]: copy.deepcopy(doc) for doc in await db[name].find({}).to_list(None)} for name in _COLLECTIONS
    }


def _changed_ids(before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]], name: str) -> set[str]:
    keys = set(before[name]) | set(after[name])
    return {key for key in keys if before[name].get(key) != after[name].get(key)}


def test_a_project_with_a_team_and_a_source_expands_to_both_fields():
    plan = plan_team_id_expansion([_project("p1", team_id="t1", team_source="manual")])

    assert plan == [TeamIdsUpdate(project_id="p1", team_ids=["t1"], team_sources={"t1": "manual"})]


def test_a_project_with_a_team_but_no_source_expands_to_a_hand_assignment():
    """218 production projects had an owner and no team_source on 2026-09-11. An owner left out of
    the map belongs to no provider, so no sync could ever retire it; naming a provider would have
    that provider's next sync retire an owner on no evidence at all."""
    plan = plan_team_id_expansion([_project("p1", team_id="t1")])

    assert plan == [TeamIdsUpdate(project_id="p1", team_ids=["t1"], team_sources={"t1": "manual"})]


def test_a_project_without_a_team_expands_to_an_empty_list():
    """311 of 750 production projects had no team_id on 2026-09-11; they must get [] rather than a
    missing field, which answers no ownership filter and no $size test."""
    plan = plan_team_id_expansion([_project("p1", team_id=None)])

    assert plan == [TeamIdsUpdate(project_id="p1", team_ids=[], team_sources={})]


def test_a_project_with_a_falsy_team_id_expands_to_an_empty_list():
    plan = plan_team_id_expansion([_project("p1", team_id="")])

    assert plan == [TeamIdsUpdate(project_id="p1", team_ids=[], team_sources={})]


def test_a_project_whose_stored_list_already_matches_the_derived_value_is_skipped():
    """The migration is idempotent: a half-finished one is re-runnable. A matching stored list
    and sources are skipped; the scalar stays authoritative until writers own the list."""
    plan = plan_team_id_expansion(
        [_project("p1", team_id="t1", team_source="manual", team_ids=["t1"], team_sources={"t1": "manual"})]
    )

    assert plan == []


def test_a_stored_list_that_drifted_from_the_scalar_is_re_derived():
    """The scalar stays authoritative in this phase; if a stored list disagrees with the derived
    value, it will be overwritten."""
    plan = plan_team_id_expansion(
        [_project("p1", team_id="t1", team_source="manual", team_ids=["t1", "t2"], team_sources={"t1": "manual"})]
    )

    assert plan == [TeamIdsUpdate(project_id="p1", team_ids=["t1"], team_sources={"t1": "manual"})]


def test_stored_sources_that_drift_from_the_scalar_are_re_derived():
    """Both list and sources must match to skip. If sources diverge, the update is planned."""
    plan = plan_team_id_expansion(
        [_project("p1", team_id="t1", team_source="manual", team_ids=["t1"], team_sources={})]
    )

    assert plan == [TeamIdsUpdate(project_id="p1", team_ids=["t1"], team_sources={"t1": "manual"})]


@pytest.mark.asyncio
async def test_a_dry_run_leaves_every_collection_byte_for_byte():
    db = FakeDatabase()
    await db.projects.insert_one(_project("p1", team_id="t1"))
    before = await _snapshot(db)

    planned, matched = await run_expand(db, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS, execute=False)

    assert planned == 1
    assert matched == 0
    assert await _snapshot(db) == before


@pytest.mark.asyncio
async def test_the_dry_run_report_names_exactly_what_an_execute_run_changes():
    planned_db = FakeDatabase()
    await planned_db.projects.insert_one(_project("p1", team_id="t1"))

    executed_db = FakeDatabase()
    await executed_db.projects.insert_one(_project("p1", team_id="t1"))

    planned, _ = await run_expand(planned_db, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS, execute=False)

    before = await _snapshot(executed_db)
    _, matched = await run_expand(executed_db, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS, execute=True)
    after = await _snapshot(executed_db)

    assert planned == matched
    assert _changed_ids(before, after, "projects") == {"p1"}
    assert after["projects"]["p1"]["team_ids"] == ["t1"]
    assert after["projects"]["p1"]["team_sources"] == {"t1": "manual"}


@pytest.mark.asyncio
async def test_a_second_run_writes_nothing_further():
    db = FakeDatabase()
    await db.projects.insert_one(_project("p1", team_id="t1"))

    await run_expand(db, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS, execute=True)
    after_first = await _snapshot(db)

    planned, matched = await run_expand(db, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS, execute=True)

    assert planned == 0
    assert matched == 0
    assert await _snapshot(db) == after_first


@pytest.mark.asyncio
async def test_a_run_interrupted_after_a_batch_finishes_the_job_on_the_next_pass():
    db = FakeDatabase()
    await db.projects.insert_one(_project("p1", team_id="t1", team_source="manual"))
    await db.projects.insert_one(_project("p2", team_id="t2"))

    plan = plan_team_id_expansion([_project("p1", team_id="t1", team_source="manual"), _project("p2", team_id="t2")])
    await apply_plan(db, plan[:1])
    assert (await db.projects.find_one({"_id": "p1"}))["team_ids"] == ["t1"]
    assert (await db.projects.find_one({"_id": "p2"})).get("team_ids") is None

    planned, matched = await run_expand(db, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS, execute=True)

    assert planned == 1
    assert matched == 1
    assert (await db.projects.find_one({"_id": "p2"}))["team_ids"] == ["t2"]


@pytest.mark.asyncio
async def test_the_walk_pages_rather_than_reading_one_batch():
    db = FakeDatabase()
    await db.projects.insert_one(_project("p1", team_id="t1"))
    await db.projects.insert_one(_project("p2", team_id="t2"))

    planned, matched = await run_expand(db, batch_size=1, sleep_ms=_NO_SLEEP_MS, execute=True)

    assert planned == 2
    assert matched == 2
    assert (await db.projects.find_one({"_id": "p1"}))["team_ids"] == ["t1"]
    assert (await db.projects.find_one({"_id": "p2"}))["team_ids"] == ["t2"]


@pytest.mark.asyncio
async def test_matched_count_reflects_actual_writes_not_intents():
    """A plan intends an update for a project that does not exist; matched_count reports 0 writes
    even though the plan listed 1 update."""
    db = FakeDatabase()
    plan = [TeamIdsUpdate(project_id="p1", team_ids=["t1"], team_sources={})]

    matched = await apply_plan(db, plan)

    assert matched == 0
