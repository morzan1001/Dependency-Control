"""The lineage backfill collapses every rescan pointer onto its root and writes nothing a dry run
did not already report."""

import copy
from datetime import datetime, timezone
from typing import Any

import pytest

from app.core.constants import MAX_RESCAN_HOPS, SCAN_STATUS_COMPLETED
from scripts.backfill_rescan_lineage import (
    EXIT_OK,
    EXIT_UNRESOLVED,
    NO_LIMIT,
    apply_lineage_plan,
    exit_code_for,
    plan_lineage_backfill,
    run_lineage_backfill,
)
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 8, 1, tzinfo=timezone.utc)

_BATCH_SIZE = 10
_SINGLE_BATCH = 1
_NO_SLEEP_MS = 0
_ONE_REWRITE = 1
_NOTHING = 0

_PROJECT = "p1"
_HEAD = "head"
_CHAIN = (_HEAD, "r1", "r2", "r3")
_DEEPEST_LINK = len(_CHAIN) - 1
_ORPHAN_RESCAN = "orphan-rescan"
_MISSING_PARENT = "gone"
_CYCLE_LEFT = "cycle-left"
_CYCLE_RIGHT = "cycle-right"
_STANDALONE = "standalone"

_COLLECTIONS = ("scans",)


def _scan(scan_id: str, **overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "_id": scan_id,
        "project_id": _PROJECT,
        "status": SCAN_STATUS_COMPLETED,
        "created_at": _NOW,
    }
    doc.update(overrides)
    return doc


async def _seed_chain(db: FakeDatabase) -> None:
    """A chain whose links name their immediate parent instead of the root."""
    for index, scan_id in enumerate(_CHAIN):
        lineage = {"is_rescan": True, "original_scan_id": _CHAIN[index - 1]} if index else {}
        await db.scans.insert_one(_scan(scan_id, **lineage))


async def _seeded_db() -> FakeDatabase:
    db = FakeDatabase()
    await _seed_chain(db)
    return db


async def _snapshot(db: FakeDatabase) -> dict[str, dict[str, Any]]:
    return {
        name: {doc["_id"]: copy.deepcopy(doc) for doc in await db[name].find({}).to_list(None)} for name in _COLLECTIONS
    }


def _changed_ids(before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]], name: str) -> set[str]:
    keys = set(before[name]) | set(after[name])
    return {key for key in keys if before[name].get(key) != after[name].get(key)}


async def _run(db: FakeDatabase, *, execute: bool, limit: int = NO_LIMIT):
    return await run_lineage_backfill(db, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS, limit=limit, execute=execute)


@pytest.mark.asyncio
async def test_a_dry_run_leaves_every_collection_byte_for_byte() -> None:
    db = await _seeded_db()
    before = await _snapshot(db)

    plan = await _run(db, execute=False)

    assert plan.repoints
    assert await _snapshot(db) == before


@pytest.mark.asyncio
async def test_the_dry_run_report_names_exactly_what_an_execute_run_changes() -> None:
    planned_db = await _seeded_db()
    executed_db = await _seeded_db()
    reported = await _run(planned_db, execute=False)

    before = await _snapshot(executed_db)
    await _run(executed_db, execute=True)
    after = await _snapshot(executed_db)

    assert _changed_ids(before, after, "scans") == {repoint.scan_id for repoint in reported.repoints}
    for repoint in reported.repoints:
        assert after["scans"][repoint.scan_id]["original_scan_id"] == repoint.root_id


@pytest.mark.asyncio
async def test_every_link_of_a_chain_ends_up_naming_the_root() -> None:
    db = await _seeded_db()

    await _run(db, execute=True)

    for scan_id in _CHAIN[1:]:
        assert (await db.scans.find_one({"_id": scan_id}))["original_scan_id"] == _HEAD


@pytest.mark.asyncio
async def test_a_pointer_already_at_the_root_is_reported_rather_than_rewritten() -> None:
    db = FakeDatabase()
    await db.scans.insert_one(_scan(_HEAD))
    await db.scans.insert_one(_scan(_CHAIN[1], is_rescan=True, original_scan_id=_HEAD))

    plan = await _run(db, execute=False)

    assert plan.repoints == ()
    assert plan.already_rooted == _ONE_REWRITE


@pytest.mark.asyncio
async def test_a_pointer_into_a_deleted_scan_is_left_where_it_is() -> None:
    """Retention can take the parent, and no id on that chain is a better answer than the one stored."""
    db = FakeDatabase()
    await db.scans.insert_one(_scan(_ORPHAN_RESCAN, is_rescan=True, original_scan_id=_MISSING_PARENT))

    plan = await _run(db, execute=True)

    assert plan.repoints == ()
    assert (await db.scans.find_one({"_id": _ORPHAN_RESCAN}))["original_scan_id"] == _MISSING_PARENT


@pytest.mark.asyncio
async def test_a_pointer_cycle_is_reported_and_left_alone() -> None:
    db = FakeDatabase()
    await db.scans.insert_one(_scan(_CYCLE_LEFT, is_rescan=True, original_scan_id=_CYCLE_RIGHT))
    await db.scans.insert_one(_scan(_CYCLE_RIGHT, is_rescan=True, original_scan_id=_CYCLE_LEFT))

    plan = await _run(db, execute=True)

    assert sorted(plan.unresolved) == [_CYCLE_LEFT, _CYCLE_RIGHT]
    assert plan.repoints == ()
    assert (await db.scans.find_one({"_id": _CYCLE_LEFT}))["original_scan_id"] == _CYCLE_RIGHT


@pytest.mark.asyncio
async def test_a_write_pass_that_leaves_anything_unresolved_fails() -> None:
    db = FakeDatabase()
    await db.scans.insert_one(_scan(_CYCLE_LEFT, is_rescan=True, original_scan_id=_CYCLE_RIGHT))
    await db.scans.insert_one(_scan(_CYCLE_RIGHT, is_rescan=True, original_scan_id=_CYCLE_LEFT))

    plan = await _run(db, execute=True)

    assert exit_code_for(plan, execute=True) == EXIT_UNRESOLVED


@pytest.mark.asyncio
async def test_a_dry_run_reports_the_leftovers_without_failing() -> None:
    """The dry run is a read; only a write pass claims to have finished the job."""
    db = FakeDatabase()
    await db.scans.insert_one(_scan(_CYCLE_LEFT, is_rescan=True, original_scan_id=_CYCLE_RIGHT))
    await db.scans.insert_one(_scan(_CYCLE_RIGHT, is_rescan=True, original_scan_id=_CYCLE_LEFT))

    plan = await _run(db, execute=False)

    assert plan.unresolved
    assert exit_code_for(plan, execute=False) == EXIT_OK


@pytest.mark.asyncio
async def test_a_limited_pass_is_partial_by_request_and_does_not_fail() -> None:
    db = FakeDatabase()
    await db.scans.insert_one(_scan(_CYCLE_LEFT, is_rescan=True, original_scan_id=_CYCLE_RIGHT))
    await db.scans.insert_one(_scan(_CYCLE_RIGHT, is_rescan=True, original_scan_id=_CYCLE_LEFT))
    await _seed_chain(db)

    plan = await _run(db, execute=True, limit=_ONE_REWRITE)

    assert plan.limit_reached is True
    assert exit_code_for(plan, execute=True) == EXIT_OK


@pytest.mark.asyncio
async def test_a_write_pass_that_resolved_everything_succeeds() -> None:
    db = await _seeded_db()

    plan = await _run(db, execute=True)

    assert plan.repoints
    assert exit_code_for(plan, execute=True) == EXIT_OK


@pytest.mark.asyncio
async def test_a_chain_longer_than_the_bound_collapses_the_rest_and_converges_on_a_second_run() -> None:
    """Each link is walked from its own pointer, so only links more than the bound above the root
    stay unresolved — and the run shortens the chain under them, so the next run reaches the root."""
    db = FakeDatabase()
    chain = [_HEAD] + [f"r{index}" for index in range(1, MAX_RESCAN_HOPS + 3)]
    for index, scan_id in enumerate(chain):
        lineage = {"is_rescan": True, "original_scan_id": chain[index - 1]} if index else {}
        await db.scans.insert_one(_scan(scan_id, **lineage))

    plan = await _run(db, execute=True)

    assert (await db.scans.find_one({"_id": chain[MAX_RESCAN_HOPS]}))["original_scan_id"] == _HEAD
    assert plan.unresolved == tuple(chain[MAX_RESCAN_HOPS + 1 :])

    await _run(db, execute=True)

    for scan_id in chain[1:]:
        assert (await db.scans.find_one({"_id": scan_id}))["original_scan_id"] == _HEAD


@pytest.mark.asyncio
async def test_a_scan_that_is_not_a_rescan_is_never_inspected() -> None:
    db = FakeDatabase()
    await db.scans.insert_one(_scan(_STANDALONE, original_scan_id=_HEAD))

    plan = await _run(db, execute=True)

    assert plan.inspected == _NOTHING
    assert (await db.scans.find_one({"_id": _STANDALONE}))["original_scan_id"] == _HEAD


@pytest.mark.asyncio
async def test_a_second_run_writes_nothing_further() -> None:
    db = await _seeded_db()
    await _run(db, execute=True)
    after_first = await _snapshot(db)

    plan = await _run(db, execute=True)

    assert plan.repoints == ()
    assert await _snapshot(db) == after_first


@pytest.mark.asyncio
async def test_the_limit_stops_the_walk_before_the_second_rewrite() -> None:
    db = await _seeded_db()

    plan = await _run(db, execute=True, limit=_ONE_REWRITE)

    assert plan.limit_reached is True
    assert len(plan.repoints) == _ONE_REWRITE
    assert (await db.scans.find_one({"_id": _CHAIN[_DEEPEST_LINK]}))["original_scan_id"] == _CHAIN[_DEEPEST_LINK - 1]


@pytest.mark.asyncio
async def test_the_walk_pages_rather_than_reading_one_batch() -> None:
    db = await _seeded_db()

    plan = await plan_lineage_backfill(db, batch_size=_SINGLE_BATCH, sleep_ms=_NO_SLEEP_MS, limit=NO_LIMIT)

    assert {repoint.scan_id for repoint in plan.repoints} == set(_CHAIN[2:])


@pytest.mark.asyncio
async def test_applying_the_same_plan_twice_leaves_the_same_pointers() -> None:
    db = await _seeded_db()
    plan = await plan_lineage_backfill(db, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS, limit=NO_LIMIT)

    await apply_lineage_plan(db, plan, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS)
    once = await _snapshot(db)
    await apply_lineage_plan(db, plan, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS)

    assert await _snapshot(db) == once
