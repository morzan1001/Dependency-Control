"""The backfill records a release for every historical tag build, prunes only the tag names it
recorded, and writes nothing a dry run did not already report."""

import copy
from datetime import datetime, timezone
from typing import Any

import pytest

from app.core import ensure_utc
from app.core.constants import (
    DEFAULT_RELEASE_ENVIRONMENT,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_COMPLETED_WITH_ERRORS,
    SCAN_STATUS_FAILED,
)
from app.models.release import Release
from app.repositories import ReleaseRepository
from scripts.backfill_release_flags import NO_LIMIT, apply_plan, plan_backfill, run_backfill
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 8, 1, tzinfo=timezone.utc)
_EARLIER = datetime(2026, 7, 1, tzinfo=timezone.utc)

_BATCH_SIZE = 10
_SINGLE_BATCH = 1
_NO_SLEEP_MS = 0
_ONE_RELEASE = 1

_PROJECT = "p1"
_OTHER_PROJECT = "p2"

_TAG_BUILD = "tag-build"
_SECOND_TAG_BUILD = "tag-build-2"
_BRANCH_BUILD = "branch-build"
_FAILED_TAG_BUILD = "tag-failed"
_TAG_RESCAN = "tag-rescan"
_UNDATED_TAG_BUILD = "tag-undated"
_ALREADY_RELEASED = "already"

_TAG = "v1.2.3"
_SECOND_TAG = "v1.3.0"
_FAILED_TAG = "v0.9"
_UNDATED_TAG = "v0.8"
_ALREADY_TAG = "v2"
_MAIN_BRANCH = "main"
_KEPT_DELETED_BRANCH = "feature-x"
_STAGING_ENVIRONMENT = "staging"
_RELEASE_ROW_ID = "release-already"

_COLLECTIONS = ("scans", "releases", "projects")


def _scan(
    scan_id: str,
    *,
    branch: str,
    commit_tag: str | None,
    status: str = SCAN_STATUS_COMPLETED,
    project_id: str = _PROJECT,
    **overrides: Any,
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "_id": scan_id,
        "project_id": project_id,
        "branch": branch,
        "commit_tag": commit_tag,
        "status": status,
        "created_at": _NOW,
    }
    doc.update(overrides)
    return doc


async def _seed(db: FakeDatabase) -> None:
    await db.scans.insert_one(_scan(_TAG_BUILD, branch=_TAG, commit_tag=_TAG))
    await db.scans.insert_one(_scan(_BRANCH_BUILD, branch=_MAIN_BRANCH, commit_tag=None))
    await db.scans.insert_one(
        _scan(_FAILED_TAG_BUILD, branch=_FAILED_TAG, commit_tag=_FAILED_TAG, status=SCAN_STATUS_FAILED)
    )
    await db.scans.insert_one(_scan(_TAG_RESCAN, branch=_TAG, commit_tag=_TAG, is_rescan=True))
    await db.scans.insert_one(
        _scan(
            _ALREADY_RELEASED,
            branch=_ALREADY_TAG,
            commit_tag=_ALREADY_TAG,
            project_id=_OTHER_PROJECT,
            is_release=True,
        )
    )
    await db.releases.insert_one(
        {
            "_id": _RELEASE_ROW_ID,
            "project_id": _OTHER_PROJECT,
            "environment": _STAGING_ENVIRONMENT,
            "version": _ALREADY_TAG,
            "scan_id": _ALREADY_RELEASED,
            "released_at": _EARLIER,
        }
    )
    await db.projects.insert_one({"_id": _PROJECT, "deleted_branches": [_TAG, _KEPT_DELETED_BRANCH]})
    await db.projects.insert_one({"_id": _OTHER_PROJECT, "deleted_branches": [_ALREADY_TAG]})


async def _seeded_db() -> FakeDatabase:
    db = FakeDatabase()
    await _seed(db)
    return db


async def _snapshot(db: FakeDatabase) -> dict[str, dict[str, Any]]:
    return {
        name: {doc["_id"]: copy.deepcopy(doc) for doc in await db[name].find({}).to_list(None)}
        for name in _COLLECTIONS
    }


def _changed_ids(before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]], name: str) -> set[str]:
    keys = set(before[name]) | set(after[name])
    return {key for key in keys if before[name].get(key) != after[name].get(key)}


async def _run(db: FakeDatabase, *, execute: bool, limit: int = NO_LIMIT):
    return await run_backfill(db, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS, limit=limit, execute=execute)


@pytest.mark.asyncio
async def test_a_dry_run_leaves_every_collection_byte_for_byte() -> None:
    db = await _seeded_db()
    before = await _snapshot(db)

    plan = await _run(db, execute=False)

    assert plan.releases
    assert await _snapshot(db) == before


@pytest.mark.asyncio
async def test_the_dry_run_report_names_exactly_what_an_execute_run_changes() -> None:
    planned_db = await _seeded_db()
    executed_db = await _seeded_db()
    reported = await _run(planned_db, execute=False)

    before = await _snapshot(executed_db)
    await _run(executed_db, execute=True)
    after = await _snapshot(executed_db)

    reported_scans = {release.scan_id for release in reported.releases} | set(reported.flag_repairs)
    assert _changed_ids(before, after, "scans") == reported_scans
    assert _changed_ids(before, after, "projects") == {prune.project_id for prune in reported.prunes}
    assert len(after["releases"]) - len(before["releases"]) == len(reported.releases)


@pytest.mark.asyncio
async def test_only_a_usable_original_tag_build_is_planned() -> None:
    db = await _seeded_db()

    plan = await _run(db, execute=False)

    assert [release.scan_id for release in plan.releases] == [_TAG_BUILD]


@pytest.mark.asyncio
async def test_a_completed_with_errors_tag_build_is_still_a_release() -> None:
    db = FakeDatabase()
    await db.scans.insert_one(
        _scan(_TAG_BUILD, branch=_TAG, commit_tag=_TAG, status=SCAN_STATUS_COMPLETED_WITH_ERRORS)
    )

    plan = await _run(db, execute=False)

    assert [release.scan_id for release in plan.releases] == [_TAG_BUILD]


@pytest.mark.asyncio
async def test_a_release_row_carries_the_tag_and_the_scan_creation_time() -> None:
    db = await _seeded_db()

    await _run(db, execute=True)

    row = await db.releases.find_one({"scan_id": _TAG_BUILD})
    assert row["project_id"] == _PROJECT
    assert row["environment"] == DEFAULT_RELEASE_ENVIRONMENT
    assert row["version"] == _TAG
    # Mongo returns UTC without tzinfo, and the fake mirrors that.
    assert ensure_utc(row["released_at"]) == _NOW


@pytest.mark.asyncio
async def test_the_denormalised_flag_is_set_alongside_the_row() -> None:
    db = await _seeded_db()

    await _run(db, execute=True)

    assert (await db.scans.find_one({"_id": _TAG_BUILD}))["is_release"] is True
    assert (await db.scans.find_one({"_id": _BRANCH_BUILD})).get("is_release") is None


@pytest.mark.asyncio
async def test_a_scan_already_released_keeps_its_own_environment() -> None:
    db = await _seeded_db()

    plan = await _run(db, execute=True)

    assert plan.skipped_already_released == _ONE_RELEASE
    rows = await db.releases.find({"scan_id": _ALREADY_RELEASED}).to_list(None)
    assert [row["environment"] for row in rows] == [_STAGING_ENVIRONMENT]


@pytest.mark.asyncio
async def test_a_scan_left_holding_only_its_row_gets_the_flag_and_no_second_release() -> None:
    """A mark interrupted between its two writes is repaired, not turned into a production release."""
    db = await _seeded_db()
    await db.scans.update_one({"_id": _ALREADY_RELEASED}, {"$set": {"is_release": False}})

    plan = await _run(db, execute=True)

    assert plan.flag_repairs == (_ALREADY_RELEASED,)
    assert _ALREADY_RELEASED not in {release.scan_id for release in plan.releases}
    assert (await db.scans.find_one({"_id": _ALREADY_RELEASED}))["is_release"] is True
    rows = await db.releases.find({"scan_id": _ALREADY_RELEASED}).to_list(None)
    assert [row["environment"] for row in rows] == [_STAGING_ENVIRONMENT]


@pytest.mark.asyncio
async def test_a_run_interrupted_after_the_row_finishes_the_job_on_the_next_pass() -> None:
    db = await _seeded_db()
    plan = await plan_backfill(db, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS, limit=NO_LIMIT)
    planned = plan.releases[0]
    await ReleaseRepository(db).record(
        Release(
            project_id=planned.project_id,
            environment=DEFAULT_RELEASE_ENVIRONMENT,
            version=planned.version,
            scan_id=planned.scan_id,
            released_at=planned.released_at,
        )
    )

    await _run(db, execute=True)

    assert (await db.scans.find_one({"_id": planned.scan_id}))["is_release"] is True
    rows = await db.releases.find({"scan_id": planned.scan_id}).to_list(None)
    assert len(rows) == _ONE_RELEASE


@pytest.mark.asyncio
async def test_a_flag_set_without_a_release_row_gains_the_row_it_resolves_through() -> None:
    db = FakeDatabase()
    await db.scans.insert_one(_scan(_TAG_BUILD, branch=_TAG, commit_tag=_TAG, is_release=True))

    await _run(db, execute=True)

    row = await db.releases.find_one({"scan_id": _TAG_BUILD})
    assert row["environment"] == DEFAULT_RELEASE_ENVIRONMENT


@pytest.mark.asyncio
async def test_a_second_run_writes_nothing_further() -> None:
    db = await _seeded_db()
    await _run(db, execute=True)
    after_first = await _snapshot(db)

    plan = await _run(db, execute=True)

    assert plan.releases == ()
    assert await _snapshot(db) == after_first


@pytest.mark.asyncio
async def test_an_undated_tag_build_is_reported_rather_than_dated_by_guess() -> None:
    db = FakeDatabase()
    doc = _scan(_UNDATED_TAG_BUILD, branch=_UNDATED_TAG, commit_tag=_UNDATED_TAG)
    del doc["created_at"]
    await db.scans.insert_one(doc)

    plan = await _run(db, execute=True)

    assert plan.skipped_undated == _ONE_RELEASE
    assert plan.releases == ()
    assert await db.releases.find_one({"scan_id": _UNDATED_TAG_BUILD}) is None


@pytest.mark.asyncio
async def test_only_the_tag_names_this_run_recorded_leave_deleted_branches() -> None:
    db = await _seeded_db()

    await _run(db, execute=True)

    assert (await db.projects.find_one({"_id": _PROJECT}))["deleted_branches"] == [_KEPT_DELETED_BRANCH]
    assert (await db.projects.find_one({"_id": _OTHER_PROJECT}))["deleted_branches"] == [_ALREADY_TAG]


@pytest.mark.asyncio
async def test_a_project_whose_deleted_branches_hold_no_marked_tag_is_not_rewritten() -> None:
    db = FakeDatabase()
    await db.scans.insert_one(_scan(_TAG_BUILD, branch=_TAG, commit_tag=_TAG))
    await db.projects.insert_one({"_id": _PROJECT, "deleted_branches": [_KEPT_DELETED_BRANCH]})

    plan = await _run(db, execute=False)

    assert plan.prunes == ()


@pytest.mark.asyncio
async def test_the_limit_stops_the_walk_before_the_second_tag_build() -> None:
    db = FakeDatabase()
    await db.scans.insert_one(_scan(_TAG_BUILD, branch=_TAG, commit_tag=_TAG))
    await db.scans.insert_one(_scan(_SECOND_TAG_BUILD, branch=_SECOND_TAG, commit_tag=_SECOND_TAG))

    plan = await _run(db, execute=True, limit=_ONE_RELEASE)

    assert plan.limit_reached is True
    assert [release.scan_id for release in plan.releases] == [_TAG_BUILD]
    assert await db.releases.find_one({"scan_id": _SECOND_TAG_BUILD}) is None


@pytest.mark.asyncio
async def test_the_walk_pages_rather_than_reading_one_batch() -> None:
    db = FakeDatabase()
    await db.scans.insert_one(_scan(_TAG_BUILD, branch=_TAG, commit_tag=_TAG))
    await db.scans.insert_one(_scan(_SECOND_TAG_BUILD, branch=_SECOND_TAG, commit_tag=_SECOND_TAG))

    plan = await plan_backfill(db, batch_size=_SINGLE_BATCH, sleep_ms=_NO_SLEEP_MS, limit=NO_LIMIT)

    assert sorted(release.scan_id for release in plan.releases) == [_TAG_BUILD, _SECOND_TAG_BUILD]


@pytest.mark.asyncio
async def test_applying_the_same_plan_twice_records_one_release() -> None:
    db = await _seeded_db()
    plan = await plan_backfill(db, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS, limit=NO_LIMIT)

    await apply_plan(db, plan, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS)
    await apply_plan(db, plan, batch_size=_BATCH_SIZE, sleep_ms=_NO_SLEEP_MS)

    rows = await db.releases.find({"scan_id": _TAG_BUILD}).to_list(None)
    assert len(rows) == _ONE_RELEASE
