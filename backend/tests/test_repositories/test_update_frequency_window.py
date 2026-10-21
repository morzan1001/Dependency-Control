from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.repositories.scans import ScanRepository
from app.repositories.update_frequency import (
    WINDOW_HARD_LIMIT,
    WINDOW_PROJECT_BATCH,
    ScanOutdatedSetRepository,
    ScanUpdateDeltaRepository,
    window_scans_by_branch,
)
from tests.mocks.fake_mongo import FakeDatabase

T0 = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _delta(scan_id: str, project_id: str, branch: str, minutes: int, **overrides: Any) -> dict[str, Any]:
    return {
        "_id": scan_id,
        "project_id": project_id,
        "branch": branch,
        "scan_created_at": T0 + timedelta(minutes=minutes),
        "commit_hash": f"c-{scan_id}",
        "prev_scan_id": None,
        "dep_count": 1,
        "updates": {"patch": 1, "minor": 0, "major": 0, "unknown": 0, "downgrade": 0},
        "outdated_count": 0,
        "outdated_added": [],
        "outdated_resolved": [],
        "error": None,
        "schema_version": 1,
    } | overrides


class TestWindowChains:
    @pytest.mark.asyncio
    async def test_only_the_asked_chains_are_read_and_each_comes_oldest_first(self):
        db = FakeDatabase()
        await db.scan_update_deltas.insert_one(_delta("s2", "p1", "main", 10))
        await db.scan_update_deltas.insert_one(_delta("s1", "p1", "main", 0))
        await db.scan_update_deltas.insert_one(_delta("d1", "p1", "develop", 5))
        await db.scan_update_deltas.insert_one(_delta("o1", "p2", "main", 5))

        chains = await ScanUpdateDeltaRepository(db).window_chains(
            [("p1", "main"), ("p2", "main")], T0 - timedelta(days=1), limit=10
        )

        assert {chain: [d["_id"] for d in deltas] for chain, deltas in chains.items()} == {
            ("p1", "main"): ["s1", "s2"],
            ("p2", "main"): ["o1"],
        }

    @pytest.mark.asyncio
    async def test_a_chain_busier_than_the_limit_is_read_newest_first_up_to_it(self):
        db = FakeDatabase()
        for minutes in range(5):
            await db.scan_update_deltas.insert_one(_delta(f"s{minutes}", "p1", "main", minutes))

        chains = await ScanUpdateDeltaRepository(db).window_chains([("p1", "main")], T0 - timedelta(days=1), limit=3)

        assert [d["_id"] for d in chains["p1", "main"]] == ["s2", "s3", "s4"]

    @pytest.mark.asyncio
    async def test_same_millisecond_deltas_keep_the_writers_order(self):
        db = FakeDatabase()
        for scan_id in ("b", "a", "c"):
            await db.scan_update_deltas.insert_one(_delta(scan_id, "p1", "main", 0))

        chains = await ScanUpdateDeltaRepository(db).window_chains([("p1", "main")], T0 - timedelta(days=1), limit=2)

        assert [d["_id"] for d in chains["p1", "main"]] == ["b", "c"]

    @pytest.mark.asyncio
    async def test_deltas_before_the_window_and_of_other_schemas_are_left_out(self):
        db = FakeDatabase()
        await db.scan_update_deltas.insert_one(_delta("old", "p1", "main", -10_000))
        await db.scan_update_deltas.insert_one(_delta("future_schema", "p1", "main", 5, schema_version=99))
        await db.scan_update_deltas.insert_one(_delta("keep", "p1", "main", 5))

        chains = await ScanUpdateDeltaRepository(db).window_chains([("p1", "main")], T0 - timedelta(days=1), limit=10)

        assert [d["_id"] for d in chains["p1", "main"]] == ["keep"]

    @pytest.mark.asyncio
    async def test_the_fold_gets_its_fields_and_nothing_else(self):
        db = FakeDatabase()
        await db.scan_update_deltas.insert_one(
            _delta("s1", "p1", "main", 0, updates_sample=[{"n": "requests"}], outdated_added=["flask"])
        )

        chains = await ScanUpdateDeltaRepository(db).window_chains([("p1", "main")], T0 - timedelta(days=1), limit=10)

        delta = chains["p1", "main"][0]
        assert "updates_sample" not in delta
        assert (delta["project_id"], delta["branch"], delta["outdated_added"]) == ("p1", "main", ["flask"])

    @pytest.mark.asyncio
    async def test_no_chains_issue_no_query(self):
        db = MagicMock()

        assert await ScanUpdateDeltaRepository(db).window_chains([], T0, limit=10) == {}
        assert db.scan_update_deltas.find.call_count == 0


async def _seed_scan(db: FakeDatabase, scan_id: str, project_id: str, branch: str | None, minutes: int, **overrides):
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": project_id,
            "branch": branch,
            "created_at": T0 + timedelta(minutes=minutes),
            "status": "completed",
            "is_rescan": False,
        }
        | overrides
    )


class TestWindowScansByBranch:
    @pytest.mark.asyncio
    async def test_same_commit_retries_count_once(self):
        # Both read paths keep only a same-commit run's first scan, so counting retries would halve the coverage.
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", "main", 0, commit_hash="c1")
        for i in range(3):
            await _seed_scan(db, f"r{i}", "p1", "main", 10 + i, commit_hash="c2")

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], T0 - timedelta(days=1))

        assert activity["p1"]["main"].commit_count == 2

    @pytest.mark.asyncio
    async def test_a_commit_scanned_again_later_still_counts_once(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", "main", 0, commit_hash="c1")
        await _seed_scan(db, "s2", "p1", "main", 10, commit_hash="c2")
        await _seed_scan(db, "s3", "p1", "main", 20, commit_hash="c1")

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], T0 - timedelta(days=1))

        assert activity["p1"]["main"].commit_count == 2

    @pytest.mark.asyncio
    async def test_scans_naming_no_commit_each_stand_for_themselves(self):
        # Each gets a timeline bar of its own, so each must count towards coverage too.
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", "main", 0, commit_hash=None)
        await _seed_scan(db, "s2", "p1", "main", 10, commit_hash="")
        await _seed_scan(db, "s3", "p1", "main", 20)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], T0 - timedelta(days=1))

        assert activity["p1"]["main"].commit_count == 3

    @pytest.mark.asyncio
    async def test_each_project_branch_reports_its_scan_count_and_newest_scan(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", "main", 0)
        await _seed_scan(db, "s2", "p1", "main", 30)
        await _seed_scan(db, "d1", "p1", "develop", 10)
        await _seed_scan(db, "o1", "p2", "main", 5)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1", "p2"], T0 - timedelta(days=1))

        assert {
            project: {branch: seen.commit_count for branch, seen in branches.items()}
            for project, branches in activity.items()
        } == {"p1": {"main": 2, "develop": 1}, "p2": {"main": 1}}
        assert activity["p1"]["main"].last_scan_at == T0 + timedelta(minutes=30)

    @pytest.mark.asyncio
    async def test_the_newest_scan_comes_back_utc_aware(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", "main", 0)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], None)

        assert activity["p1"]["main"].last_scan_at.tzinfo is not None

    @pytest.mark.asyncio
    async def test_rescans_and_unusable_scans_are_not_counted(self):
        db = FakeDatabase()
        await _seed_scan(db, "keep", "p1", "main", 0)
        await _seed_scan(db, "rescan", "p1", "main", 10, is_rescan=True)
        await _seed_scan(db, "failed", "p1", "main", 20, status="failed")

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], T0 - timedelta(days=1))

        assert activity["p1"]["main"].commit_count == 1
        assert activity["p1"]["main"].last_scan_at == T0

    @pytest.mark.asyncio
    async def test_only_scans_inside_the_window_count(self):
        db = FakeDatabase()
        await _seed_scan(db, "before", "p1", "main", -10_000)
        await _seed_scan(db, "inside", "p1", "main", 10)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], T0 - timedelta(days=1))

        assert activity["p1"]["main"].commit_count == 1

    @pytest.mark.asyncio
    async def test_without_a_window_the_whole_history_counts(self):
        db = FakeDatabase()
        await _seed_scan(db, "ancient", "p1", "main", -10_000)
        await _seed_scan(db, "recent", "p1", "main", 10)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], None)

        assert activity["p1"]["main"].commit_count == 2

    @pytest.mark.asyncio
    async def test_scans_naming_no_branch_are_left_out(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", None, 0)
        await _seed_scan(db, "s2", "p1", "", 10)
        await _seed_scan(db, "s3", "p1", "main", 20)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], None)

        assert {project: list(branches) for project, branches in activity.items()} == {"p1": ["main"]}

    @pytest.mark.asyncio
    async def test_a_scan_carrying_no_branch_field_at_all_is_left_out(self):
        db = FakeDatabase()
        await db.scans.insert_one(
            {
                "_id": "no-branch",
                "project_id": "p1",
                "created_at": T0,
                "status": "completed",
                "is_rescan": False,
            }
        )
        await _seed_scan(db, "s1", "p1", "main", 10)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], None)

        assert {project: list(branches) for project, branches in activity.items()} == {"p1": ["main"]}

    @pytest.mark.asyncio
    async def test_a_scan_dated_in_text_falls_outside_every_calendar_window(self):
        # A range query is bracketed to its bound's BSON type, so a date cutoff never matches a string date.
        db = FakeDatabase()
        await _seed_scan(db, "restored", "p1", "main", 0, created_at="2026-06-01T12:00:00+00:00")
        await _seed_scan(db, "s1", "p1", "main", 10)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], T0 - timedelta(days=1))

        assert activity["p1"]["main"].commit_count == 1

    @pytest.mark.asyncio
    async def test_a_branch_dated_only_in_restored_iso_strings_counts_without_a_window_neither(self):
        # Archive restore inserts bundle JSON verbatim; the walk cannot date such scans, so they elect nothing.
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", "main", 0, created_at="2026-01-01T00:00:00+00:00")
        await _seed_scan(db, "s2", "p1", "main", 10, created_at="2026-01-02T00:00:00+00:00")

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], None)

        assert activity == {}

    @pytest.mark.asyncio
    async def test_a_scope_larger_than_one_batch_is_read_in_batches(self):
        db = FakeDatabase()
        project_ids = [f"p{i}" for i in range(WINDOW_PROJECT_BATCH * 2 + 1)]
        for project_id in project_ids:
            await _seed_scan(db, f"{project_id}-s1", project_id, "main", 0)

        real_find = db.scans.find
        batch_sizes: list[int] = []

        def _spy(query: dict[str, Any], *args: Any, **kwargs: Any):
            batch_sizes.append(len(query["project_id"]["$in"]))
            return real_find(query, *args, **kwargs)

        db.scans.find = _spy  # type: ignore[method-assign]
        activity = await window_scans_by_branch(ScanRepository(db), project_ids, T0 - timedelta(days=1))

        assert len(activity) == len(project_ids)
        assert batch_sizes == [WINDOW_PROJECT_BATCH, WINDOW_PROJECT_BATCH, 1]

    @pytest.mark.asyncio
    async def test_an_empty_scope_issues_no_query(self):
        db = MagicMock()

        assert await window_scans_by_branch(ScanRepository(db), [], T0) == {}
        assert db.scans.find.call_count == 0


class TestFindDependents:
    @pytest.mark.asyncio
    async def test_the_read_stops_at_the_window(self):
        db = FakeDatabase()
        await db.scan_update_deltas.insert_many(
            [
                _delta("before", "p1", "main", -2 * 24 * 60, prev_scan_id="gone"),
                _delta("inside", "p1", "main", 0, prev_scan_id="gone"),
            ]
        )

        docs = await ScanUpdateDeltaRepository(db).find_dependents("p1", "main", ["gone"], T0 - timedelta(days=1))

        assert [doc["_id"] for doc in docs] == ["inside"]


class TestWindowHardLimit:
    def test_the_shared_document_cap_is_the_documented_one(self):
        # Both read paths truncate a branch here, so moving it silently redefines every busier project's window.
        assert WINDOW_HARD_LIMIT == 1000


class TestNamesByScan:
    @pytest.mark.asyncio
    async def test_scans_without_a_stored_set_are_absent_rather_than_empty(self):
        db = FakeDatabase()
        await db.scan_outdated_sets.insert_one({"_id": "s1", "names": ["flask", "requests"]})
        await db.scan_outdated_sets.insert_one({"_id": "s2", "names": []})

        names = await ScanOutdatedSetRepository(db).names_by_scan(["s1", "s2", "s3"])

        assert names == {"s1": {"flask", "requests"}, "s2": set()}

    @pytest.mark.asyncio
    async def test_no_anchors_issues_no_query(self):
        db = MagicMock()
        assert await ScanOutdatedSetRepository(db).names_by_scan([]) == {}
        assert db.scan_outdated_sets.find.call_count == 0
