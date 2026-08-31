"""Window reads on the update-frequency rollup collections."""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.repositories.scans import ScanRepository
from app.repositories.update_frequency import (
    _SCAN_WINDOW_PROJECT_BATCH,
    _WINDOW_PROJECT_BATCH,
    WINDOW_HARD_LIMIT,
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
        "scan_created_at": (T0 + timedelta(minutes=minutes)).replace(tzinfo=None),
        "commit_hash": f"c-{scan_id}",
        "prev_scan_id": None,
        "dep_count": 1,
        "updates": {"patch": 1, "minor": 0, "major": 0, "unknown": 0, "downgrade": 0},
        "outdated_count": 0,
        "outdated_added": [],
        "outdated_resolved": [],
        "eco": {"pypi": 1},
        "updates_sample": [],
        "error": None,
        "schema_version": 1,
    } | overrides


class TestGroupWindowByBranch:
    @pytest.mark.asyncio
    async def test_buckets_are_keyed_by_project_and_branch_and_ordered_oldest_first(self):
        db = FakeDatabase()
        await db.scan_update_deltas.insert_one(_delta("s2", "p1", "main", 10))
        await db.scan_update_deltas.insert_one(_delta("s1", "p1", "main", 0))
        await db.scan_update_deltas.insert_one(_delta("d1", "p1", "develop", 5))
        await db.scan_update_deltas.insert_one(_delta("o1", "p2", "main", 5))

        buckets = await ScanUpdateDeltaRepository(db).group_window_by_branch(["p1", "p2"], T0 - timedelta(days=1))

        assert set(buckets) == {("p1", "main"), ("p1", "develop"), ("p2", "main")}
        assert [d["_id"] for d in buckets["p1", "main"]] == ["s1", "s2"]

    @pytest.mark.asyncio
    async def test_every_delta_names_its_project_and_branch(self):
        db = FakeDatabase()
        await db.scan_update_deltas.insert_one(_delta("s1", "p1", "main", 0))

        buckets = await ScanUpdateDeltaRepository(db).group_window_by_branch(["p1"], T0 - timedelta(days=1))

        delta = buckets["p1", "main"][0]
        assert (delta["project_id"], delta["branch"]) == ("p1", "main")

    @pytest.mark.asyncio
    async def test_deltas_before_the_window_and_of_other_schemas_are_left_out(self):
        db = FakeDatabase()
        await db.scan_update_deltas.insert_one(_delta("old", "p1", "main", -10_000))
        await db.scan_update_deltas.insert_one(_delta("future_schema", "p1", "main", 5, schema_version=99))
        await db.scan_update_deltas.insert_one(_delta("keep", "p1", "main", 5))

        buckets = await ScanUpdateDeltaRepository(db).group_window_by_branch(["p1"], T0 - timedelta(days=1))

        assert [d["_id"] for d in buckets["p1", "main"]] == ["keep"]

    @pytest.mark.asyncio
    async def test_the_large_outdated_arrays_stay_out_of_the_grouped_output(self):
        db = FakeDatabase()
        await db.scan_update_deltas.insert_one(
            _delta("s1", "p1", "main", 0, updates_sample=[{"n": "requests"}], outdated_added=["flask"])
        )

        buckets = await ScanUpdateDeltaRepository(db).group_window_by_branch(["p1"], T0 - timedelta(days=1))

        delta = buckets["p1", "main"][0]
        assert "updates_sample" not in delta
        assert delta["outdated_added"] == ["flask"]

    @pytest.mark.asyncio
    async def test_a_scope_larger_than_one_batch_is_read_in_batches(self):
        db = FakeDatabase()
        project_ids = [f"p{i}" for i in range(_WINDOW_PROJECT_BATCH * 2 + 1)]
        for project_id in project_ids:
            await db.scan_update_deltas.insert_one(_delta(f"{project_id}-s1", project_id, "main", 0))

        real_find = db.scan_update_deltas.find
        batch_sizes: list[int] = []

        def _spy(query: dict[str, Any], *args: Any, **kwargs: Any):
            batch_sizes.append(len(query["project_id"]["$in"]))
            return real_find(query, *args, **kwargs)

        db.scan_update_deltas.find = _spy  # type: ignore[method-assign]
        buckets = await ScanUpdateDeltaRepository(db).group_window_by_branch(project_ids, T0 - timedelta(days=1))

        assert len(buckets) == len(project_ids)
        assert batch_sizes == [_WINDOW_PROJECT_BATCH, _WINDOW_PROJECT_BATCH, 1]

    @pytest.mark.asyncio
    async def test_no_stage_accumulates_the_window_server_side(self):
        # Deltas carry the outdated names their scan added; accumulating those arrays in a
        # $group cost more than ten times the documents and blew the blocking-stage ceiling
        # on real data. Nothing may put them back into one.
        db = FakeDatabase()
        for index in range(3):
            await db.scan_update_deltas.insert_one(_delta(f"s{index}", "p1", "main", index))

        def _refuse(*_args: Any, **_kwargs: Any):
            raise AssertionError("the window must not be accumulated server-side")

        db.scan_update_deltas.aggregate = _refuse  # type: ignore[method-assign]
        buckets = await ScanUpdateDeltaRepository(db).group_window_by_branch(["p1"], T0 - timedelta(days=1))

        assert [d["_id"] for d in buckets["p1", "main"]] == ["s0", "s1", "s2"]

    @pytest.mark.asyncio
    async def test_an_empty_scope_issues_no_query(self):
        db = MagicMock()
        buckets = await ScanUpdateDeltaRepository(db).group_window_by_branch([], T0)

        assert buckets == {}
        assert db.scan_update_deltas.aggregate.call_count == 0


class TestFindProjectWindow:
    @pytest.mark.asyncio
    async def test_the_newest_deltas_survive_the_limit_and_come_back_oldest_first(self):
        db = FakeDatabase()
        for i in range(5):
            await db.scan_update_deltas.insert_one(_delta(f"s{i}", "p1", "main", i * 10))

        deltas = await ScanUpdateDeltaRepository(db).find_project_window("p1", "main", T0 - timedelta(days=1), 3)

        assert [d["_id"] for d in deltas] == ["s2", "s3", "s4"]

    @pytest.mark.asyncio
    async def test_the_single_project_read_keeps_the_update_samples(self):
        db = FakeDatabase()
        await db.scan_update_deltas.insert_one(_delta("s1", "p1", "main", 0, updates_sample=[{"n": "requests"}]))

        deltas = await ScanUpdateDeltaRepository(db).find_project_window("p1", "main", T0 - timedelta(days=1), 10)

        assert deltas[0]["updates_sample"] == [{"n": "requests"}]

    @pytest.mark.asyncio
    async def test_the_limit_is_spent_on_the_asked_branch_alone(self):
        # A busier sibling branch must not push the analysed branch out of its own window.
        db = FakeDatabase()
        for i in range(4):
            await db.scan_update_deltas.insert_one(_delta(f"side{i}", "p1", "side", 100 + i))
        for i in range(3):
            await db.scan_update_deltas.insert_one(_delta(f"main{i}", "p1", "main", i * 10))

        deltas = await ScanUpdateDeltaRepository(db).find_project_window("p1", "main", T0 - timedelta(days=1), 3)

        assert [d["_id"] for d in deltas] == ["main0", "main1", "main2"]


async def _seed_scan(db: FakeDatabase, scan_id: str, project_id: str, branch: str | None, minutes: int, **overrides):
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": project_id,
            "branch": branch,
            # Mongo stores naive UTC.
            "created_at": (T0 + timedelta(minutes=minutes)).replace(tzinfo=None),
            "status": "completed",
            "is_rescan": False,
        }
        | overrides
    )


class TestWindowScansByBranch:
    @pytest.mark.asyncio
    async def test_same_commit_retries_count_once(self):
        # Both read paths keep only the first scan of a same-commit run, so counting
        # the retries would report a healthy branch as half measured.
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", "main", 0, commit_hash="c1")
        for i in range(3):
            await _seed_scan(db, f"r{i}", "p1", "main", 10 + i, commit_hash="c2")

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], T0 - timedelta(days=1))

        assert activity["p1", "main"].commit_count == 2

    @pytest.mark.asyncio
    async def test_a_commit_scanned_again_later_still_counts_once(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", "main", 0, commit_hash="c1")
        await _seed_scan(db, "s2", "p1", "main", 10, commit_hash="c2")
        await _seed_scan(db, "s3", "p1", "main", 20, commit_hash="c1")

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], T0 - timedelta(days=1))

        assert activity["p1", "main"].commit_count == 2

    @pytest.mark.asyncio
    async def test_scans_naming_no_commit_each_stand_for_themselves(self):
        # Each gets a timeline bar of its own, so each must count towards coverage too.
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", "main", 0, commit_hash=None)
        await _seed_scan(db, "s2", "p1", "main", 10, commit_hash="")
        await _seed_scan(db, "s3", "p1", "main", 20)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], T0 - timedelta(days=1))

        assert activity["p1", "main"].commit_count == 3

    @pytest.mark.asyncio
    async def test_each_project_branch_reports_its_scan_count_and_newest_scan(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", "main", 0)
        await _seed_scan(db, "s2", "p1", "main", 30)
        await _seed_scan(db, "d1", "p1", "develop", 10)
        await _seed_scan(db, "o1", "p2", "main", 5)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1", "p2"], T0 - timedelta(days=1))

        assert {key: seen.commit_count for key, seen in activity.items()} == {
            ("p1", "main"): 2,
            ("p1", "develop"): 1,
            ("p2", "main"): 1,
        }
        assert activity["p1", "main"].last_scan_at == T0 + timedelta(minutes=30)

    @pytest.mark.asyncio
    async def test_the_newest_scan_comes_back_utc_aware(self):
        # A naive timestamp compares wrong against the tz-aware dates the rule ranks by.
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", "main", 0)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], None)

        assert activity["p1", "main"].last_scan_at.tzinfo is not None

    @pytest.mark.asyncio
    async def test_rescans_and_unusable_scans_are_not_counted(self):
        db = FakeDatabase()
        await _seed_scan(db, "keep", "p1", "main", 0)
        await _seed_scan(db, "rescan", "p1", "main", 10, is_rescan=True)
        await _seed_scan(db, "failed", "p1", "main", 20, status="failed")

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], T0 - timedelta(days=1))

        assert activity["p1", "main"].commit_count == 1
        assert activity["p1", "main"].last_scan_at == T0

    @pytest.mark.asyncio
    async def test_only_scans_inside_the_window_count(self):
        db = FakeDatabase()
        await _seed_scan(db, "before", "p1", "main", -10_000)
        await _seed_scan(db, "inside", "p1", "main", 10)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], T0 - timedelta(days=1))

        assert activity["p1", "main"].commit_count == 1

    @pytest.mark.asyncio
    async def test_without_a_window_the_whole_history_counts(self):
        db = FakeDatabase()
        await _seed_scan(db, "ancient", "p1", "main", -10_000)
        await _seed_scan(db, "recent", "p1", "main", 10)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], None)

        assert activity["p1", "main"].commit_count == 2

    @pytest.mark.asyncio
    async def test_scans_naming_no_branch_are_left_out(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", None, 0)
        await _seed_scan(db, "s2", "p1", "", 10)
        await _seed_scan(db, "s3", "p1", "main", 20)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], None)

        assert list(activity) == [("p1", "main")]

    @pytest.mark.asyncio
    async def test_a_scan_carrying_no_branch_field_at_all_is_left_out(self):
        db = FakeDatabase()
        await db.scans.insert_one(
            {
                "_id": "no-branch",
                "project_id": "p1",
                "created_at": T0.replace(tzinfo=None),
                "status": "completed",
                "is_rescan": False,
            }
        )
        await _seed_scan(db, "s1", "p1", "main", 10)

        # The server omits a grouping key whose field the document does not carry, so
        # the row has no branch entry to index -- only to ask for.
        rows = await db.scans.aggregate(
            [{"$group": {"_id": {"p": "$project_id", "b": "$branch"}, "n": {"$sum": 1}}}]
        ).to_list(None)
        assert {"p": "p1"} in [row["_id"] for row in rows]

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], None)

        assert list(activity) == [("p1", "main")]

    @pytest.mark.asyncio
    async def test_a_scan_dated_in_text_falls_outside_every_calendar_window(self):
        # Measured against the server: a range query is bracketed to its bound's BSON
        # type, so a date cutoff never matches a document holding a string there. The
        # backfill cannot collect such a scan and neither read path may count it.
        db = FakeDatabase()
        await _seed_scan(db, "restored", "p1", "main", 0, created_at="2026-06-01T12:00:00+00:00")
        await _seed_scan(db, "s1", "p1", "main", 10)

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], T0 - timedelta(days=1))

        assert activity["p1", "main"].commit_count == 1

    @pytest.mark.asyncio
    async def test_a_branch_whose_dates_are_restored_iso_strings_keeps_its_count(self):
        # Archive restore inserts bundle JSON verbatim, so $max can return a string.
        db = FakeDatabase()
        await _seed_scan(db, "s1", "p1", "main", 0, created_at="2026-01-01T00:00:00+00:00")
        await _seed_scan(db, "s2", "p1", "main", 10, created_at="2026-01-02T00:00:00+00:00")

        activity = await window_scans_by_branch(ScanRepository(db), ["p1"], None)

        assert activity["p1", "main"].commit_count == 2
        assert activity["p1", "main"].last_scan_at == datetime.min.replace(tzinfo=timezone.utc)

    @pytest.mark.asyncio
    async def test_a_scope_larger_than_one_batch_is_read_in_batches(self):
        db = FakeDatabase()
        project_ids = [f"p{i}" for i in range(_SCAN_WINDOW_PROJECT_BATCH * 2 + 1)]
        for project_id in project_ids:
            await _seed_scan(db, f"{project_id}-s1", project_id, "main", 0)

        real_aggregate = db.scans.aggregate
        calls: list[list[dict[str, Any]]] = []

        def _spy(pipeline: list[dict[str, Any]], **kwargs: Any):
            calls.append(pipeline)
            return real_aggregate(pipeline, **kwargs)

        db.scans.aggregate = _spy  # type: ignore[method-assign]
        activity = await window_scans_by_branch(ScanRepository(db), project_ids, T0 - timedelta(days=1))

        assert len(activity) == len(project_ids)
        assert len(calls) == 3

    @pytest.mark.asyncio
    async def test_an_empty_scope_issues_no_query(self):
        db = MagicMock()

        assert await window_scans_by_branch(ScanRepository(db), [], T0) == {}
        assert db.scans.aggregate.call_count == 0


class TestWindowHardLimit:
    def test_the_shared_document_cap_is_the_documented_one(self):
        # Both read paths truncate one branch to this many documents and report the
        # result as fully covered. Moving it silently redefines the window for every
        # project busier than it, and no differential between the paths can see that.
        assert WINDOW_HARD_LIMIT == 1000


class TestNamesByScan:
    @pytest.mark.asyncio
    async def test_scans_without_a_stored_set_are_absent_rather_than_empty(self):
        db = FakeDatabase()
        await db.scan_outdated_sets.insert_one({"_id": "s1", "names": ["flask", "requests"], "n": 2})
        await db.scan_outdated_sets.insert_one({"_id": "s2", "names": [], "n": 0})

        names = await ScanOutdatedSetRepository(db).names_by_scan(["s1", "s2", "s3"])

        assert names == {"s1": {"flask", "requests"}, "s2": set()}

    @pytest.mark.asyncio
    async def test_no_anchors_issues_no_query(self):
        db = MagicMock()
        assert await ScanOutdatedSetRepository(db).names_by_scan([]) == {}
        assert db.scan_outdated_sets.find.call_count == 0
