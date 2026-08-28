"""Window reads on the update-frequency rollup collections."""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.repositories.update_frequency import (
    _WINDOW_PROJECT_BATCH,
    ScanOutdatedSetRepository,
    ScanUpdateDeltaRepository,
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
    async def test_a_scope_larger_than_one_batch_is_read_in_batches_without_disk_spill(self):
        db = FakeDatabase()
        project_ids = [f"p{i}" for i in range(_WINDOW_PROJECT_BATCH * 2 + 1)]
        for project_id in project_ids:
            await db.scan_update_deltas.insert_one(_delta(f"{project_id}-s1", project_id, "main", 0))

        real_aggregate = db.scan_update_deltas.aggregate
        calls: list[dict[str, Any]] = []

        def _spy(pipeline: list[dict[str, Any]], **kwargs: Any):
            calls.append(kwargs)
            return real_aggregate(pipeline, **kwargs)

        db.scan_update_deltas.aggregate = _spy  # type: ignore[method-assign]
        buckets = await ScanUpdateDeltaRepository(db).group_window_by_branch(project_ids, T0 - timedelta(days=1))

        assert len(buckets) == len(project_ids)
        assert len(calls) == 3
        # Outgrowing the batch sizing must fail loudly rather than spill to the mongod's disk.
        assert all(call["allowDiskUse"] is False for call in calls)

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

        deltas = await ScanUpdateDeltaRepository(db).find_project_window("p1", T0 - timedelta(days=1), 3)

        assert [d["_id"] for d in deltas] == ["s2", "s3", "s4"]

    @pytest.mark.asyncio
    async def test_the_single_project_read_keeps_the_update_samples(self):
        db = FakeDatabase()
        await db.scan_update_deltas.insert_one(_delta("s1", "p1", "main", 0, updates_sample=[{"n": "requests"}]))

        deltas = await ScanUpdateDeltaRepository(db).find_project_window("p1", T0 - timedelta(days=1), 10)

        assert deltas[0]["updates_sample"] == [{"n": "requests"}]


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
