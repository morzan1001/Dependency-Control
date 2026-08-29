"""The update-frequency backfill must walk each branch oldest first and resume off the ledger.

Newest-first would make every scan a baseline until the writer's self-repair rewrote it, so
the order is checked against the real writer, and so is the promise that a resumed run does
not rewrite what it already recorded.
"""

import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from scripts import backfill_update_frequency as backfill_script
from scripts.backfill_update_frequency import backfill, find_chains, recorded_scan_ids, run
from tests.mocks.fake_mongo import FakeDatabase

PROJECT = "proj-1"
BRANCH = "main"
NOW = datetime.now(tz=timezone.utc)


def _days_ago(days: float) -> datetime:
    return NOW - timedelta(days=days)


async def _seed_scan(
    db: FakeDatabase,
    scan_id: str,
    created_at: datetime,
    packages: dict[str, str],
    *,
    project_id: str = PROJECT,
    branch: str | None = BRANCH,
    status: str = "completed",
    is_rescan: bool = False,
) -> None:
    scan: dict[str, Any] = {
        "_id": scan_id,
        "project_id": project_id,
        "created_at": created_at,
        "commit_hash": f"commit-{scan_id}",
        "status": status,
        "is_rescan": is_rescan,
    }
    if branch is not None:
        scan["branch"] = branch
    await db.scans.insert_one(scan)
    for name, version in packages.items():
        await db.dependencies.insert_one(
            {
                "_id": f"{scan_id}:{name}",
                "scan_id": scan_id,
                "project_id": project_id,
                "name": name,
                "version": version,
                "type": "library",
                "purl": f"pkg:pypi/{name}@{version}",
            }
        )


async def _seed_history(db: FakeDatabase, count: int = 4, **kwargs: Any) -> None:
    """``count`` scans, one every ten days, each bumping the same package's patch level."""
    for index in range(count):
        await _seed_scan(db, f"s{index + 1}", _days_ago(60 - index * 10), {"requests": f"2.0.{index}"}, **kwargs)


@pytest.fixture
def write_order(monkeypatch):
    """Scan ids handed to the real writer, in the order the backfill fed them."""
    order: list[str] = []
    real = backfill_script.record_scan_update_delta

    async def _spy(db: Any, scan_id: str) -> None:
        order.append(scan_id)
        await real(db, scan_id)

    monkeypatch.setattr(backfill_script, "record_scan_update_delta", _spy)
    return order


def _count_delta_writes(db: FakeDatabase) -> list[str]:
    """Ids upserted into scan_update_deltas, one entry per write."""
    written: list[str] = []
    collection = db.scan_update_deltas
    real = collection.update_one

    async def _spy(query, update, upsert: bool = False):
        written.append(query.get("_id"))
        return await real(query, update, upsert=upsert)

    collection.update_one = _spy  # type: ignore[method-assign]
    return written


async def _run_backfill(db: FakeDatabase, *, since=None, concurrency: int = 1, batch_size: int = 500, execute=True):
    chains = await find_chains(db, since, None)
    return await backfill(
        db, chains, since, concurrency=concurrency, batch_size=batch_size, sleep_ms=0, execute=execute
    )


class TestOrdering:
    @pytest.mark.asyncio
    async def test_a_chain_is_fed_to_the_writer_oldest_first(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=5)

        await _run_backfill(db)

        assert write_order == ["s1", "s2", "s3", "s4", "s5"]

    @pytest.mark.asyncio
    async def test_oldest_first_writes_every_delta_exactly_once(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=5)
        written = _count_delta_writes(db)

        await _run_backfill(db)

        assert written == ["s1", "s2", "s3", "s4", "s5"]

    @pytest.mark.asyncio
    async def test_the_ledger_links_each_scan_to_its_predecessor(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=4)

        await _run_backfill(db)

        deltas = {doc["_id"]: doc for doc in await db.scan_update_deltas.find({}).to_list(None)}
        assert deltas["s1"]["is_baseline"] is True
        assert [deltas[f"s{i}"]["prev_scan_id"] for i in (2, 3, 4)] == ["s1", "s2", "s3"]
        assert [deltas[f"s{i}"]["updates"]["patch"] for i in (2, 3, 4)] == [1, 1, 1]

    @pytest.mark.asyncio
    async def test_branches_stay_ordered_when_backfilled_in_parallel(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=3)
        for index in range(3):
            await _seed_scan(
                db, f"f{index + 1}", _days_ago(55 - index * 10), {"flask": f"3.{index}.0"}, branch="feature"
            )

        await _run_backfill(db, concurrency=2)

        assert [scan_id for scan_id in write_order if scan_id.startswith("s")] == ["s1", "s2", "s3"]
        assert [scan_id for scan_id in write_order if scan_id.startswith("f")] == ["f1", "f2", "f3"]
        feature = await db.scan_update_deltas.find_one({"_id": "f3"})
        assert feature["prev_scan_id"] == "f2"

    @pytest.mark.asyncio
    async def test_paging_walks_the_whole_chain_without_repeating_a_scan(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=5)

        await _run_backfill(db, batch_size=2)

        assert write_order == ["s1", "s2", "s3", "s4", "s5"]

    @pytest.mark.asyncio
    async def test_scans_sharing_a_timestamp_are_each_fed_once(self, write_order):
        db = FakeDatabase()
        same_moment = _days_ago(30)
        for scan_id in ("sa", "sb", "sc"):
            await _seed_scan(db, scan_id, same_moment, {"requests": "2.0.0"})

        await _run_backfill(db, batch_size=1)

        assert write_order == ["sa", "sb", "sc"]


class TestResume:
    @pytest.mark.asyncio
    async def test_a_second_run_records_nothing(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=4)
        await _run_backfill(db)
        write_order.clear()

        counters = await _run_backfill(db)

        assert write_order == []
        assert counters["skipped_recorded"] == 4
        assert counters["to_record"] == 0

    @pytest.mark.asyncio
    async def test_an_aborted_run_resumes_at_the_first_unrecorded_scan(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=4)
        await backfill_script.record_scan_update_delta(db, "s1")
        await backfill_script.record_scan_update_delta(db, "s2")
        write_order.clear()

        await _run_backfill(db)

        assert write_order == ["s3", "s4"]
        deltas = {doc["_id"]: doc for doc in await db.scan_update_deltas.find({}).to_list(None)}
        assert deltas["s3"]["prev_scan_id"] == "s2"
        assert deltas["s3"]["updates"]["patch"] == 1

    @pytest.mark.asyncio
    async def test_a_delta_written_by_an_older_schema_version_is_recomputed(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=2)
        await db.scan_update_deltas.insert_one(
            {
                "_id": "s1",
                "project_id": PROJECT,
                "branch": BRANCH,
                "scan_created_at": _days_ago(60),
                "dep_count": 1,
                "error": None,
                "schema_version": 0,
            }
        )

        await _run_backfill(db)

        assert write_order == ["s1", "s2"]
        assert (await db.scan_update_deltas.find_one({"_id": "s1"}))["schema_version"] == 1

    @pytest.mark.asyncio
    async def test_a_delta_holding_a_writer_failure_is_retried(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=2)
        await db.scan_update_deltas.insert_one(
            {
                "_id": "s1",
                "project_id": PROJECT,
                "branch": BRANCH,
                "scan_created_at": _days_ago(60),
                "dep_count": 0,
                "error": "RuntimeError: transient",
                "schema_version": 1,
            }
        )

        await _run_backfill(db)

        assert write_order == ["s1", "s2"]
        stored = await db.scan_update_deltas.find_one({"_id": "s1"})
        assert stored["error"] is None
        assert stored["dep_count"] == 1

    @pytest.mark.asyncio
    async def test_recorded_ids_are_read_per_branch(self):
        db = FakeDatabase()
        await _seed_history(db, count=2)
        await _seed_scan(db, "f1", _days_ago(55), {"flask": "3.0.0"}, branch="feature")
        await _run_backfill(db)

        assert await recorded_scan_ids(db, (PROJECT, BRANCH), None) == {"s1", "s2"}
        assert await recorded_scan_ids(db, (PROJECT, "feature"), None) == {"f1"}


class TestScope:
    @pytest.mark.asyncio
    async def test_since_days_leaves_older_scans_alone(self, write_order):
        db = FakeDatabase()
        await _seed_scan(db, "old", _days_ago(200), {"requests": "1.0.0"})
        await _seed_history(db, count=2)

        await _run_backfill(db, since=_days_ago(90))

        assert write_order == ["s1", "s2"]
        assert await db.scan_update_deltas.find_one({"_id": "old"}) is None

    @pytest.mark.asyncio
    async def test_project_id_restricts_the_chains(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=2)
        await _seed_scan(db, "o1", _days_ago(40), {"requests": "2.0.0"}, project_id="proj-2")

        chains = await find_chains(db, None, "proj-2")
        await backfill(db, chains, None, concurrency=1, batch_size=500, sleep_ms=0, execute=True)

        assert write_order == ["o1"]

    @pytest.mark.asyncio
    async def test_a_scan_naming_no_branch_yields_no_chain(self):
        db = FakeDatabase()
        await _seed_scan(db, "nameless", _days_ago(40), {"requests": "1.0.0"}, branch=None)
        await _seed_scan(db, "blank", _days_ago(39), {"requests": "1.0.1"}, branch="")

        assert await find_chains(db, None, None) == []

    @pytest.mark.asyncio
    async def test_two_projects_on_the_same_branch_stay_separate_chains(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=2)
        await _seed_scan(db, "o1", _days_ago(55), {"requests": "9.0.0"}, project_id="proj-2")
        await _seed_scan(db, "o2", _days_ago(45), {"requests": "9.1.0"}, project_id="proj-2")

        await _run_backfill(db)

        assert write_order == ["s1", "s2", "o1", "o2"]
        assert (await db.scan_update_deltas.find_one({"_id": "s2"}))["prev_scan_id"] == "s1"
        assert (await db.scan_update_deltas.find_one({"_id": "o2"}))["prev_scan_id"] == "o1"
        assert (await db.scan_update_deltas.find_one({"_id": "o1"}))["is_baseline"] is True

    @pytest.mark.asyncio
    async def test_unusable_and_rescan_scans_never_reach_the_writer(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=2)
        await _seed_scan(db, "failed", _days_ago(45), {"requests": "2.0.0"}, status="failed")
        await _seed_scan(db, "rescan", _days_ago(44), {"requests": "2.0.0"}, is_rescan=True)

        await _run_backfill(db)

        assert write_order == ["s1", "s2"]

    @pytest.mark.asyncio
    async def test_a_scan_without_a_usable_date_is_not_enumerated(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=2)
        await db.scans.insert_one(
            {"_id": "undated", "project_id": PROJECT, "branch": BRANCH, "status": "completed", "is_rescan": False}
        )

        chains = await find_chains(db, None, None)

        assert sum(count for _chain, count in chains) == 2
        await backfill(db, chains, None, concurrency=1, batch_size=500, sleep_ms=0, execute=True)
        assert write_order == ["s1", "s2"]

    @pytest.mark.asyncio
    async def test_scans_without_a_branch_are_left_alone(self, write_order):
        # The writer refuses them, so a chain built from them would be retried on every
        # run and never converge. Both read paths skip them for the same reason.
        db = FakeDatabase()
        await _seed_scan(db, "n1", _days_ago(60), {"requests": "2.0.0"}, branch=None)
        await _seed_scan(db, "n2", _days_ago(50), {"requests": "2.1.0"}, branch=None)
        await _seed_scan(db, "m1", _days_ago(40), {"requests": "2.1.0"}, branch="main")
        await _seed_scan(db, "m2", _days_ago(30), {"requests": "2.2.0"}, branch="main")

        await _run_backfill(db)

        assert write_order == ["m1", "m2"]
        assert await db.scan_update_deltas.find_one({"_id": "n1"}) is None


class TestDryRun:
    @pytest.mark.asyncio
    async def test_dry_run_counts_the_work_without_writing(self, write_order):
        db = FakeDatabase()
        await _seed_history(db, count=3)

        counters = await _run_backfill(db, execute=False)

        assert counters["to_record"] == 3
        assert counters["recorded"] == 0
        assert write_order == []
        assert await db.scan_update_deltas.find({}).to_list(None) == []

    @pytest.mark.parametrize(
        ("argv", "execute"),
        [([], False), (["--dry-run"], False), (["--execute"], True)],
    )
    def test_writing_takes_an_explicit_flag(self, monkeypatch, argv, execute):
        seen: dict[str, bool] = {}

        async def _capture(args):
            seen["execute"] = args.execute
            return 0

        monkeypatch.setattr(backfill_script, "run", _capture)
        monkeypatch.setattr(sys, "argv", ["backfill_update_frequency", *argv])

        assert backfill_script.main() == 0
        assert seen["execute"] is execute

    def test_dry_run_and_execute_together_are_rejected(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["backfill_update_frequency", "--dry-run", "--execute"])

        with pytest.raises(SystemExit):
            backfill_script.main()


class _FakeClient:
    def __init__(self, db: FakeDatabase):
        self._db = db

    def __getitem__(self, _name: str) -> FakeDatabase:
        return self._db

    def close(self) -> None:
        return None


class TestRun:
    @pytest.mark.asyncio
    async def test_the_run_refuses_while_the_rollup_kill_switch_is_off(self, monkeypatch, capsys):
        monkeypatch.setattr(backfill_script.settings, "UPDATE_FREQUENCY_ROLLUP_ENABLED", False)

        assert await run(_args(execute=True)) == 2
        assert "REFUSED" in capsys.readouterr().err

    @pytest.mark.asyncio
    async def test_a_completed_run_exits_zero(self, monkeypatch, write_order):
        db = FakeDatabase()
        db.name = "testdb"
        await _seed_history(db, count=3)
        monkeypatch.setattr(backfill_script, "AsyncIOMotorClient", lambda _url: _FakeClient(db))

        assert await run(_args(execute=True)) == 0
        assert write_order == ["s1", "s2", "s3"]

    @pytest.mark.asyncio
    async def test_since_days_reaches_the_enumeration(self, monkeypatch, write_order):
        db = FakeDatabase()
        db.name = "testdb"
        await _seed_scan(db, "old", _days_ago(200), {"requests": "1.0.0"})
        await _seed_history(db, count=2)
        monkeypatch.setattr(backfill_script, "AsyncIOMotorClient", lambda _url: _FakeClient(db))

        assert await run(_args(execute=True, since_days=90)) == 0
        assert write_order == ["s1", "s2"]

    @pytest.mark.asyncio
    async def test_a_failing_query_exits_one(self, monkeypatch, capsys):
        db = FakeDatabase()
        db.name = "testdb"
        monkeypatch.setattr(backfill_script, "AsyncIOMotorClient", lambda _url: _FakeClient(db))

        async def _explode(*_args: Any, **_kwargs: Any):
            raise RuntimeError("no route to mongod")

        monkeypatch.setattr(backfill_script, "find_chains", _explode)

        assert await run(_args(execute=True)) == 1
        assert "no route to mongod" in capsys.readouterr().err


def _args(**overrides: Any):
    import argparse

    defaults = {
        "execute": False,
        "since_days": 0,
        "project_id": None,
        "concurrency": 1,
        "sleep_ms": 0,
        "batch_size": 500,
    }
    return argparse.Namespace(**(defaults | overrides))
