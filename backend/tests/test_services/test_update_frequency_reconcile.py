"""Tests for the nightly reconcile of the update-frequency delta ledger."""

import logging
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.core import housekeeping
from app.core.config import settings
from app.core.metrics import update_frequency_reconcile_drift_total
from app.repositories.distributed_locks import DistributedLocksRepository
from app.repositories.update_frequency import ScanUpdateDeltaRepository
from app.services import update_frequency_reconcile as reconcile_module
from app.services import update_frequency_rollup as rollup_module
from app.services.update_frequency_reconcile import (
    _LOCK_NAME,
    _LOCK_TTL_SECONDS,
    _MAX_REPAIRS,
    _REPAIR_PAUSE_SECONDS,
    ReconcileReport,
    run_update_frequency_reconcile,
)
from app.services.update_frequency_fold import select_window
from app.services.update_frequency_rollup import record_scan_update_delta
from tests.mocks.fake_mongo import FakeDatabase

PROJECT = "proj-1"
BRANCH = "main"
# Relative to now: the reconcile only looks at a rolling window, so a fixed date would
# quietly walk out of scope.
T0 = (datetime.now(tz=timezone.utc) - timedelta(days=10)).replace(microsecond=0)


def _at(hours: int) -> datetime:
    return T0 + timedelta(hours=hours)


def _dep(scan_id: str, name: str, version: str) -> dict[str, Any]:
    return {
        "_id": f"{scan_id}:{name}",
        "scan_id": scan_id,
        "project_id": PROJECT,
        "name": name,
        "version": version,
        "type": "library",
        "purl": f"pkg:pypi/{name}@{version}",
    }


async def _seed_project(db: FakeDatabase, project_id: str = PROJECT) -> None:
    await db.projects.insert_one({"_id": project_id, "name": project_id, "default_branch": BRANCH})


async def _seed_scan(
    db: FakeDatabase,
    scan_id: str,
    created_at: Any,
    deps: list[dict[str, Any]],
    *,
    outdated: tuple[str, ...] | None = None,
    status: str = "completed",
    is_rescan: bool = False,
    branch: str | None = BRANCH,
    project_id: str = PROJECT,
) -> None:
    doc: dict[str, Any] = {
        "_id": scan_id,
        "project_id": project_id,
        "created_at": created_at,
        "commit_hash": f"commit-{scan_id}",
        "status": status,
        "is_rescan": is_rescan,
    }
    if branch is not None:
        doc["branch"] = branch
    await db.scans.insert_one(doc)
    for dep in deps:
        await db.dependencies.insert_one({**dep, "project_id": project_id})
    if outdated is not None:
        await db.analysis_results.insert_one(
            {
                "_id": f"{scan_id}:outdated",
                "scan_id": scan_id,
                "analyzer_name": "outdated_packages",
                "result": {"outdated_dependencies": [{"component": name} for name in outdated]},
            }
        )


async def _seed_chain(db: FakeDatabase, versions: dict[str, str], *, record: bool = True) -> None:
    """One scan per entry, each carrying a single package at the given version."""
    for index, (scan_id, version) in enumerate(versions.items()):
        await _seed_scan(db, scan_id, _at(index), [_dep(scan_id, "requests", version)], outdated=("requests",))
    if record:
        for scan_id in versions:
            await record_scan_update_delta(db, scan_id)


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Scan ids handed to the writer, in the order the reconcile handed them over."""
    calls: list[str] = []

    async def _record(db: Any, scan_id: str) -> None:
        calls.append(scan_id)
        await record_scan_update_delta(db, scan_id)

    monkeypatch.setattr(reconcile_module, "record_scan_update_delta", _record)
    return calls


@pytest.fixture(autouse=True)
def _no_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reconcile_module, "_REPAIR_PAUSE_SECONDS", 0)


def _metric(kind: str, outcome: str) -> float:
    return update_frequency_reconcile_drift_total.labels(kind=kind, outcome=outcome)._value.get()


async def _delta(db: FakeDatabase, scan_id: str) -> dict[str, Any] | None:
    return await db.scan_update_deltas.find_one({"_id": scan_id})


async def _run_with_probe(db: FakeDatabase, monkeypatch: pytest.MonkeyPatch, probe: Any) -> Any:
    """Run the reconcile with ``probe`` called while the run holds the lock."""
    real_reconcile = reconcile_module._reconcile

    async def _hooked(inner_db: Any) -> Any:
        await probe(inner_db)
        return await real_reconcile(inner_db)

    monkeypatch.setattr(reconcile_module, "_reconcile", _hooked)
    return await run_update_frequency_reconcile(db)


class TestCleanLedger:
    @pytest.mark.asyncio
    async def test_a_ledger_in_step_repairs_nothing(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0", "s3": "2.0.0"})
        before = {doc["_id"]: doc["computed_at"] for doc in await db.scan_update_deltas.find({}).to_list(None)}

        report = await run_update_frequency_reconcile(db)

        assert report == ReconcileReport(chains=1)
        assert spy == []
        after = {doc["_id"]: doc["computed_at"] for doc in await db.scan_update_deltas.find({}).to_list(None)}
        assert after == before

    @pytest.mark.asyncio
    async def test_a_clean_run_says_so_without_a_warning(self, caplog: pytest.LogCaptureFixture):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"})

        with caplog.at_level(logging.INFO, logger=reconcile_module.__name__):
            await run_update_frequency_reconcile(db)

        assert "1 chain(s) in step" in caplog.text
        assert [record for record in caplog.records if record.levelno >= logging.WARNING] == []

    @pytest.mark.asyncio
    async def test_two_scans_of_one_commit_each_owe_a_delta(self, spy: list[str]):
        """The scan census must not collapse a commit's scans the way the read path does."""
        db = FakeDatabase()
        await _seed_project(db)
        for index, scan_id in enumerate(("s1", "s2")):
            await _seed_scan(db, scan_id, _at(index), [_dep(scan_id, "requests", "1.0.0")])
            await db.scans.update_one({"_id": scan_id}, {"$set": {"commit_hash": "same-commit"}})
            await record_scan_update_delta(db, scan_id)

        report = await run_update_frequency_reconcile(db)

        assert report == ReconcileReport(chains=1)
        assert spy == []


class TestMissingDelta:
    @pytest.mark.asyncio
    async def test_a_scan_without_a_delta_is_derived(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"})
        # A write path that inserts a scan without calling the writer.
        await _seed_scan(db, "s3", _at(2), [_dep("s3", "requests", "2.0.0")], outdated=())

        report = await run_update_frequency_reconcile(db)

        assert spy == ["s3"]
        assert report.resolved["missing"] == 1
        assert report.drifted_chains == 1
        doc = await _delta(db, "s3")
        assert doc is not None
        assert doc["prev_scan_id"] == "s2"
        assert doc["updates"]["major"] == 1
        assert doc["outdated_resolved"] == ["requests"]


class TestStaleSchema:
    @pytest.mark.asyncio
    async def test_a_delta_from_an_older_schema_is_derived_again(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"})
        await db.scan_update_deltas.update_one({"_id": "s2"}, {"$set": {"schema_version": 0, "updates.minor": 99}})

        report = await run_update_frequency_reconcile(db)

        assert spy == ["s2"]
        assert report.resolved == {"stale": 1}
        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["schema_version"] == 1
        assert doc["updates"]["minor"] == 1

    @pytest.mark.asyncio
    async def test_a_delta_that_names_no_schema_version_is_derived_again(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0"})
        await db.scan_update_deltas.update_one({"_id": "s1"}, {"$unset": {"schema_version": ""}})

        report = await run_update_frequency_reconcile(db)

        assert spy == ["s1"]
        assert report.resolved == {"stale": 1}

    @pytest.mark.asyncio
    async def test_a_recorded_failure_is_left_alone(self, spy: list[str]):
        """The writer stored that outcome on purpose."""
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0"})
        await db.scan_update_deltas.update_one({"_id": "s1"}, {"$set": {"error": "boom"}})

        report = await run_update_frequency_reconcile(db)

        assert spy == []
        assert report == ReconcileReport(chains=1)


async def _folded_window(db: FakeDatabase) -> list[str]:
    deltas = await db.scan_update_deltas.find({}).to_list(None)
    return [d["_id"] for d in select_window(sorted(deltas, key=lambda d: (d["scan_created_at"], d["_id"])))]


class TestSkipLink:
    """A delta diffed past the comparable scan before it truncates the fold's window there."""

    @pytest.mark.asyncio
    async def test_a_delta_racing_its_predecessor_is_relinked(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"p": "1.0.0", "a": "1.1.0", "b": "1.2.0"}, record=False)
        await record_scan_update_delta(db, "p")
        # b's ingest finds its predecessor before a's delta exists, and a's successor repair
        # runs before b's delta does.
        b_delta, b_outdated = await rollup_module._compute_delta(db, await rollup_module._load_scan(db, "b"))
        await record_scan_update_delta(db, "a")
        await rollup_module._persist(db, b_delta, b_outdated)
        assert await _folded_window(db) == ["b"]
        exported = _metric("relink", "resolved")

        report = await run_update_frequency_reconcile(db)

        assert spy == ["b"]
        assert report.resolved == {"relink": 1}
        assert _metric("relink", "resolved") == exported + 1
        assert await _folded_window(db) == ["p", "a", "b"]

    @pytest.mark.asyncio
    async def test_the_successor_of_a_failed_recompute_is_relinked_past_it(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s0": "1.0.0", "s1": "1.1.0", "s2": "1.2.0", "s3": "1.3.0"})
        with patch.object(rollup_module, "load_scan_deps", AsyncMock(side_effect=RuntimeError("mongo hiccup"))):
            await record_scan_update_delta(db, "s1")
        assert await _folded_window(db) == ["s2", "s3"]

        report = await run_update_frequency_reconcile(db)

        assert spy == ["s2"]
        assert report.resolved == {"relink": 1}
        assert (await _delta(db, "s1") or {}).get("error")
        assert await _folded_window(db) == ["s0", "s2", "s3"]

    @pytest.mark.asyncio
    async def test_the_oldest_delta_in_the_window_may_point_before_it(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_scan(db, "s0", T0 - timedelta(days=100), [_dep("s0", "requests", "0.9.0")], outdated=())
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"}, record=False)
        for scan_id in ("s0", "s1", "s2"):
            await record_scan_update_delta(db, scan_id)
        assert (await _delta(db, "s1") or {})["prev_scan_id"] == "s0"

        report = await run_update_frequency_reconcile(db)

        assert report == ReconcileReport(chains=1)
        assert spy == []


class TestOrphanDelta:
    @pytest.mark.asyncio
    async def test_a_delta_whose_scan_is_gone_is_removed(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"})
        assert await db.scan_outdated_sets.find_one({"_id": "s1"}) is not None
        await db.scans.delete_one({"_id": "s1"})

        report = await run_update_frequency_reconcile(db)

        assert report.resolved["orphan"] == 1
        assert await _delta(db, "s1") is None
        assert await db.scan_outdated_sets.find_one({"_id": "s1"}) is None

    @pytest.mark.asyncio
    async def test_the_successor_of_a_removed_delta_is_derived_again(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"})
        assert (await _delta(db, "s2") or {})["prev_scan_id"] == "s1"
        await db.scans.delete_one({"_id": "s1"})

        report = await run_update_frequency_reconcile(db)

        assert spy == ["s2"]
        assert report.resolved["dependent"] == 1
        doc = await _delta(db, "s2")
        assert doc is not None
        assert doc["prev_scan_id"] is None
        assert doc["is_baseline"] is True

    @pytest.mark.asyncio
    async def test_a_delta_of_a_scan_that_lost_its_usable_status_is_removed(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0"})
        await db.scans.update_one({"_id": "s1"}, {"$set": {"status": "failed"}})

        report = await run_update_frequency_reconcile(db)

        assert report.resolved == {"orphan": 1}
        assert await _delta(db, "s1") is None

    @pytest.mark.asyncio
    async def test_a_whole_chain_of_orphans_is_removed(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"})
        await db.scans.delete_many({})

        report = await run_update_frequency_reconcile(db)

        assert report.resolved["orphan"] == 2
        assert await db.scan_update_deltas.find({}).to_list(None) == []
        assert spy == []

    @pytest.mark.asyncio
    async def test_a_delta_that_moved_to_another_chain_survives_the_delete(
        self, monkeypatch: pytest.MonkeyPatch, spy: list[str]
    ):
        """The orphan verdict is made against a census. A re-ingest that rewrites the delta's
        branch in between has already re-derived it under the new chain, so this run's verdict no
        longer describes the document it is about to delete."""
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"})
        await db.scans.delete_one({"_id": "s1"})

        real_ledger_census = ScanUpdateDeltaRepository.window_ledger_by_branch

        async def _census_then_reingest(self: Any, *args: Any, **kwargs: Any) -> Any:
            result = await real_ledger_census(self, *args, **kwargs)
            await db.scan_update_deltas.update_one({"_id": "s1"}, {"$set": {"branch": "release-1.2"}})
            return result

        monkeypatch.setattr(ScanUpdateDeltaRepository, "window_ledger_by_branch", _census_then_reingest)

        await run_update_frequency_reconcile(db)

        assert await _delta(db, "s1") is not None


class TestConcurrentIngest:
    @pytest.mark.asyncio
    async def test_a_scan_finishing_between_the_two_censuses_keeps_its_delta(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Whichever census runs second decides how the gap reads. Scans-second makes the
        # newcomer a scan the ledger owes a delta for; ledger-second would make its fresh
        # delta look unowned, and the repair for that deletes it.
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"})

        # Seed after whichever census runs first, so the test pins the ORDER rather than
        # the hook: scans-first would leave the newcomer's delta unowned and delete it.
        real_scan_census = reconcile_module.window_scan_ids_by_branch
        real_ledger_census = ScanUpdateDeltaRepository.window_ledger_by_branch
        arrived: list[int] = []

        async def _ingest_once() -> None:
            if arrived:
                return
            arrived.append(1)
            await _seed_scan(db, "s3", _at(2), [_dep("s3", "requests", "2.0.0")], outdated=("requests",))
            await record_scan_update_delta(db, "s3")

        async def _scan_census(*args: Any, **kwargs: Any) -> Any:
            result = await real_scan_census(*args, **kwargs)
            await _ingest_once()
            return result

        async def _ledger_census(self: Any, *args: Any, **kwargs: Any) -> Any:
            result = await real_ledger_census(self, *args, **kwargs)
            await _ingest_once()
            return result

        monkeypatch.setattr(reconcile_module, "window_scan_ids_by_branch", _scan_census)
        monkeypatch.setattr(ScanUpdateDeltaRepository, "window_ledger_by_branch", _ledger_census)

        report = await run_update_frequency_reconcile(db)

        assert report is not None
        assert report.resolved["orphan"] == 0
        assert await db.scan_update_deltas.find_one({"_id": "s3"}) is not None


class TestRepairOrder:
    @pytest.mark.asyncio
    async def test_a_chain_is_derived_oldest_first(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        # Inserted newest first: the census hands back whatever order the group pushed,
        # so nothing but the repair sort can put the oldest scan in front.
        for hours, scan_id in reversed(list(enumerate(("s1", "s2", "s3")))):
            await _seed_scan(db, scan_id, _at(hours), [_dep(scan_id, "requests", "1.0.0")])

        await run_update_frequency_reconcile(db)

        assert spy == ["s1", "s2", "s3"]

    @pytest.mark.asyncio
    async def test_a_successor_repair_takes_its_place_in_the_age_order(self, spy: list[str]):
        """A dependent is found after the census, so only the repair sort can place it."""
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"})
        await _seed_scan(db, "s3", _at(2), [_dep("s3", "requests", "2.0.0")])
        await db.scans.delete_one({"_id": "s1"})

        report = await run_update_frequency_reconcile(db)

        assert spy == ["s2", "s3"]
        assert report.resolved == {"orphan": 1, "dependent": 1, "missing": 1}

    @pytest.mark.asyncio
    async def test_scans_of_one_millisecond_are_ordered_by_id(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        for scan_id in ("s2", "s1"):
            await _seed_scan(db, scan_id, _at(0), [_dep(scan_id, "requests", "1.0.0")])

        await run_update_frequency_reconcile(db)

        assert spy == ["s1", "s2"]

    @pytest.mark.asyncio
    async def test_the_writer_gets_the_pause_between_repairs(self, monkeypatch: pytest.MonkeyPatch, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"}, record=False)
        monkeypatch.setattr(reconcile_module, "_REPAIR_PAUSE_SECONDS", 0.25)
        pauses: list[float] = []

        async def _sleep(seconds: float) -> None:
            pauses.append(seconds)

        # Only this module's name for asyncio, so the loop's own sleeps stay out of the record.
        monkeypatch.setattr(reconcile_module, "asyncio", SimpleNamespace(sleep=_sleep))

        await run_update_frequency_reconcile(db)

        assert pauses == [0.25, 0.25]


class TestCaps:
    @pytest.mark.asyncio
    async def test_the_repair_cap_defers_the_rest_and_says_how_much(
        self, monkeypatch: pytest.MonkeyPatch, spy: list[str], caplog: pytest.LogCaptureFixture
    ):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0", "s3": "2.0.0"}, record=False)
        monkeypatch.setattr(reconcile_module, "_MAX_REPAIRS", 1)

        with caplog.at_level(logging.WARNING, logger=reconcile_module.__name__):
            report = await run_update_frequency_reconcile(db)

        assert spy == ["s1"]
        assert report.resolved == {"missing": 1}
        assert report.deferred == {"missing": 2}
        # The operator contract is the deferred count, not the wording of the other four counters.
        assert "left 2 missing" in caplog.text

    @pytest.mark.asyncio
    async def test_a_deferred_repair_is_visible_in_prometheus(self, monkeypatch: pytest.MonkeyPatch, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"}, record=False)
        monkeypatch.setattr(reconcile_module, "_MAX_REPAIRS", 1)
        before = _metric("missing", "deferred")

        await run_update_frequency_reconcile(db)

        assert _metric("missing", "deferred") == before + 1

    @pytest.mark.asyncio
    async def test_the_orphan_cap_leaves_the_rest_in_place(self, monkeypatch: pytest.MonkeyPatch, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"})
        await db.scans.delete_many({})
        monkeypatch.setattr(reconcile_module, "_MAX_ORPHAN_DELETES", 1)

        report = await run_update_frequency_reconcile(db)

        assert report.resolved == {"orphan": 1}
        assert report.deferred == {"orphan": 1}
        assert len(await db.scan_update_deltas.find({}).to_list(None)) == 1
        # The delta left behind is the deleted one's successor, but its own scan is gone
        # too: handing it to the writer would count a repair the writer cannot make.
        assert spy == []

    @pytest.mark.asyncio
    async def test_an_orphan_delete_does_not_spend_the_repair_budget(
        self, monkeypatch: pytest.MonkeyPatch, spy: list[str]
    ):
        """The repair budget bounds re-derivations, which re-read two dependency sets each; a bulk
        delete costs nothing like that, so a sweep of orphans must not stall the repairs behind it."""
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0"})
        await db.scans.delete_one({"_id": "s1"})
        monkeypatch.setattr(reconcile_module, "_MAX_REPAIRS", 1)

        report = await run_update_frequency_reconcile(db)

        assert spy == ["s2"]
        assert report.resolved == {"orphan": 1, "dependent": 1}
        assert report.deferred == {}

    @pytest.mark.asyncio
    async def test_the_orphan_cap_is_spent_across_chains(self, monkeypatch: pytest.MonkeyPatch, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_project(db, "proj-2")
        await _seed_chain(db, {"s1": "1.0.0"})
        await _seed_scan(db, "o1", _at(0), [_dep("o1", "requests", "1.0.0")], project_id="proj-2")
        await record_scan_update_delta(db, "o1")
        await db.scans.delete_many({})
        monkeypatch.setattr(reconcile_module, "_MAX_ORPHAN_DELETES", 1)
        before = _metric("orphan", "resolved"), _metric("orphan", "deferred")

        report = await run_update_frequency_reconcile(db)

        assert report.resolved == {"orphan": 1}
        assert report.deferred == {"orphan": 1}
        assert await _delta(db, "s1") is None
        assert await _delta(db, "o1") is not None
        assert (_metric("orphan", "resolved"), _metric("orphan", "deferred")) == (before[0] + 1, before[1] + 1)


class TestDriftMetric:
    @pytest.mark.asyncio
    async def test_every_kind_of_drift_reaches_prometheus(self, spy: list[str]):
        """A kind the warning line counts but the metric drops would understate the drift."""
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0", "s2": "1.1.0", "s3": "2.0.0"})
        await db.scan_update_deltas.update_one({"_id": "s3"}, {"$set": {"schema_version": 0}})
        await _seed_scan(db, "s4", _at(3), [_dep("s4", "requests", "2.1.0")])
        await db.scans.delete_one({"_id": "s1"})
        kinds = ("missing", "stale", "orphan", "dependent")
        before = {kind: _metric(kind, "resolved") for kind in kinds}

        report = await run_update_frequency_reconcile(db)

        assert report.resolved == {"missing": 1, "stale": 1, "orphan": 1, "dependent": 1}
        assert {kind: _metric(kind, "resolved") for kind in kinds} == {
            kind: value + 1 for kind, value in before.items()
        }


class TestLock:
    @pytest.mark.asyncio
    async def test_a_second_pod_finds_the_lock_taken(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0"}, record=False)
        await db.distributed_locks.insert_one(
            {
                "_id": _LOCK_NAME,
                "holder": "update-frequency-reconcile-other-pod",
                "acquired_at": datetime.now(timezone.utc),
                "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
            }
        )

        assert await run_update_frequency_reconcile(db) is None
        assert spy == []
        assert await _delta(db, "s1") is None

    @pytest.mark.asyncio
    async def test_a_second_pod_is_turned_away_while_the_run_holds_the_lock(
        self, monkeypatch: pytest.MonkeyPatch, spy: list[str]
    ):
        """Both takes go through the repository, so the TTL the run asks for has to hold."""
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0"}, record=False)
        contender: list[bool] = []

        async def _probe(inner_db: Any) -> None:
            locks = DistributedLocksRepository(inner_db)
            taken = await locks.acquire_lock(_LOCK_NAME, "reconcile-second-pod", ttl_seconds=_LOCK_TTL_SECONDS)
            contender.append(taken)

        await _run_with_probe(db, monkeypatch, _probe)

        assert contender == [False]
        assert spy == ["s1"]

    @pytest.mark.asyncio
    async def test_the_lock_outlives_a_run_that_spends_its_whole_repair_budget(self, monkeypatch: pytest.MonkeyPatch):
        db = FakeDatabase()
        await _seed_project(db)
        held: list[dict[str, Any]] = []

        async def _probe(inner_db: Any) -> None:
            held.append(await inner_db.distributed_locks.find_one({"_id": _LOCK_NAME}))

        await _run_with_probe(db, monkeypatch, _probe)

        # The shipped pause, not the zero the fixture patches in; the writer's own work
        # between the pauses comes on top of this floor.
        budget = timedelta(seconds=_MAX_REPAIRS * _REPAIR_PAUSE_SECONDS)
        assert held[0]["expires_at"] - held[0]["acquired_at"] >= budget

    @pytest.mark.asyncio
    async def test_pods_reaching_the_quiet_hour_after_a_run_find_the_night_done(
        self, monkeypatch: pytest.MonkeyPatch, spy: list[str]
    ):
        """Every pod checks once in the quiet hour, so a capped run must not repeat on each of them."""
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {f"s{i}": f"1.0.{i}" for i in range(6)}, record=False)
        monkeypatch.setattr(reconcile_module, "_MAX_REPAIRS", 2)

        reports = [await run_update_frequency_reconcile(db) for _pod in range(3)]

        assert reports[1:] == [None, None]
        assert spy == ["s0", "s1"]
        held = await db.distributed_locks.find_one({"_id": _LOCK_NAME})
        assert held["expires_at"] - held["acquired_at"] > timedelta(hours=1)


class TestScope:
    @pytest.mark.asyncio
    async def test_the_writer_being_off_stops_the_run_before_the_lock(
        self, monkeypatch: pytest.MonkeyPatch, spy: list[str]
    ):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0"}, record=False)
        monkeypatch.setattr(settings, "UPDATE_FREQUENCY_ROLLUP_ENABLED", False)

        assert await run_update_frequency_reconcile(db) is None
        assert spy == []
        assert await db.distributed_locks.find({}).to_list(None) == []

    @pytest.mark.asyncio
    async def test_a_rescan_owes_no_delta(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0"})
        await _seed_scan(db, "r1", _at(1), [_dep("r1", "requests", "1.1.0")], is_rescan=True)

        report = await run_update_frequency_reconcile(db)

        assert spy == []
        assert report == ReconcileReport(chains=1)

    @pytest.mark.asyncio
    async def test_a_pending_scan_owes_no_delta(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0"})
        await _seed_scan(db, "p1", _at(1), [], status="pending")

        report = await run_update_frequency_reconcile(db)

        assert spy == []
        assert report == ReconcileReport(chains=1)

    @pytest.mark.asyncio
    async def test_a_scan_that_names_no_branch_owes_no_delta(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0"})
        await _seed_scan(db, "n1", _at(1), [_dep("n1", "requests", "1.1.0")], branch=None)

        report = await run_update_frequency_reconcile(db)

        assert spy == []
        assert report == ReconcileReport(chains=1)

    @pytest.mark.asyncio
    async def test_a_scan_whose_date_is_text_owes_no_delta(self, spy: list[str]):
        """A restore can write created_at as an ISO string; the writer cannot place it either."""
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0"})
        await _seed_scan(db, "t1", "2026-06-01T14:00:00Z", [_dep("t1", "requests", "1.1.0")])

        report = await run_update_frequency_reconcile(db)

        assert spy == []
        assert report == ReconcileReport(chains=1)

    @pytest.mark.asyncio
    async def test_scans_older_than_the_window_are_out_of_scope(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_chain(db, {"s1": "1.0.0"})
        old = datetime.now(tz=timezone.utc) - timedelta(days=200)
        await _seed_scan(db, "old", old, [_dep("old", "requests", "0.9.0")])

        report = await run_update_frequency_reconcile(db)

        assert spy == []
        assert report == ReconcileReport(chains=1)

    @pytest.mark.asyncio
    async def test_every_project_is_reconciled(self, spy: list[str]):
        db = FakeDatabase()
        await _seed_project(db)
        await _seed_project(db, "proj-2")
        await _seed_chain(db, {"s1": "1.0.0"}, record=False)
        await _seed_scan(db, "o1", _at(0), [_dep("o1", "requests", "1.0.0")], project_id="proj-2")

        report = await run_update_frequency_reconcile(db)

        assert sorted(spy) == ["o1", "s1"]
        assert report.chains == 2
        assert report.drifted_chains == 2


class TestHousekeepingWiring:
    @pytest.mark.asyncio
    async def test_a_failing_reconcile_does_not_stop_housekeeping(self, monkeypatch: pytest.MonkeyPatch):
        db = FakeDatabase()

        async def _get_database() -> FakeDatabase:
            return db

        reached: list[str] = []

        async def _boom(_db: Any) -> None:
            reached.append("boom")
            raise RuntimeError("mongod unreachable")

        monkeypatch.setattr(settings, "UPDATE_FREQUENCY_RECONCILE_ENABLED", True)
        monkeypatch.setattr(housekeeping, "get_database", _get_database)
        monkeypatch.setattr(housekeeping, "run_update_frequency_reconcile", _boom)

        await housekeeping.reconcile_update_frequency_ledger()

        assert reached == ["boom"]
