"""Queued waiver changes and expiries: one run at a time recalculates what they reach, and a change stays queued
until its pass is done."""

from datetime import datetime, timedelta, timezone

import pytest

import app.services.stats as stats_module
from app.models.waiver import Waiver
from app.repositories.distributed_locks import DistributedLocksRepository
from app.services.stats import request_waiver_recalc, run_waiver_recalc
from app.services.waivers.apply import waiver_fingerprint
from tests.mocks.fake_mongo import FakeDatabase

pytestmark = pytest.mark.asyncio

_GPL = "LIC-GPL-3.0"
_NOW = datetime.now(timezone.utc)


async def _seed_project(db: FakeDatabase, project_id: str, finding_id: str, waived: bool = False) -> None:
    scan_id = f"scan-{project_id}"
    await db.projects.insert_one({"_id": project_id, "name": project_id, "latest_scan_id": scan_id})
    await db.scans.insert_one({"_id": scan_id, "project_id": project_id, "status": "completed"})
    await db.findings.insert_one(
        {
            "_id": f"f-{project_id}",
            "scan_id": scan_id,
            "type": "license",
            "component": "lib",
            "finding_id": finding_id,
            "waived": waived,
        }
    )


def _gpl_waiver(**fields) -> Waiver:
    return Waiver(
        **{
            "finding_type": "license",
            "finding_id": _GPL,
            "package_name": "lib",
            "reason": "r",
            "created_by": "admin",
            **fields,
        }
    )


async def _store(db: FakeDatabase, waiver: Waiver) -> Waiver:
    await db.waivers.insert_one(waiver.model_dump(by_alias=True))
    return waiver


def _record_recalcs(monkeypatch) -> list[str]:
    visited: list[str] = []
    original = stats_module.recalculate_project_stats

    async def recording(project_id, db, reach=None, **kwargs):
        visited.append(project_id)
        return await original(project_id, db, reach, **kwargs)

    monkeypatch.setattr(stats_module, "recalculate_project_stats", recording)
    return visited


async def _queued(db: FakeDatabase) -> int:
    return await db.waiver_recalc.count_documents({"waiver": {"$exists": True}})


async def test_only_the_projects_holding_a_finding_a_global_waiver_matches_are_recalculated():
    db = FakeDatabase()
    await _seed_project(db, "p-gpl", _GPL)
    await _seed_project(db, "p-mit", "LIC-MIT")
    await request_waiver_recalc(db, await _store(db, _gpl_waiver()))
    await run_waiver_recalc(db)

    assert "stats" in await db.scans.find_one({"_id": "scan-p-gpl"})
    assert "stats" not in await db.scans.find_one({"_id": "scan-p-mit"})
    assert (await db.findings.find_one({"_id": "f-p-gpl"}))["waived"] is True
    assert await _queued(db) == 0


async def test_a_project_waivers_change_recalculates_its_project_whatever_it_holds(monkeypatch):
    db = FakeDatabase()
    await _seed_project(db, "p-own", "LIC-MIT")
    await _seed_project(db, "p-other", _GPL)
    visited = _record_recalcs(monkeypatch)

    await request_waiver_recalc(db, _gpl_waiver(project_id="p-own"))
    await run_waiver_recalc(db)

    assert visited == ["p-own"]


async def test_the_scan_a_waiver_was_written_from_is_restamped_though_no_branch_tip():
    db = FakeDatabase()
    await db.projects.insert_one({"_id": "p-own", "name": "p-own", "default_branch": "main"})
    await db.scans.insert_one(
        {"_id": "scan-head", "project_id": "p-own", "branch": "main", "status": "completed", "created_at": _NOW}
    )
    await db.scans.insert_one(
        {
            "_id": "scan-stale",
            "project_id": "p-own",
            "branch": "old-feature",
            "status": "completed",
            "created_at": _NOW - timedelta(days=400),
        }
    )
    await db.findings.insert_one(
        {"_id": "f-stale", "scan_id": "scan-stale", "type": "license", "component": "lib", "finding_id": _GPL}
    )

    await request_waiver_recalc(db, await _store(db, _gpl_waiver(project_id="p-own")), restamp=["scan-stale"])
    await run_waiver_recalc(db)

    assert (await db.findings.find_one({"_id": "f-stale"}))["waived"] is True


async def test_changes_queued_together_share_one_pass_over_the_projects(monkeypatch):
    db = FakeDatabase()
    await _seed_project(db, "p-1", _GPL)
    await _seed_project(db, "p-2", _GPL)
    visited = _record_recalcs(monkeypatch)

    for waiver in (_gpl_waiver(), _gpl_waiver(reason="second"), _gpl_waiver(project_id="p-1")):
        await request_waiver_recalc(db, waiver)
    await run_waiver_recalc(db)

    assert sorted(visited) == ["p-1", "p-2"]


async def test_one_failing_project_does_not_stop_the_recalculation_of_the_others(monkeypatch):
    db = FakeDatabase()
    for project_id in ("p-1", "p-broken", "p-3"):
        await _seed_project(db, project_id, _GPL)
    visited: list[str] = []

    async def recalculate(project_id, database, reach=None, **kwargs):
        visited.append(project_id)
        if project_id == "p-broken":
            raise RuntimeError("legacy document")

    monkeypatch.setattr(stats_module, "recalculate_project_stats", recalculate)

    await request_waiver_recalc(db, _gpl_waiver())
    await run_waiver_recalc(db)

    assert visited == ["p-1", "p-broken", "p-3"]
    assert await _queued(db) == 0


async def test_a_run_that_lost_its_lock_partway_leaves_the_change_queued_for_the_next(monkeypatch):
    db = FakeDatabase()
    await _seed_project(db, "p-1", _GPL)
    await request_waiver_recalc(db, await _store(db, _gpl_waiver()))

    async def taken_over(self, lock_name, holder_id, ttl_seconds=30):
        return False

    with monkeypatch.context() as patched:
        patched.setattr(DistributedLocksRepository, "renew_lock", taken_over)
        await run_waiver_recalc(db)
    assert await _queued(db) == 1

    await run_waiver_recalc(db)

    assert await _queued(db) == 0
    assert (await db.findings.find_one({"_id": "f-p-1"}))["waived"] is True


async def test_a_run_finding_the_lock_taken_leaves_the_queue_to_its_holder(monkeypatch):
    db = FakeDatabase()
    await _seed_project(db, "p-1", _GPL)
    await request_waiver_recalc(db, _gpl_waiver())
    await DistributedLocksRepository(db).acquire_lock("waiver_recalc", "another-pod", 300)
    visited = _record_recalcs(monkeypatch)

    await run_waiver_recalc(db)

    assert visited == []
    assert await _queued(db) == 1


async def test_a_queued_change_that_no_longer_loads_is_dropped_rather_than_blocking_the_queue(monkeypatch):
    db = FakeDatabase()
    await _seed_project(db, "p-1", _GPL)
    await db.waiver_recalc.insert_one({"waiver": {"_id": "w-null", "project_id": "p-1", "status": None}})
    await request_waiver_recalc(db, await _store(db, _gpl_waiver()))

    await run_waiver_recalc(db)

    assert await _queued(db) == 0
    assert (await db.findings.find_one({"_id": "f-p-1"}))["waived"] is True


async def test_the_projects_last_waiver_expiring_clears_what_it_waived():
    db = FakeDatabase()
    await _seed_project(db, "p-1", _GPL, waived=True)
    await db.waiver_recalc.insert_one({"_id": "expiry_sweep", "swept_until": _NOW - timedelta(hours=1)})
    await _store(db, _gpl_waiver(project_id="p-1", expiration_date=_NOW - timedelta(minutes=5)))

    await run_waiver_recalc(db)

    assert (await db.findings.find_one({"_id": "f-p-1"}))["waived"] is False


async def test_a_waiver_that_expired_before_the_last_sweep_is_not_recalculated_again(monkeypatch):
    db = FakeDatabase()
    await _seed_project(db, "p-1", _GPL)
    await db.waiver_recalc.insert_one({"_id": "expiry_sweep", "swept_until": _NOW - timedelta(minutes=5)})
    await _store(db, _gpl_waiver(project_id="p-1", expiration_date=_NOW - timedelta(hours=1)))
    visited = _record_recalcs(monkeypatch)

    await run_waiver_recalc(db)

    assert visited == []


async def test_the_first_sweep_takes_every_waiver_that_ever_expired():
    """No watermark yet: flags an expiry left behind before the sweep existed are cleared once."""
    db = FakeDatabase()
    await _seed_project(db, "p-1", _GPL, waived=True)
    await _store(db, _gpl_waiver(project_id="p-1", expiration_date=_NOW - timedelta(days=400)))

    await run_waiver_recalc(db)

    assert (await db.findings.find_one({"_id": "f-p-1"}))["waived"] is False
    assert (await db.waiver_recalc.find_one({"_id": "expiry_sweep"}))["swept_until"] is not None


async def test_the_operator_restamp_entry_clears_flags_stamped_under_older_rules():
    db = FakeDatabase()
    await _seed_project(db, "p-1", _GPL, waived=True)
    await db.waiver_recalc.insert_one(
        {"waiver": {"_id": "restamp-p-1", "project_id": "p-1", "reason": "post-deploy restamp", "created_by": "op"}}
    )

    await run_waiver_recalc(db)

    assert (await db.findings.find_one({"_id": "f-p-1"}))["waived"] is False
    assert (await db.scans.find_one({"_id": "scan-p-1"}))["waiver_fingerprint"] == waiver_fingerprint([])
