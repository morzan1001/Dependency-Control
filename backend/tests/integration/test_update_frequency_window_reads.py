from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from prometheus_client import REGISTRY

from app.core.constants import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_COMPLETED_WITH_ERRORS,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
)
from app.models.update_frequency import UPDATE_DELTA_SCHEMA_VERSION
from app.repositories.scans import ScanRepository
from app.repositories.update_frequency import (
    _WINDOW_PROJECT_BATCH,
    BranchWindowActivity,
    LedgerEntry,
    ScanUpdateDeltaRepository,
    window_scan_ids_by_branch,
    window_scans_by_branch,
)
from app.services.update_frequency_reconcile import ReconcileReport, run_update_frequency_reconcile

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]

T0 = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
SINCE = T0 - timedelta(days=1)
V = UPDATE_DELTA_SCHEMA_VERSION
# Splits p-a and p-b into different batches, so a batch boundary cannot hide a lost chain.
SCOPE = ["p-a", *(f"p-filler-{i:03d}" for i in range(_WINDOW_PROJECT_BATCH)), "p-b", "p-c"]


def _at(minutes: int) -> datetime:
    return T0 + timedelta(minutes=minutes)


async def _seed_ledger(db: Any) -> None:
    rows: list[dict[str, Any]] = [
        {"_id": "a1", "project_id": "p-a", "branch": "main", "scan_created_at": _at(0), "schema_version": V,
         "prev_scan_id": None, "prev_created_at": None, "dep_count": 3, "error": None},
        {"_id": "a2", "project_id": "p-a", "branch": "main", "scan_created_at": _at(10), "schema_version": V,
         "prev_scan_id": "a1", "prev_created_at": _at(0), "dep_count": 0, "error": None},
        {"_id": "a3", "project_id": "p-a", "branch": "main", "scan_created_at": _at(20), "schema_version": V,
         "prev_scan_id": "a1", "prev_created_at": _at(0), "dep_count": 5, "error": "resolver timed out"},
        {"_id": "a4", "project_id": "p-a", "branch": "main", "scan_created_at": _at(30), "schema_version": V - 1,
         "prev_scan_id": "a3", "prev_created_at": _at(20), "dep_count": 4, "error": None},
        {"_id": "a5", "project_id": "p-a", "branch": "main", "scan_created_at": _at(40), "dep_count": 2},
        {"_id": "r1", "project_id": "p-a", "branch": "release/1.x", "scan_created_at": _at(5), "schema_version": V,
         "prev_scan_id": "gone", "prev_created_at": "2026-05-01T00:00:00+00:00", "dep_count": 1, "error": ""},
        {"_id": "u1", "project_id": "p-a", "branch": None, "scan_created_at": _at(1), "dep_count": 1},
        {"_id": "u2", "project_id": "p-a", "branch": "", "scan_created_at": _at(2), "dep_count": 1},
        {"_id": "u3", "project_id": "p-a", "scan_created_at": _at(3), "dep_count": 1},
        {"_id": "u4", "project_id": "p-a", "branch": 7, "scan_created_at": _at(4), "dep_count": 1},
        {"_id": "b0", "project_id": "p-b", "branch": "main", "scan_created_at": SINCE, "schema_version": V,
         "dep_count": 1},
        {"_id": "b1", "project_id": "p-b", "branch": "main", "scan_created_at": _at(1), "schema_version": V,
         "prev_scan_id": "b0", "prev_created_at": SINCE},
        {"_id": "b2", "project_id": "p-b", "branch": "main", "scan_created_at": _at(2), "schema_version": V,
         "prev_scan_id": "b1", "prev_created_at": _at(1), "dep_count": None, "error": None},
        {"_id": "b-old", "project_id": "p-b", "branch": "main", "scan_created_at": SINCE - timedelta(minutes=1),
         "schema_version": V, "dep_count": 1},
        {"_id": "f1", "project_id": "p-b", "branch": "feature", "scan_created_at": _at(3), "schema_version": V + 1,
         "dep_count": 7, "outdated_added": ["flask"], "updates": {"patch": 1}},
        {"_id": "o1", "project_id": "p-out", "branch": "main", "scan_created_at": _at(0), "schema_version": V,
         "dep_count": 1},
    ]  # fmt: skip
    await db.scan_update_deltas.insert_many(rows)


async def _scan(db: Any, scan_id: str, project_id: str, branch: Any, created_at: Any, **fields: Any) -> None:
    doc = {
        "_id": scan_id,
        "project_id": project_id,
        "created_at": created_at,
        "status": SCAN_STATUS_COMPLETED,
        "is_rescan": False,
        "sbom_refs": [{"file_id": f"sbom-{scan_id}"}],
    }
    if branch is not ...:
        doc["branch"] = branch
    await db.scans.insert_one(doc | fields)


async def _seed_scans(db: Any) -> None:
    await _scan(db, "sa1", "p-a", "main", _at(0), commit_hash="c1")
    await _scan(db, "sa2", "p-a", "main", _at(5), commit_hash="c1")
    await _scan(db, "sa3", "p-a", "main", _at(10), commit_hash="c2", status=SCAN_STATUS_COMPLETED_WITH_ERRORS)
    await db.scans.update_one({"_id": "sa3"}, {"$unset": {"sbom_refs": ""}})
    await _scan(db, "sa4", "p-a", "main", _at(15), commit_hash=None)
    await _scan(db, "sa5", "p-a", "main", _at(20), commit_hash="")
    await _scan(db, "sa6", "p-a", "main", _at(25), is_rescan=None)
    await _scan(db, "sa7", "p-a", "main", _at(30), commit_hash=12345)
    await _scan(db, "sa8", "p-a", "main", _at(35), commit_hash="c3", sbom_refs=[])
    await _scan(db, "sa-rescan", "p-a", "main", _at(36), commit_hash="c4", is_rescan=True)
    await _scan(db, "sa-failed", "p-a", "main", _at(37), commit_hash="c5", status=SCAN_STATUS_FAILED)
    await _scan(db, "sa-pending", "p-a", "main", _at(38), commit_hash="c6", status=SCAN_STATUS_PENDING)
    await _scan(db, "sa-old", "p-a", "main", SINCE - timedelta(minutes=1), commit_hash="c-old")
    await _scan(db, "sa-text", "p-a", "main", "2026-06-01T13:00:00+00:00", commit_hash="c-text")
    await _scan(db, "sd1", "p-a", "dev", "2026-06-01T12:00:00+00:00", commit_hash="cd1")
    await _scan(db, "sd2", "p-a", "dev", None, commit_hash="cd2")
    await _scan(db, "sd3", "p-a", "dev", _at(50), commit_hash="cd3")
    await _scan(db, "sl1", "p-a", "legacy", "2026-06-01T12:00:00+00:00", commit_hash="cl1")
    await _scan(db, "sl2", "p-a", "legacy", None, commit_hash="cl2")
    await _scan(db, "su1", "p-a", None, _at(1), commit_hash="cu1")
    await _scan(db, "su2", "p-a", "", _at(2), commit_hash="cu2")
    await _scan(db, "su3", "p-a", ..., _at(3), commit_hash="cu3")
    await _scan(db, "su4", "p-a", 7, _at(4), commit_hash="cu4")
    await _scan(db, "sb1", "p-b", "main", _at(1), commit_hash="cb1")
    await _scan(db, "so1", "p-out", "main", _at(1), commit_hash="co1")


async def test_the_ledger_census_keys_every_named_chain_by_delta(db):
    await _seed_ledger(db)

    chains = await ScanUpdateDeltaRepository(db).window_ledger_by_branch(SCOPE, SINCE)

    assert chains == {
        ("p-a", "main"): {
            "a1": LedgerEntry(V, None, None, _at(0), True),
            "a2": LedgerEntry(V, "a1", _at(0), _at(10), False),
            "a3": LedgerEntry(V, "a1", _at(0), _at(20), False),
            "a4": LedgerEntry(V - 1, "a3", _at(20), _at(30), True),
            "a5": LedgerEntry(None, None, None, _at(40), True),
        },
        ("p-a", "release/1.x"): {"r1": LedgerEntry(V, "gone", None, _at(5), True)},
        ("p-b", "main"): {
            "b0": LedgerEntry(V, None, None, SINCE, True),
            "b1": LedgerEntry(V, "b0", SINCE, _at(1), False),
            "b2": LedgerEntry(V, "b1", _at(1), _at(2), False),
        },
        ("p-b", "feature"): {"f1": LedgerEntry(V + 1, None, None, _at(3), True)},
    }


async def test_the_scan_census_lists_the_usable_scans_of_every_named_chain(db):
    await _seed_scans(db)

    scans = await window_scan_ids_by_branch(ScanRepository(db), SCOPE, SINCE)

    assert {chain: sorted(entries) for chain, entries in scans.items()} == {
        ("p-a", "main"): [
            ("sa1", _at(0)),
            ("sa2", _at(5)),
            ("sa3", _at(10)),
            ("sa4", _at(15)),
            ("sa5", _at(20)),
            ("sa6", _at(25)),
            ("sa7", _at(30)),
            ("sa8", _at(35)),
        ],
        ("p-a", "dev"): [("sd3", _at(50))],
        ("p-b", "main"): [("sb1", _at(1))],
    }


async def test_branch_activity_inside_a_window_counts_commits_and_the_newest_scan(db):
    await _seed_scans(db)

    activity = await window_scans_by_branch(ScanRepository(db), SCOPE, SINCE)

    assert activity == {
        "p-a": {
            "main": BranchWindowActivity({"c1": 2, "c2": 1, "sa4": 1, "sa5": 1, "sa6": 1}, _at(30)),
            "dev": BranchWindowActivity({"cd3": 1}, _at(50)),
        },
        "p-b": {"main": BranchWindowActivity({"cb1": 1}, _at(1))},
    }


async def test_branch_activity_over_the_whole_history_counts_only_dated_scans(db):
    await _seed_scans(db)

    activity = await window_scans_by_branch(ScanRepository(db), SCOPE, None)

    assert activity == {
        "p-a": {
            "main": BranchWindowActivity({"c1": 2, "c2": 1, "sa4": 1, "sa5": 1, "sa6": 1, "c-old": 1}, _at(30)),
            "dev": BranchWindowActivity({"cd3": 1}, _at(50)),
        },
        "p-b": {"main": BranchWindowActivity({"cb1": 1}, _at(1))},
    }


def _issued(collection: str, operation: str) -> float:
    return REGISTRY.get_sample_value("db_operations_total", {"collection": collection, "operation": operation}) or 0.0


async def test_the_reconcile_accumulates_neither_census_server_side(db):
    # A $group over the window outgrows a blocking stage's 100 MB and fails the whole run.
    t0 = (datetime.now(tz=timezone.utc) - timedelta(days=10)).replace(microsecond=0)
    await db.projects.insert_one({"_id": "p-a", "name": "p-a"})
    for index, scan_id in enumerate(("s1", "s2")):
        await _scan(db, scan_id, "p-a", "main", t0 + timedelta(hours=index), commit_hash=f"c-{scan_id}")
    await db.scan_update_deltas.insert_many(
        [
            {"_id": "s1", "project_id": "p-a", "branch": "main", "scan_created_at": t0, "schema_version": V,
             "prev_scan_id": None, "prev_created_at": None, "dep_count": 1, "error": None},
            {"_id": "s2", "project_id": "p-a", "branch": "main", "scan_created_at": t0 + timedelta(hours=1),
             "schema_version": V, "prev_scan_id": "s1", "prev_created_at": t0, "dep_count": 1, "error": None},
        ]
    )  # fmt: skip
    probes = [("scan_update_deltas", "aggregate"), ("scans", "aggregate"), ("scan_update_deltas", "find")]
    before = {probe: _issued(*probe) for probe in probes}

    report = await run_update_frequency_reconcile(db)

    assert report == ReconcileReport(chains=1)
    issued = {probe: _issued(*probe) - before[probe] for probe in probes}
    assert issued[("scan_update_deltas", "aggregate")] == 0
    assert issued[("scans", "aggregate")] == 0
    assert issued[("scan_update_deltas", "find")] >= 1
