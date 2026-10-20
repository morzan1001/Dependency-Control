"""Every pod runs the housekeeping loop, so the daily sweep and branch sync must claim one pod per interval."""

from datetime import timedelta

import pytest

from app.core import housekeeping
from app.core.constants import HOUSEKEEPING_BRANCH_SYNC_INTERVAL_HOURS, HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_OTHER_SWEEPS = (
    "prune_old_audit_entries",
    "sweep_expired_compliance_reports",
    "reap_stale_metadata",
    "reap_orphan_s3_objects",
    "_reap_orphan_callgraphs",
    "reap_orphan_gridfs_files",
)


async def test_pods_starting_within_an_interval_sweep_and_sync_branches_once(db, monkeypatch):
    await db.projects.insert_one({"_id": "p1", "name": "p1", "gitlab_instance_id": "gl-1", "gitlab_project_id": 7})
    sweeps: list[object] = []
    synced: list[str] = []

    async def _noop(*_args, **_kwargs):
        return None

    async def _sweep(sweep_db):
        sweeps.append(sweep_db)

    async def _sync(project_data, _db):
        synced.append(project_data["_id"])

    for name in _OTHER_SWEEPS:
        monkeypatch.setattr(housekeeping, name, _noop)
    monkeypatch.setattr(housekeeping, "reconcile_release_flags", _sweep)
    monkeypatch.setattr(housekeeping, "sync_project_branches", _sync)

    for _pod in range(2):
        await housekeeping.run_housekeeping(db)
        await housekeeping.sync_branch_status(db)

    assert (len(sweeps), synced) == (1, ["p1"])
    held_for = {lock["_id"]: lock["expires_at"] - lock["acquired_at"] async for lock in db.distributed_locks.find()}
    assert held_for == {
        "housekeeping": timedelta(hours=HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS),
        "branch_sync": timedelta(hours=HOUSEKEEPING_BRANCH_SYNC_INTERVAL_HOURS),
    }
