"""Every pod runs the housekeeping loop. The daily sweep and the branch sync must still run on one pod per
interval, or each rollout repeats them once per replica against Mongo, S3 and the GitLab/GitHub APIs."""

from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.core import housekeeping
from app.core.constants import HOUSEKEEPING_BRANCH_SYNC_INTERVAL_HOURS, HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_UNRELATED = (
    "recover_stuck_scans",
    "check_scheduled_rescans",
    "update_db_stats",
    "update_archive_stats",
    "update_cache_stats",
    "run_waiver_recalc",
    "_run_retention",
    "reconcile_update_frequency_ledger",
    "prune_old_audit_entries",
    "sweep_expired_compliance_reports",
    "_reap_orphan_s3_objects",
    "_reap_orphan_callgraphs",
    "reap_orphan_gridfs_files",
)


class _StopLoop(Exception):
    """Ends a pod's housekeeping loop after its first pass."""


async def test_pods_starting_within_an_interval_sweep_and_sync_branches_once(db, monkeypatch):
    await db.projects.insert_one({"_id": "p1", "name": "p1", "gitlab_instance_id": "gl-1", "gitlab_project_id": 7})
    sweeps: list[object] = []
    synced: list[str] = []

    async def _noop(*_args, **_kwargs):
        return None

    async def _get_database():
        return db

    async def _sweep(sweep_db):
        sweeps.append(sweep_db)

    async def _sync(project_data, _db):
        synced.append(project_data["_id"])

    async def _sleep(_seconds):
        raise _StopLoop

    for name in _UNRELATED:
        monkeypatch.setattr(housekeeping, name, _noop)
    monkeypatch.setattr(housekeeping, "get_database", _get_database)
    monkeypatch.setattr(housekeeping, "reconcile_release_flags", _sweep)
    monkeypatch.setattr(housekeeping, "sync_project_branches", _sync)
    monkeypatch.setattr(housekeeping, "asyncio", SimpleNamespace(sleep=_sleep))

    for _pod in range(2):
        with pytest.raises(_StopLoop):
            await housekeeping.housekeeping_loop()

    assert (len(sweeps), synced) == (1, ["p1"])
    held_for = sorted([lock["expires_at"] - lock["acquired_at"] async for lock in db.distributed_locks.find()])
    assert held_for == [
        timedelta(hours=HOUSEKEEPING_BRANCH_SYNC_INTERVAL_HOURS),
        timedelta(hours=HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS),
    ]
