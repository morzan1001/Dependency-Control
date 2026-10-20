import logging
from typing import Any

import pytest

from app.core import housekeeping
from tests.mocks.fake_mongo import FakeDatabase

_SWEEPS = {
    "reconcile_release_flags": "Housekeeping: release flag reconcile",
    "prune_old_audit_entries": "Housekeeping: policy audit retention",
    "sweep_expired_compliance_reports": "Housekeeping: compliance report sweep",
    "_reap_orphan_s3_objects": "Orphan reaper",
    "_reap_orphan_callgraphs": "Callgraph orphan reaper",
    "reap_orphan_gridfs_files": "GridFS orphan reaper",
}


@pytest.mark.asyncio
@pytest.mark.parametrize("failing", list(_SWEEPS))
async def test_a_failing_sweep_is_logged_by_name_and_the_others_still_run(monkeypatch, caplog, failing):
    db = FakeDatabase()
    ran: list[tuple[str, Any]] = []

    def _sweep(name: str):
        async def _run(sweep_db: Any) -> None:
            ran.append((name, sweep_db))
            if name == failing:
                raise RuntimeError("mongo unreachable")

        return _run

    for name in _SWEEPS:
        monkeypatch.setattr(housekeeping, name, _sweep(name))

    with caplog.at_level(logging.ERROR, logger="app.core.housekeeping"):
        await housekeeping.run_housekeeping(db)

    assert ran == [(name, db) for name in _SWEEPS]
    assert [record.getMessage() for record in caplog.records] == [f"{_SWEEPS[failing]} failed: mongo unreachable"]
