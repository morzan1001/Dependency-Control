"""The waiver recalculation queue and its expiry sweep on a real server: the sweep window compares the stored
watermark (read back naive) with aware datetimes, and the queue filter tells requests from the watermark."""

from datetime import datetime, timezone

import pytest

import app.services.stats as stats_module
from app.models.waiver import Waiver
from app.services.stats import request_waiver_recalc, run_waiver_recalc

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]

_NOW = datetime.now(timezone.utc)


async def _seed(db) -> None:
    await db.projects.insert_one({"_id": "p-1", "name": "p", "latest_scan_id": "s-1", "deleted_branches": []})
    await db.scans.insert_one({"_id": "s-1", "project_id": "p-1", "status": "completed", "created_at": _NOW})
    await db.findings.insert_one(
        {"_id": "f-1", "scan_id": "s-1", "type": "license", "finding_id": "LIC-GPL-3.0", "component": "lib"}
    )


def _waiver(**fields) -> Waiver:
    return Waiver(project_id="p-1", finding_id="LIC-GPL-3.0", package_name="lib", reason="r", created_by="u", **fields)


async def test_a_queued_change_is_worked_off_and_an_expiry_is_swept_once(db, monkeypatch):
    await _seed(db)
    active = _waiver()
    await db.waivers.insert_one(active.model_dump(by_alias=True, exclude={"is_active"}))
    await request_waiver_recalc(db, active)

    await run_waiver_recalc(db)

    assert (await db.findings.find_one({"_id": "f-1"}))["waived"] is True
    assert await db.waiver_recalc.count_documents({}) == 1  # only the sweep's watermark is left

    await db.waivers.update_one({"_id": active.id}, {"$set": {"expiration_date": datetime.now(timezone.utc)}})
    await run_waiver_recalc(db)

    assert (await db.findings.find_one({"_id": "f-1"}))["waived"] is False
    assert await db.waiver_recalc.count_documents({}) == 1

    visited: list[str] = []

    async def recording(project_id, *_args):
        visited.append(project_id)

    monkeypatch.setattr(stats_module, "recalculate_project_stats", recording)
    await run_waiver_recalc(db)

    assert visited == []
