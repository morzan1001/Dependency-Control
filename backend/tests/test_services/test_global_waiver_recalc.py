"""A global waiver change recalculates the projects it can reach, each on its own."""

import pytest

import app.services.stats as stats_module
from app.models.waiver import Waiver
from app.services.stats import recalculate_all_projects
from tests.mocks.fake_mongo import FakeDatabase

pytestmark = pytest.mark.asyncio

_GPL = "LIC-GPL-3.0"


async def _seed_project(db: FakeDatabase, project_id: str, finding_id: str) -> None:
    scan_id = f"scan-{project_id}"
    await db.projects.insert_one({"_id": project_id, "name": project_id, "latest_scan_id": scan_id})
    await db.scans.insert_one({"_id": scan_id, "project_id": project_id, "status": "completed"})
    await db.findings.insert_one(
        {"_id": f"f-{project_id}", "scan_id": scan_id, "type": "license", "component": "lib", "finding_id": finding_id}
    )


def _gpl_waiver() -> Waiver:
    return Waiver(finding_type="license", finding_id=_GPL, package_name="lib", reason="r", created_by="admin")


async def test_only_the_projects_holding_a_finding_the_waiver_matches_are_recalculated():
    db = FakeDatabase()
    await _seed_project(db, "p-gpl", _GPL)
    await _seed_project(db, "p-mit", "LIC-MIT")
    waiver = _gpl_waiver()
    await db.waivers.insert_one(waiver.model_dump(by_alias=True))

    assert await recalculate_all_projects(db, waiver) == 1

    assert "stats" in await db.scans.find_one({"_id": "scan-p-gpl"})
    assert "stats" not in await db.scans.find_one({"_id": "scan-p-mit"})
    assert (await db.findings.find_one({"_id": "f-p-gpl"}))["waived"] is True


async def test_one_failing_project_does_not_stop_the_recalculation_of_the_others(monkeypatch):
    db = FakeDatabase()
    for project_id in ("p-1", "p-broken", "p-3"):
        await _seed_project(db, project_id, _GPL)
    visited: list[str] = []

    async def recalculate(project_id, database, reach=None):
        visited.append(project_id)
        if project_id == "p-broken":
            raise RuntimeError("legacy document")
        return object()

    monkeypatch.setattr(stats_module, "recalculate_project_stats", recalculate)

    assert await recalculate_all_projects(db, _gpl_waiver()) == 2
    assert visited == ["p-1", "p-broken", "p-3"]
