"""backfill_risk_scores must rewrite only the two score fields, skip scans whose findings are gone, and mirror projects."""

import pytest

from scripts.backfill_risk_scores import backfill_scans, mirror_projects
from tests.mocks.fake_mongo import FakeDatabase


def _finding(_id, scan_id, severity="CRITICAL"):
    return {
        "_id": _id,
        "finding_id": _id,
        "scan_id": scan_id,
        "type": "vulnerability",
        "severity": severity,
        "component": "pkg",
        "version": "1.0.0",
        "details": {},
        "waived": False,
    }


def _old_stats(critical=1, risk=13.5):
    return {
        "critical": critical,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
        "risk_score": risk,
        "adjusted_risk_score": risk,
        "prioritized": {"total": 99},
    }


@pytest.fixture
def seeded_db():
    db = FakeDatabase()
    return db


async def _seed(db):
    # scan-a: findings present, stored score stale -> update
    await db.scans.insert_one({"_id": "scan-a", "stats": _old_stats()})
    await db.findings.insert_one(_finding("f1", "scan-a"))
    # scan-b: stats claim findings but none stored anymore -> skip
    await db.scans.insert_one({"_id": "scan-b", "stats": _old_stats(critical=3, risk=12.1)})
    await db.projects.insert_one({"_id": "proj-1", "latest_scan_id": "scan-a", "stats": _old_stats()})


class TestBackfillRiskScores:
    @pytest.mark.asyncio
    async def test_dry_run_reports_but_writes_nothing(self, seeded_db):
        await _seed(seeded_db)
        counters = await backfill_scans(seeded_db, batch_size=10, sleep_ms=0, limit=0, execute=False)
        assert counters["would_update"] == 1
        assert counters["skipped_no_findings"] == 1
        assert counters["updated"] == 0
        scan = await seeded_db.scans.find_one({"_id": "scan-a"})
        assert scan["stats"]["risk_score"] == 13.5

    @pytest.mark.asyncio
    async def test_execute_rewrites_only_score_fields(self, seeded_db):
        await _seed(seeded_db)
        counters = await backfill_scans(seeded_db, batch_size=10, sleep_ms=0, limit=0, execute=True)
        assert counters["updated"] == 1
        scan = await seeded_db.scans.find_one({"_id": "scan-a"})
        # 1 CRITICAL -> 100*20/(20+250) = 7.4, via the shared runtime formula
        assert scan["stats"]["risk_score"] == 7.4
        assert scan["stats"]["adjusted_risk_score"] == 7.4
        # the rest of the stored stats blob stays untouched
        assert scan["stats"]["critical"] == 1
        assert scan["stats"]["prioritized"] == {"total": 99}

    @pytest.mark.asyncio
    async def test_skipped_scan_keeps_stored_scores(self, seeded_db):
        await _seed(seeded_db)
        await backfill_scans(seeded_db, batch_size=10, sleep_ms=0, limit=0, execute=True)
        scan = await seeded_db.scans.find_one({"_id": "scan-b"})
        assert scan["stats"]["risk_score"] == 12.1

    @pytest.mark.asyncio
    async def test_project_mirror_follows_latest_scan(self, seeded_db):
        await _seed(seeded_db)
        counters = await backfill_scans(seeded_db, batch_size=10, sleep_ms=0, limit=0, execute=True)
        project_counters = await mirror_projects(seeded_db, counters["new_scores"], execute=True)
        assert project_counters["projects_updated"] == 1
        project = await seeded_db.projects.find_one({"_id": "proj-1"})
        assert project["stats"]["risk_score"] == 7.4
        assert project["stats"]["critical"] == 1
