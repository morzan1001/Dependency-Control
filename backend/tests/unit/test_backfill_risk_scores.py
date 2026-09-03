"""backfill_risk_scores must rewrite only the two score fields, skip scans whose findings are gone, and mirror projects."""

import pytest

from app.models.stats import Stats
from scripts.backfill_risk_scores import UNPARSEABLE_FIELD, backfill_scans, mirror_projects, stats_field_diff
from tests.mocks.fake_mongo import FakeDatabase

BATCH_SIZE = 10
NO_SLEEP_MS = 0
NO_LIMIT = 0
DRIFTED_ACTIONABLE_TOTAL = 42
SENTINEL_STORED_CRITICAL = 99
SENTINEL_STORED_RISK_SCORE = 1.0


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


class TestFullStatsDivergenceReport:
    """The dry-run against a prod restore is the only oracle that runs on real Mongo."""

    @pytest.mark.asyncio
    async def test_identical_stats_report_no_divergence(self, seeded_db):
        from app.services.analysis.stats import calculate_comprehensive_stats

        await seeded_db.findings.insert_one(_finding("f1", "scan-c"))
        computed = await calculate_comprehensive_stats(seeded_db, "scan-c")
        await seeded_db.scans.insert_one({"_id": "scan-c", "stats": computed.model_dump()})

        counters = await backfill_scans(
            seeded_db, batch_size=BATCH_SIZE, sleep_ms=NO_SLEEP_MS, limit=NO_LIMIT, execute=False
        )
        assert counters["stats_differ"] == 0
        assert counters["stats_diff_fields"] == {}

    @pytest.mark.asyncio
    async def test_a_drifted_counter_is_reported_by_field_name(self, seeded_db):
        from app.services.analysis.stats import calculate_comprehensive_stats

        await seeded_db.findings.insert_one(_finding("f1", "scan-c"))
        computed = await calculate_comprehensive_stats(seeded_db, "scan-c")
        stored = computed.model_dump()
        stored["prioritized"]["actionable_total"] = DRIFTED_ACTIONABLE_TOTAL
        await seeded_db.scans.insert_one({"_id": "scan-c", "stats": stored})

        counters = await backfill_scans(
            seeded_db, batch_size=BATCH_SIZE, sleep_ms=NO_SLEEP_MS, limit=NO_LIMIT, execute=False
        )
        assert counters["stats_differ"] == 1
        assert counters["stats_diff_fields"]["prioritized"] == 1

    @pytest.mark.asyncio
    async def test_the_breakdown_counts_scans_per_field(self, seeded_db):
        """The breakdown's values are scan counts, so a field drifting twice must read 2."""
        from app.services.analysis.stats import calculate_comprehensive_stats

        for scan_id in ("scan-c", "scan-d"):
            await seeded_db.findings.insert_one(_finding(f"f-{scan_id}", scan_id))
            computed = await calculate_comprehensive_stats(seeded_db, scan_id)
            stored = computed.model_dump()
            stored["prioritized"]["actionable_total"] = DRIFTED_ACTIONABLE_TOTAL
            await seeded_db.scans.insert_one({"_id": scan_id, "stats": stored})

        counters = await backfill_scans(
            seeded_db, batch_size=BATCH_SIZE, sleep_ms=NO_SLEEP_MS, limit=NO_LIMIT, execute=False
        )
        assert counters["stats_differ"] == 2
        assert counters["stats_diff_fields"] == {"prioritized": 2}

    @pytest.mark.asyncio
    async def test_a_stats_block_missing_newer_keys_is_normalised_not_reported(self, seeded_db):
        """An old stats block predates a field; defaulting it keeps schema drift out of the signal."""
        from app.services.analysis.stats import calculate_comprehensive_stats

        await seeded_db.findings.insert_one(_finding("f1", "scan-c"))
        computed = await calculate_comprehensive_stats(seeded_db, "scan-c")
        stored = computed.model_dump()
        del stored["negligible"]

        assert stats_field_diff(stored, computed) == {}

    def test_an_unparseable_stats_block_is_reported_rather_than_raising(self):
        assert list(stats_field_diff({"critical": "not-a-number"}, Stats())) == [UNPARSEABLE_FIELD]

    @pytest.mark.asyncio
    async def test_divergence_reporting_never_writes(self, seeded_db):
        await seeded_db.findings.insert_one(_finding("f1", "scan-c"))
        await seeded_db.scans.insert_one(
            {
                "_id": "scan-c",
                "stats": {"critical": SENTINEL_STORED_CRITICAL, "risk_score": SENTINEL_STORED_RISK_SCORE},
            }
        )

        await backfill_scans(seeded_db, batch_size=BATCH_SIZE, sleep_ms=NO_SLEEP_MS, limit=NO_LIMIT, execute=False)
        scan = await seeded_db.scans.find_one({"_id": "scan-c"})
        assert scan["stats"]["critical"] == SENTINEL_STORED_CRITICAL

    @pytest.mark.asyncio
    async def test_execute_writes_only_the_two_score_fields_when_the_whole_block_diverges(self, seeded_db):
        """Divergence is reported, never repaired: widening the write would drop keys older writers emitted."""
        await seeded_db.findings.insert_one(_finding("f1", "scan-c"))
        await seeded_db.scans.insert_one(
            {
                "_id": "scan-c",
                "stats": {
                    "critical": SENTINEL_STORED_CRITICAL,
                    "risk_score": SENTINEL_STORED_RISK_SCORE,
                    "legacy_key_no_writer_emits_today": SENTINEL_STORED_CRITICAL,
                },
            }
        )

        counters = await backfill_scans(
            seeded_db, batch_size=BATCH_SIZE, sleep_ms=NO_SLEEP_MS, limit=NO_LIMIT, execute=True
        )
        assert counters["stats_differ"] == 1
        scan = await seeded_db.scans.find_one({"_id": "scan-c"})
        assert scan["stats"]["risk_score"] == 7.4
        assert scan["stats"]["adjusted_risk_score"] == 7.4
        assert scan["stats"]["critical"] == SENTINEL_STORED_CRITICAL
        assert scan["stats"]["legacy_key_no_writer_emits_today"] == SENTINEL_STORED_CRITICAL
        assert "prioritized" not in scan["stats"]
