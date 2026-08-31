"""The rollup read path, checked against the live path it replaces.

The differential tests run one scan history twice: once through
``compute_update_frequency``, which walks every scan, and once through the
delta ledger plus fold. Where the two disagree by design, the test says so.
"""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch

import pytest

from app.api.v1.endpoints.analytics import update_frequency as endpoint
from app.api.v1.endpoints.analytics.update_frequency import (
    _compute_comparison,
    _compute_comparison_from_rollup,
    _fold_branch,
    _resolve_window,
    _rollup_project_metrics,
)
from app.repositories import AnalysisResultRepository, DependencyRepository, ScanRepository
from app.repositories.update_frequency import WINDOW_HARD_LIMIT, BranchWindowActivity
from app.schemas.analytics import UpdateFrequencyComparison, UpdateFrequencyMetrics
from app.services.update_frequency import compute_update_frequency
from app.services.update_frequency_rollup import record_scan_update_delta
from tests.mocks.fake_mongo import FakeDatabase

PROJECT = "proj-1"
BRANCH = "main"
WINDOW_DAYS = 90


def _one_scan_each(commit_count: int) -> dict[str, int]:
    """A window whose commits were each scanned once, the shape most cases only need."""
    return {f"commit-{index}": 1 for index in range(commit_count)}


# Anchored inside the window so both paths see the same scans.
NOW = datetime.now(tz=timezone.utc)


def _days_ago(days: float) -> datetime:
    return NOW - timedelta(days=days)


def _dep(scan_id: str, name: str, version: str, ecosystem: str = "pypi") -> dict[str, Any]:
    return {
        "_id": f"{scan_id}:{name}",
        "scan_id": scan_id,
        "project_id": PROJECT,
        "name": name,
        "version": version,
        "type": "library",
        "purl": f"pkg:{ecosystem}/{name}@{version}",
    }


async def _seed_scan(
    db: FakeDatabase,
    scan_id: str,
    created_at: datetime,
    packages: dict[str, str],
    outdated: tuple[str, ...] | None = None,
    *,
    branch: str = BRANCH,
    commit_hash: str | None = None,
    project_id: str = PROJECT,
    ecosystem: str = "pypi",
) -> None:
    """``outdated=None`` seeds no outdated analysis at all; ``()`` seeds one that found nothing."""
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": project_id,
            "branch": branch,
            "created_at": created_at,
            "commit_hash": commit_hash or f"commit-{scan_id}",
            "status": "completed",
            "is_rescan": False,
        }
    )
    for name, version in packages.items():
        await db.dependencies.insert_one(_dep(scan_id, name, version, ecosystem) | {"project_id": project_id})
    if outdated is not None:
        await db.analysis_results.insert_one(
            {
                "_id": f"{scan_id}:outdated",
                "scan_id": scan_id,
                "analyzer_name": "outdated_packages",
                "result": {
                    "outdated_dependencies": [
                        {"component": name, "current_version": "0.0.1", "latest_version": "9.9.9"} for name in outdated
                    ]
                },
            }
        )


async def _build_ledger(db: FakeDatabase) -> None:
    """Run the ingest hook over every seeded scan, oldest first, as production does."""
    scans = await db.scans.find({}).to_list(None)
    for scan in sorted(scans, key=lambda s: (s["created_at"], s["_id"])):
        await record_scan_update_delta(db, scan["_id"])


def _project(**overrides: Any) -> dict[str, Any]:
    return {"_id": PROJECT, "name": "Project One", "default_branch": None, "deleted_branches": []} | overrides


async def _live(
    db: FakeDatabase, project: dict[str, Any] | None = None, hard_limit: int = WINDOW_HARD_LIMIT
) -> UpdateFrequencyMetrics:
    project = project or _project()
    return await compute_update_frequency(
        project_id=str(project["_id"]),
        project_name=project["name"],
        scan_repo=ScanRepository(db),
        dep_repo=DependencyRepository(db),
        analysis_repo=AnalysisResultRepository(db),
        window_days=WINDOW_DAYS,
        hard_limit=hard_limit,
        deleted_branches=project.get("deleted_branches"),
        default_branch=project.get("default_branch"),
    )


async def _rollup(db: FakeDatabase, project: dict[str, Any] | None = None) -> UpdateFrequencyMetrics | None:
    return await _rollup_project_metrics(db, project or _project(), WINDOW_DAYS)


# Fields both paths must agree on. dominant_ecosystem is excluded on purpose:
# the live path folds every scan's dependency types, the rollup reports what the
# newest scan holds.
_SHARED_FIELDS = (
    "branch",
    "scan_count",
    "time_range_days",
    "first_scan_date",
    "last_scan_date",
    "total_updates",
    "updates_per_scan",
    "updates_per_month",
    "patch_updates",
    "minor_updates",
    "major_updates",
    "unknown_updates",
    "downgrade_updates",
    "granularity_ratio",
    "avg_days_between_scans",
    "total_outdated_detected",
    "outdated_resolved",
    "update_coverage_pct",
    "trend_direction",
    "trend_detail",
    "scan_timeline",
)


def _assert_same_metrics(live: UpdateFrequencyMetrics, rolled: UpdateFrequencyMetrics | None) -> None:
    assert rolled is not None
    mismatches = {
        field: (getattr(live, field), getattr(rolled, field))
        for field in _SHARED_FIELDS
        if getattr(live, field) != getattr(rolled, field)
    }
    assert mismatches == {}


def _update_signatures(metrics: UpdateFrequencyMetrics) -> set[tuple[str, str, str, str, str]]:
    return {(e.package_name, e.old_version, e.new_version, e.update_type, e.scan_date) for e in metrics.recent_updates}


def _slowest_signatures(metrics: UpdateFrequencyMetrics) -> set[tuple[str, int]]:
    return {(p.name, p.scans_outdated) for p in metrics.slowest_packages}


class TestDifferentialNormalHistory:
    @pytest.mark.asyncio
    async def test_every_shared_metric_matches(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0", "flask": "3.0.0"}, ("flask",))
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.0.1", "flask": "3.0.0"}, ("flask",))
        await _seed_scan(db, "s3", _days_ago(40), {"requests": "2.1.0", "flask": "4.0.0"}, ())
        await _seed_scan(db, "s4", _days_ago(30), {"requests": "3.0.0", "flask": "4.0.0"}, ("requests",))
        await _build_ledger(db)

        live = await _live(db)
        rolled = await _rollup(db)

        _assert_same_metrics(live, rolled)
        assert live.total_updates == 4
        assert live.update_coverage_pct is not None

    @pytest.mark.asyncio
    async def test_update_events_and_backlog_match(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0", "flask": "3.0.0"}, ("flask", "requests"))
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.0.1", "flask": "3.0.0"}, ("flask",))
        await _seed_scan(db, "s3", _days_ago(40), {"requests": "2.1.0", "flask": "4.0.0"}, ("flask",))
        await _build_ledger(db)

        live = await _live(db)
        rolled = await _rollup(db)

        assert rolled is not None
        assert _update_signatures(rolled) == _update_signatures(live)
        assert _slowest_signatures(rolled) == _slowest_signatures(live)
        assert rolled.slowest_packages[0].latest_version == "9.9.9"

    @pytest.mark.asyncio
    async def test_downgrades_stay_out_of_the_update_total(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.5.0", "flask": "3.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.0.0", "flask": "3.1.0"}, ())
        await _build_ledger(db)

        live = await _live(db)
        rolled = await _rollup(db)

        _assert_same_metrics(live, rolled)
        assert live.downgrade_updates == 1
        assert live.total_updates == 1

    @pytest.mark.asyncio
    async def test_same_commit_retries_share_one_bar_in_both_paths(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, (), commit_hash="c1")
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, (), commit_hash="c2")
        await _seed_scan(db, "s3", _days_ago(49), {"requests": "2.1.0"}, (), commit_hash="c2")
        await _seed_scan(db, "s4", _days_ago(48), {"requests": "2.1.0"}, (), commit_hash="c2")
        await _build_ledger(db)

        live = await _live(db)
        rolled = await _rollup(db)

        _assert_same_metrics(live, rolled)
        assert live.scan_count == 2
        # The bar is the run's newest scan, so the project's last activity is not backdated.
        assert [e.scan_id for e in live.scan_timeline] == ["s1", "s4"]
        assert live.last_scan_date == _days_ago(48).isoformat()

    @pytest.mark.asyncio
    async def test_a_scan_without_outdated_analysis_matches(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0", "flask": "3.0.0"}, ("flask",))
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.0.1", "flask": "3.0.0"}, None)
        await _seed_scan(db, "s3", _days_ago(40), {"requests": "2.0.2", "flask": "3.0.0"}, ("flask",))
        await _build_ledger(db)

        live = await _live(db)
        rolled = await _rollup(db)

        _assert_same_metrics(live, rolled)
        assert live.scan_timeline[1].outdated_count is None
        assert live.update_coverage_pct == 0.0

    @pytest.mark.asyncio
    async def test_only_the_selected_branch_is_folded(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        await _seed_scan(db, "f1", _days_ago(45), {"requests": "9.0.0"}, (), branch="feature")
        await _seed_scan(db, "s3", _days_ago(40), {"requests": "2.2.0"}, ())
        await _build_ledger(db)

        live = await _live(db)
        rolled = await _rollup(db)

        _assert_same_metrics(live, rolled)
        assert live.branch == BRANCH
        assert live.total_updates == 2

    @pytest.mark.asyncio
    async def test_a_restored_scan_dated_in_text_is_invisible_to_both_paths(self):
        # An archive restore inserts bundle JSON verbatim and JSON has no date type.
        # No ingest hook ever runs for such a scan, and the backfill cannot collect it
        # either, because a range query is bracketed to its bound's BSON type.
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s3", _days_ago(40), {"requests": "2.1.0"}, ())
        await _build_ledger(db)
        await db.scans.insert_one(
            {
                "_id": "restored",
                "project_id": PROJECT,
                "branch": BRANCH,
                "created_at": "2026-07-01T00:00:00+00:00",
                "commit_hash": "commit-restored",
                "status": "completed",
                "is_rescan": False,
            }
        )
        await db.dependencies.insert_one(_dep("restored", "requests", "9.9.9"))

        live = await _live(db)
        rolled = await _rollup(db)

        _assert_same_metrics(live, rolled)
        assert [e.scan_id for e in live.scan_timeline] == ["s1", "s3"]
        assert live.total_updates == 1

    @pytest.mark.asyncio
    async def test_a_window_without_scans_falls_back_to_the_live_path(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(300), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(290), {"requests": "2.1.0"}, ())
        await _build_ledger(db)

        live = await _live(db)

        assert await _rollup(db) is None
        assert live.scan_count == 0


class TestDifferentialSbomLessScans:
    """A scan that produced no SBOM measured nothing, so both paths compare across it."""

    @pytest.mark.asyncio
    async def test_both_paths_compare_across_the_gap_instead_of_reading_it_as_quiet(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {}, ())
        await _seed_scan(db, "s3", _days_ago(40), {"requests": "2.1.0"}, ())
        await _build_ledger(db)

        live = await _live(db)
        rolled = await _rollup(db)

        _assert_same_metrics(live, rolled)
        # Keeping s2 framed the bump across it as two quiet intervals.
        assert live.scan_count == 2
        assert (live.total_updates, live.minor_updates) == (1, 1)
        assert [e.scan_id for e in live.scan_timeline] == ["s1", "s3"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sbom_less", ["s1", "s2"])
    async def test_two_scans_one_without_an_sbom_supports_no_comparison_on_either_path(self, sbom_less: str):
        db = FakeDatabase()
        for scan_id, day in (("s1", 60), ("s2", 50)):
            packages = {} if scan_id == sbom_less else {"requests": "2.0.0"}
            await _seed_scan(db, scan_id, _days_ago(day), packages, ())
        await _build_ledger(db)

        live = await _live(db)

        assert (live.scan_count, live.updates_per_month) == (1, None)
        assert await _rollup(db) is None

    @pytest.mark.asyncio
    async def test_three_scans_two_without_an_sbom_supports_no_comparison_on_either_path(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {}, ())
        await _seed_scan(db, "s3", _days_ago(40), {}, ())
        await _build_ledger(db)

        live = await _live(db)

        assert (live.scan_count, live.updates_per_month) == (1, None)
        assert await _rollup(db) is None

    @pytest.mark.asyncio
    async def test_a_project_with_nothing_to_say_stays_out_of_the_team_average(self):
        # A "ready" row at 0.0 updates/month dragged the team average down and could
        # be named worst_project, for a project no comparison was possible on.
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "b1", _days_ago(60), {"flask": "3.0.0"}, (), project_id="proj-2")
        await _seed_scan(db, "b2", _days_ago(50), {"flask": "3.1.0"}, (), project_id="proj-2")
        await _build_ledger(db)
        await _seed_projects(db, [PROJECT, "proj-2"])

        live = await _live_comparison(db, [PROJECT, "proj-2"])
        rolled = UpdateFrequencyComparison(
            **await _compute_comparison_from_rollup(db, [PROJECT, "proj-2"], None, window_days=WINDOW_DAYS)
        )

        for comparison in (live, rolled):
            statuses = {p.project_id: p.data_status for p in comparison.projects}
            assert statuses == {PROJECT: "insufficient_data", "proj-2": "ready"}
            assert comparison.team_avg_updates_per_month == 0.34
            assert comparison.skipped_insufficient_data == 1


class TestDataStatus:
    @pytest.mark.asyncio
    async def test_a_folded_project_is_ready(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        await _build_ledger(db)

        comparison = await _comparison(db, [PROJECT])

        assert [(p.project_id, p.data_status) for p in comparison.projects] == [(PROJECT, "ready")]
        assert comparison.projects[0].branch == BRANCH
        assert comparison.projects[0].window_days == WINDOW_DAYS
        assert comparison.projects[0].total_updates == 1
        assert comparison.pending_projects == 0

    @pytest.mark.asyncio
    async def test_a_project_without_deltas_is_pending_not_dropped(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        # No ledger: this is a project the backfill has not reached.

        comparison = await _comparison(db, [PROJECT])

        row = comparison.projects[0]
        assert row.data_status == "pending"
        assert comparison.pending_projects == 1
        # The scans name the branch even where the ledger has nothing to say yet.
        assert (row.branch, row.scan_count, row.updates_per_month, row.total_updates) == (BRANCH, None, None, None)
        assert (row.update_coverage_pct, row.patch_ratio, row.trend_direction, row.last_scan_date) == (
            None,
            None,
            None,
            None,
        )

    @pytest.mark.asyncio
    async def test_a_project_that_never_scanned_in_the_window_is_insufficient_not_pending(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(300), {"requests": "2.0.0"}, ())

        comparison = await _comparison(db, [PROJECT])

        row = comparison.projects[0]
        assert (row.project_id, row.data_status, row.branch) == (PROJECT, "insufficient_data", None)
        assert comparison.pending_projects == 0
        assert comparison.skipped_insufficient_data == 1

    @pytest.mark.asyncio
    async def test_a_single_in_window_scan_is_named_not_merely_counted(self):
        # A bare "1 with too few scans" leaves nobody able to go and look at it.
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _build_ledger(db)

        comparison = await _comparison(db, [PROJECT])

        row = comparison.projects[0]
        assert (row.project_id, row.data_status, row.branch) == (PROJECT, "insufficient_data", BRANCH)
        assert (row.scan_count, row.updates_per_month, row.total_updates) == (None, None, None)
        assert comparison.skipped_insufficient_data == 1
        assert comparison.skipped_error == 0

    @pytest.mark.asyncio
    async def test_deltas_carrying_a_writer_failure_are_reported_as_errors(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        await _build_ledger(db)
        await db.scan_update_deltas.update_many({}, {"$set": {"error": "boom", "dep_count": 0}})

        comparison = await _comparison(db, [PROJECT])

        row = comparison.projects[0]
        assert (row.project_id, row.data_status) == (PROJECT, "error")
        assert row.scan_count is None
        assert comparison.skipped_error == 1
        assert comparison.skipped_insufficient_data == 0

    @pytest.mark.asyncio
    async def test_unmeasurable_rows_come_last_and_in_the_agreed_order(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        await _seed_scan(db, "e1", _days_ago(60), {"flask": "3.0.0"}, (), project_id="proj-err")
        await _seed_scan(db, "e2", _days_ago(50), {"flask": "3.1.0"}, (), project_id="proj-err")
        await _seed_scan(db, "t1", _days_ago(60), {"click": "8.0.0"}, (), project_id="proj-thin")
        await _build_ledger(db)
        await db.scan_update_deltas.update_many({"project_id": "proj-err"}, {"$set": {"error": "boom", "dep_count": 0}})
        # proj-wait scanned but the backfill has not reached it.
        await _seed_scan(db, "w1", _days_ago(60), {"attrs": "1.0.0"}, (), project_id="proj-wait")
        await _seed_scan(db, "w2", _days_ago(50), {"attrs": "1.1.0"}, (), project_id="proj-wait")

        comparison = await _comparison(db, [PROJECT, "proj-err", "proj-thin", "proj-wait"])

        assert [p.data_status for p in comparison.projects] == [
            "ready",
            "pending",
            "insufficient_data",
            "error",
        ]
        assert [p.project_id for p in comparison.projects] == [PROJECT, "proj-wait", "proj-thin", "proj-err"]

    @pytest.mark.asyncio
    async def test_a_broken_chain_never_reaches_the_fold_out_of_order(self):
        # The read path re-sorts every bucket, so the fold's ordering contract
        # holds however the documents came back from Mongo.
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        await _build_ledger(db)
        await db.scan_update_deltas.update_one({"_id": "s1"}, {"$set": {"scan_created_at": _days_ago(10)}})

        comparison = await _comparison(db, [PROJECT])

        # s1 now follows s2 and its prev_scan_id no longer links them, so only
        # the newest scan survives the chain cut.
        assert comparison.skipped_insufficient_data == 1


class TestPendingRowsDoNotSkewTheRanking:
    @pytest.mark.asyncio
    async def test_averages_and_best_worst_ignore_unmeasured_projects(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ("requests",))
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        await _seed_scan(db, "b1", _days_ago(60), {"flask": "3.0.0"}, ("flask",), project_id="proj-2")
        await _seed_scan(db, "b2", _days_ago(50), {"flask": "3.0.1"}, ("flask",), project_id="proj-2")
        await _build_ledger(db)
        # proj-3 has scans but no deltas yet, so it can only be reported as pending.
        await _seed_scan(db, "c1", _days_ago(60), {"click": "8.0.0"}, (), project_id="proj-3")
        await _seed_scan(db, "c2", _days_ago(50), {"click": "8.1.0"}, (), project_id="proj-3")

        comparison = await _comparison(db, [PROJECT, "proj-2", "proj-3"])

        ready = [p for p in comparison.projects if p.data_status == "ready"]
        assert comparison.pending_projects == 1
        assert {p.project_id for p in ready} == {PROJECT, "proj-2"}
        assert comparison.team_avg_coverage_pct == 50.0
        assert comparison.team_avg_updates_per_month == round(sum(p.updates_per_month for p in ready) / len(ready), 2)
        assert (comparison.best_project, comparison.worst_project) == ("Project proj-1", "Project proj-2")
        # The unmeasured project is listed, but after every ranked one.
        assert comparison.projects[-1].data_status == "pending"

    @pytest.mark.asyncio
    async def test_a_ready_project_that_never_flagged_a_package_ranks_behind_a_measured_one(self):
        # Coverage of None is "nothing was ever outdated", not "everything is late",
        # so it must not outrank a project whose backlog was actually measured --
        # not even when it moves more packages.
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ("requests",))
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.0.1"}, ())
        await _seed_scan(db, "b1", _days_ago(60), {"flask": "3.0.0", "click": "8.0.0"}, (), project_id="proj-2")
        await _seed_scan(db, "b2", _days_ago(50), {"flask": "3.1.0", "click": "8.1.0"}, (), project_id="proj-2")
        await _build_ledger(db)

        comparison = await _comparison(db, [PROJECT, "proj-2"])

        measured, unmeasured = comparison.projects
        assert (measured.project_id, measured.data_status, measured.update_coverage_pct) == (PROJECT, "ready", 100.0)
        assert (unmeasured.project_id, unmeasured.data_status, unmeasured.update_coverage_pct) == (
            "proj-2",
            "ready",
            None,
        )
        assert unmeasured.updates_per_month > measured.updates_per_month
        assert (comparison.best_project, comparison.worst_project) == ("Project proj-1", None)

    @pytest.mark.asyncio
    async def test_a_scope_where_nothing_was_ever_outdated_crowns_nobody(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        await _seed_scan(db, "b1", _days_ago(60), {"flask": "3.0.0"}, (), project_id="proj-2")
        await _seed_scan(db, "b2", _days_ago(50), {"flask": "3.1.0"}, (), project_id="proj-2")
        await _build_ledger(db)

        comparison = await _comparison(db, [PROJECT, "proj-2"])

        assert [p.data_status for p in comparison.projects] == ["ready", "ready"]
        assert [p.update_coverage_pct for p in comparison.projects] == [None, None]
        assert (comparison.best_project, comparison.worst_project) == (None, None)
        assert comparison.team_avg_coverage_pct is None
        # The rows are ranked and averaged on cadence; only the podium is empty.
        assert comparison.team_avg_updates_per_month is not None

    @pytest.mark.asyncio
    async def test_a_scope_of_only_pending_projects_reports_no_averages(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())

        comparison = await _comparison(db, [PROJECT])

        assert comparison.team_avg_updates_per_month is None
        assert comparison.team_avg_coverage_pct is None
        assert comparison.best_project is None
        assert comparison.worst_project is None


def _fake_deltas(branch: str, count: int, newest_days_ago: float, retries: int = 1) -> list[dict[str, Any]]:
    """A linked chain of usable deltas, oldest first, as the repository hands it over.

    ``retries`` is how many times CI scanned each commit.
    """
    ids = [f"{branch}-{i}" for i in range(count)]
    return [
        {
            "_id": scan_id,
            "project_id": PROJECT,
            "branch": branch,
            "scan_created_at": _days_ago(newest_days_ago + count - 1 - i),
            "commit_hash": f"c-{branch}-{i // retries}",
            "prev_scan_id": ids[i - 1] if i else None,
            "dep_count": 1,
            "updates": {"patch": 1, "minor": 0, "major": 0, "unknown": 0, "downgrade": 0},
            "outdated_count": 0,
            "outdated_added": [],
            "outdated_resolved": [],
            "eco": {"pypi": 1},
            "error": None,
        }
        for i, scan_id in enumerate(ids)
    ]


class TestBranchChoice:
    def test_a_project_whose_only_branches_are_deleted_resolves_to_nothing(self):
        resolved = _resolve_window(
            {"gone": BranchWindowActivity(_one_scan_each(3), _days_ago(2))},
            {"gone": _fake_deltas("gone", 3, 2)},
            {"_id": PROJECT, "deleted_branches": ["gone"]},
        )
        assert (resolved.branch, resolved.status) == (None, "insufficient_data")

    def test_the_branch_comes_from_the_scans_not_from_the_ledger(self):
        # A ledger that only reached the quieter branch must not move the project
        # onto it; the live path would still report the branch the scans elect.
        resolved = _resolve_window(
            {
                "old": BranchWindowActivity(_one_scan_each(3), _days_ago(60)),
                "new": BranchWindowActivity(_one_scan_each(2), _days_ago(10)),
            },
            {"new": _fake_deltas("new", 2, 10)},
            {"_id": PROJECT},
        )
        assert (resolved.branch, resolved.status) == ("old", "pending")

    @pytest.mark.asyncio
    async def test_the_chosen_branch_is_reported_on_the_row(self):
        db = FakeDatabase()
        await _seed_scan(db, "d1", _days_ago(60), {"requests": "2.0.0"}, (), branch="develop")
        await _seed_scan(db, "d2", _days_ago(50), {"requests": "2.1.0"}, (), branch="develop")
        await _build_ledger(db)

        comparison = await _comparison(db, [PROJECT])

        assert comparison.projects[0].branch == "develop"

    @pytest.mark.asyncio
    async def test_a_busy_branch_beats_a_fresher_one_on_both_read_paths(self):
        db = FakeDatabase()
        for i, day in enumerate((80, 70, 60)):
            await _seed_scan(db, f"o{i}", _days_ago(day), {"requests": f"2.0.{i}"}, (), branch="old")
        for i, day in enumerate((20, 10)):
            await _seed_scan(db, f"n{i}", _days_ago(day), {"requests": f"9.0.{i}"}, (), branch="new")
        await _build_ledger(db)
        await _seed_projects(db, [PROJECT])

        live = await _live_comparison(db, [PROJECT])
        rolled = UpdateFrequencyComparison(
            **await _compute_comparison_from_rollup(db, [PROJECT], None, window_days=WINDOW_DAYS)
        )

        assert live.projects[0].branch == rolled.projects[0].branch == "old"
        assert live.projects[0].scan_count == rolled.projects[0].scan_count == 3

    @pytest.mark.asyncio
    async def test_a_ledger_that_only_reached_the_quiet_branch_does_not_switch_branches(self):
        db = FakeDatabase()
        for i, day in enumerate((80, 70, 60)):
            await _seed_scan(db, f"o{i}", _days_ago(day), {"requests": f"2.0.{i}"}, (), branch="old")
        for i, day in enumerate((20, 10)):
            await _seed_scan(db, f"n{i}", _days_ago(day), {"requests": f"9.0.{i}"}, (), branch="new")
        await _build_ledger(db)
        # The backfill got as far as one scan of the busy branch.
        await db.scan_update_deltas.delete_many({"_id": {"$in": ["o1", "o2"]}})

        comparison = await _comparison(db, [PROJECT])

        row = comparison.projects[0]
        assert (row.branch, row.data_status) == ("old", "insufficient_data")


async def _seed_series(
    db: FakeDatabase,
    project_id: str,
    package: str,
    count: int,
    *,
    outdated_at: int | None = None,
) -> None:
    """``count`` scans of one branch, one patch bump apart, newest 5 days back."""
    for i in range(count):
        outdated: tuple[str, ...] = (package,) if i == outdated_at else ()
        await _seed_scan(
            db,
            f"{project_id}-{i}",
            _days_ago(5 + (count - 1 - i) * 5),
            {package: f"3.0.{i}"},
            outdated,
            project_id=project_id,
        )


class TestPartialCoverage:
    @pytest.mark.asyncio
    async def test_a_window_the_ledger_only_partly_covers_is_partial_not_ready(self):
        # The measured state right after a deploy without a backfill: ten scans in
        # the window, deltas for the two newest.
        db = FakeDatabase()
        await _seed_series(db, PROJECT, "requests", 10)
        await _build_ledger(db)
        await db.scan_update_deltas.delete_many({"_id": {"$in": [f"{PROJECT}-{i}" for i in range(8)]}})

        comparison = await _comparison(db, [PROJECT])

        row = comparison.projects[0]
        assert row.data_status == "partial"
        # Exact for what it covers, and it says how little that is.
        assert (row.scan_count, row.total_updates) == (2, 1)
        assert comparison.partial_projects == 1

    @pytest.mark.asyncio
    async def test_the_ready_threshold_is_four_fifths_of_the_window(self):
        # The fold drops same-commit retries and SBOM-less scans on purpose, so a
        # small shortfall must not demote a healthy project while a large one must.
        for folded, expected in ((8, "ready"), (7, "partial")):
            db = FakeDatabase()
            await _seed_series(db, PROJECT, "requests", 10)
            await _build_ledger(db)
            await db.scan_update_deltas.delete_many({"_id": {"$in": [f"{PROJECT}-{i}" for i in range(10 - folded)]}})

            comparison = await _comparison(db, [PROJECT])

            assert (comparison.projects[0].scan_count, comparison.projects[0].data_status) == (folded, expected)

    @pytest.mark.asyncio
    async def test_a_partial_window_is_not_served_to_the_project_page(self):
        # UpdateFrequencyMetrics has no field for a caveat, so a partly folded
        # window would read as the whole one. The comparison holds the same row
        # back from its ranking; the project page instead falls back to the walk,
        # which reads the scans the ledger has not reached.
        db = FakeDatabase()
        await _seed_series(db, PROJECT, "requests", 10)
        await _build_ledger(db)
        await db.scan_update_deltas.delete_many({"_id": {"$in": [f"{PROJECT}-{i}" for i in range(8)]}})

        comparison = await _comparison(db, [PROJECT])

        assert (comparison.projects[0].data_status, comparison.projects[0].scan_count) == ("partial", 2)
        assert await _rollup(db) is None
        # What the fallback delivers instead of the ledger's two-scan stretch.
        assert (await _live(db)).scan_count == 10

    @pytest.mark.asyncio
    async def test_a_retry_heavy_project_is_fully_covered_on_both_paths(self):
        # Both paths give a same-commit run one bar, so coverage counts commits too.
        # Counting raw scans instead read a CI retry storm as missing data and dropped
        # a healthy project out of the ranking.
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, (), commit_hash="c1")
        for i, day in enumerate((50, 49, 48)):
            await _seed_scan(db, f"r{i}", _days_ago(day), {"requests": "2.1.0"}, (), commit_hash="c2")
        await _build_ledger(db)
        await _seed_projects(db, [PROJECT])

        live = await _live_comparison(db, [PROJECT])
        rolled = UpdateFrequencyComparison(
            **await _compute_comparison_from_rollup(db, [PROJECT], None, window_days=WINDOW_DAYS)
        )

        assert live.projects[0].data_status == rolled.projects[0].data_status == "ready"
        assert live.projects[0].scan_count == rolled.projects[0].scan_count == 2

    @pytest.mark.asyncio
    async def test_a_partial_row_never_reaches_the_averages_or_the_podium(self):
        db = FakeDatabase()
        # Fully covered, and nothing it flagged was ever resolved.
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ("requests",))
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.0.1"}, ("requests",))
        # Ten scans but only the newest two folded, with a spotless coverage record.
        await _seed_series(db, "proj-2", "flask", 10, outdated_at=8)
        await _build_ledger(db)
        await db.scan_update_deltas.delete_many({"_id": {"$in": [f"proj-2-{i}" for i in range(8)]}})

        comparison = await _comparison(db, [PROJECT, "proj-2"])

        ranked, held_back = comparison.projects
        assert (ranked.project_id, ranked.data_status) == (PROJECT, "ready")
        assert (held_back.project_id, held_back.data_status) == ("proj-2", "partial")
        assert held_back.update_coverage_pct == 100.0
        # Every one of these would move if the partial row were ranked with the rest.
        assert comparison.team_avg_coverage_pct == 0.0
        assert comparison.team_avg_updates_per_month == ranked.updates_per_month
        assert (comparison.best_project, comparison.worst_project) == ("Project proj-1", None)


async def _seed_storm(db: FakeDatabase, commits: int, retries: int) -> None:
    """``commits`` commits of one branch, each scanned ``retries`` times, one patch bump apart."""
    for i in range(commits * retries):
        await _seed_scan(
            db,
            f"s{i:04d}",
            _days_ago(80 - i * 0.02),
            {"requests": f"2.0.{i // retries}"},
            (),
            commit_hash=f"c{i // retries}",
        )


class TestWindowCap:
    """A branch busier than the document cap is truncated, not demoted."""

    @staticmethod
    async def _both(db: FakeDatabase, cap: int) -> tuple[UpdateFrequencyMetrics, UpdateFrequencyMetrics | None]:
        live = await _live(db, hard_limit=cap)
        with patch.object(endpoint, "WINDOW_HARD_LIMIT", cap):
            return live, await _rollup(db)

    @pytest.mark.asyncio
    async def test_both_paths_fold_the_same_newest_documents_when_the_cap_bites(self):
        db = FakeDatabase()
        await _seed_storm(db, commits=20, retries=1)
        await _build_ledger(db)

        live, rolled = await self._both(db, cap=10)

        _assert_same_metrics(live, rolled)
        assert live.scan_count == 10

    @pytest.mark.asyncio
    async def test_a_capped_branch_full_of_retries_is_not_demoted_out_of_the_ranking(self):
        # The cap counts documents on both paths, coverage counts commits: measuring the
        # truncated stretch against the whole window's commits made the rollup call this
        # partial while the live walk called it ready, over the very same scans.
        db = FakeDatabase()
        await _seed_storm(db, commits=10, retries=2)
        await _build_ledger(db)

        live, rolled = await self._both(db, cap=10)

        _assert_same_metrics(live, rolled)
        assert live.scan_count == 5

    @pytest.mark.parametrize(
        ("documents", "retries", "window_commits", "bars"),
        [(1200, 1, 1200, 1000), (1881, 2, 941, 501), (1881, 3, 627, 334)],
    )
    def test_the_largest_production_branches_stay_ready(
        self, documents: int, retries: int, window_commits: int, bars: int
    ) -> None:
        # 1881 scans is the largest project in production. Both paths read only the
        # newest WINDOW_HARD_LIMIT documents, which hold fewer commits than the window.
        deltas = _fake_deltas("main", documents, 1, retries=retries)
        assert len({d["commit_hash"] for d in deltas}) == window_commits

        resolved = _fold_branch("main", deltas, BranchWindowActivity(_one_scan_each(window_commits), _days_ago(1)))

        assert resolved.status == "ready"
        assert len(resolved.window) == min(documents, WINDOW_HARD_LIMIT)
        # A cap landing inside a run leaves that run a bar of its surviving members.
        assert len(resolved.bars) == bars

    def test_a_branch_under_the_cap_is_still_measured_against_its_own_commits(self) -> None:
        # The cap must not become a blanket amnesty: a ledger that reached three of ten
        # commits is partial however small the window is.
        deltas = _fake_deltas("main", 3, 1)

        resolved = _fold_branch("main", deltas, BranchWindowActivity(_one_scan_each(10), _days_ago(1)))

        assert resolved.status == "partial"


class TestComparisonRowDifferential:
    @pytest.mark.asyncio
    async def test_both_read_paths_report_the_same_ready_row(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"a": "1.0.0", "b": "1.0.0", "c": "1.0.0", "d": "1.0.0"}, ("a",))
        await _seed_scan(db, "s2", _days_ago(50), {"a": "1.0.1", "b": "1.0.1", "c": "1.0.1", "d": "1.1.0"}, ())
        await _build_ledger(db)
        await _seed_projects(db, [PROJECT])

        live = await _live_comparison(db, [PROJECT])
        rolled = UpdateFrequencyComparison(
            **await _compute_comparison_from_rollup(db, [PROJECT], None, window_days=WINDOW_DAYS)
        )

        assert live.projects[0].model_dump() == rolled.projects[0].model_dump()
        # Three of four forward updates are patches; no other field of this row
        # carries 0.75, so a row reporting another tier's share is visible here.
        assert (live.projects[0].patch_ratio, rolled.projects[0].patch_ratio) == (0.75, 0.75)
        assert (live.projects[0].total_updates, live.projects[0].update_coverage_pct) == (4, 100.0)


class TestScopeAndTeams:
    @pytest.mark.asyncio
    async def test_projects_outside_the_scope_are_not_read(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        await _seed_scan(db, "x1", _days_ago(60), {"flask": "3.0.0"}, (), project_id="proj-other")
        await _seed_scan(db, "x2", _days_ago(50), {"flask": "3.1.0"}, (), project_id="proj-other")
        await _build_ledger(db)

        comparison = await _comparison(db, [PROJECT])

        assert [p.project_id for p in comparison.projects] == [PROJECT]

    @pytest.mark.asyncio
    async def test_rows_carry_the_team_name(self):
        db = FakeDatabase()
        await db.teams.insert_one({"_id": "team-1", "name": "Platform"})
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        await _build_ledger(db)

        comparison = await _comparison(db, [PROJECT], team_id="team-1")

        assert comparison.projects[0].team_name == "Platform"


async def _seed_projects(db: FakeDatabase, project_ids: list[str], team_id: str | None = None) -> None:
    for project_id in project_ids:
        await db.projects.insert_one(
            {
                "_id": project_id,
                "name": f"Project {project_id}",
                "team_id": team_id,
                "default_branch": None,
                "deleted_branches": [],
            }
        )


async def _comparison(
    db: FakeDatabase, project_ids: list[str], team_id: str | None = None
) -> UpdateFrequencyComparison:
    await _seed_projects(db, project_ids, team_id)
    payload = await _compute_comparison_from_rollup(db, project_ids, team_id, window_days=WINDOW_DAYS)
    return UpdateFrequencyComparison(**payload)


async def _live_comparison(db: FakeDatabase, project_ids: list[str]) -> UpdateFrequencyComparison:
    """The same endpoint with the flag off: the live walk over every scan."""
    payload = await _compute_comparison(db, project_ids, None, window_days=WINDOW_DAYS)
    return UpdateFrequencyComparison(**payload)
