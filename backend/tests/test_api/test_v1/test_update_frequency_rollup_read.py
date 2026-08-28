"""The rollup read path, checked against the live path it replaces.

The differential tests run one scan history twice: once through
``compute_update_frequency``, which walks every scan, and once through the
delta ledger plus fold. Where the two disagree by design, the test says so.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.api.v1.endpoints.analytics.update_frequency import (
    _compute_comparison_from_rollup,
    _pick_branch,
    _resolve_window,
    _rollup_project_metrics,
)
from app.repositories import AnalysisResultRepository, DependencyRepository, ScanRepository
from app.schemas.analytics import UpdateFrequencyComparison, UpdateFrequencyMetrics
from app.services.update_frequency import compute_update_frequency
from app.services.update_frequency_rollup import record_scan_update_delta
from tests.mocks.fake_mongo import FakeDatabase

PROJECT = "proj-1"
BRANCH = "main"
WINDOW_DAYS = 90

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


async def _live(db: FakeDatabase, project: dict[str, Any] | None = None) -> UpdateFrequencyMetrics:
    project = project or _project()
    return await compute_update_frequency(
        project_id=str(project["_id"]),
        project_name=project["name"],
        scan_repo=ScanRepository(db),
        dep_repo=DependencyRepository(db),
        analysis_repo=AnalysisResultRepository(db),
        window_days=WINDOW_DAYS,
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
    async def test_same_commit_retries_collapse_in_both_paths(self):
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
    async def test_a_window_without_scans_falls_back_to_the_live_path(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(300), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(290), {"requests": "2.1.0"}, ())
        await _build_ledger(db)

        live = await _live(db)

        assert await _rollup(db) is None
        assert live.scan_count == 0


class TestDifferentialSbomLessScans:
    @pytest.mark.asyncio
    async def test_the_rollup_bridges_the_gap_the_live_path_reads_as_quiet(self):
        # A scan that produced no SBOM is a missing measurement, not a scan
        # without updates: the live path counts two zero-update intervals
        # around it, the rollup compares across it.
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {}, ())
        await _seed_scan(db, "s3", _days_ago(40), {"requests": "2.1.0"}, ())
        await _build_ledger(db)

        live = await _live(db)
        rolled = await _rollup(db)

        assert rolled is not None
        assert live.scan_count == 3
        assert live.total_updates == 0
        assert rolled.scan_count == 2
        assert rolled.total_updates == 1
        assert rolled.minor_updates == 1


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
        assert (row.branch, row.scan_count, row.updates_per_month, row.total_updates) == (None, None, None, None)
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

        assert comparison.projects == []
        assert comparison.pending_projects == 0
        assert comparison.skipped_insufficient_data == 1

    @pytest.mark.asyncio
    async def test_a_single_in_window_scan_is_insufficient_data(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _build_ledger(db)

        comparison = await _comparison(db, [PROJECT])

        assert comparison.projects == []
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

        assert comparison.projects == []
        assert comparison.skipped_error == 1
        assert comparison.skipped_insufficient_data == 0

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
    async def test_a_scope_of_only_pending_projects_reports_no_averages(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())

        comparison = await _comparison(db, [PROJECT])

        assert comparison.team_avg_updates_per_month is None
        assert comparison.team_avg_coverage_pct is None
        assert comparison.best_project is None
        assert comparison.worst_project is None


def _fake_deltas(branch: str, count: int, newest_days_ago: float) -> list[dict[str, Any]]:
    """A linked chain of usable deltas, oldest first, as the repository hands it over."""
    ids = [f"{branch}-{i}" for i in range(count)]
    return [
        {
            "_id": scan_id,
            "project_id": PROJECT,
            "branch": branch,
            "scan_created_at": _days_ago(newest_days_ago + count - 1 - i),
            "commit_hash": f"c-{scan_id}",
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
    def test_the_default_branch_wins_when_it_can_be_folded(self):
        branches = {"main": _fake_deltas("main", 2, 1), "develop": _fake_deltas("develop", 3, 1)}
        windows = {name: list(deltas) for name, deltas in branches.items()}
        assert _pick_branch(branches, windows, "main", []) == "main"

    def test_a_default_branch_with_too_little_history_yields_to_the_busiest(self):
        branches = {"main": _fake_deltas("main", 1, 1), "develop": _fake_deltas("develop", 3, 1)}
        windows = {name: list(deltas) for name, deltas in branches.items()}
        assert _pick_branch(branches, windows, "main", []) == "develop"

    def test_a_deleted_default_branch_is_never_chosen(self):
        branches = {"main": _fake_deltas("main", 3, 1), "develop": _fake_deltas("develop", 2, 1)}
        windows = {name: list(deltas) for name, deltas in branches.items()}
        assert _pick_branch(branches, windows, "main", ["main"]) == "develop"

    def test_a_tie_on_delta_count_goes_to_the_branch_scanned_last(self):
        branches = {"old": _fake_deltas("old", 2, 20), "fresh": _fake_deltas("fresh", 2, 2)}
        windows = {name: list(deltas) for name, deltas in branches.items()}
        assert _pick_branch(branches, windows, None, []) == "fresh"

    def test_a_project_whose_only_branches_are_deleted_resolves_to_nothing(self):
        resolved = _resolve_window(
            {"gone": _fake_deltas("gone", 3, 2)},
            {"_id": PROJECT, "deleted_branches": ["gone"]},
        )
        assert (resolved.branch, resolved.status) == (None, "insufficient_data")

    @pytest.mark.asyncio
    async def test_the_chosen_branch_is_reported_on_the_row(self):
        db = FakeDatabase()
        await _seed_scan(db, "d1", _days_ago(60), {"requests": "2.0.0"}, (), branch="develop")
        await _seed_scan(db, "d2", _days_ago(50), {"requests": "2.1.0"}, (), branch="develop")
        await _build_ledger(db)

        comparison = await _comparison(db, [PROJECT])

        assert comparison.projects[0].branch == "develop"


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


async def _comparison(
    db: FakeDatabase, project_ids: list[str], team_id: str | None = None
) -> UpdateFrequencyComparison:
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
    payload = await _compute_comparison_from_rollup(db, project_ids, team_id, window_days=WINDOW_DAYS)
    return UpdateFrequencyComparison(**payload)
