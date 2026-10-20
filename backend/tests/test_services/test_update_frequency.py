import asyncio
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

import app.services.update_frequency as update_frequency_module
from app.core.purl import parse_purl
from app.core.constants import RECENT_UPDATES_LIMIT, SLOWEST_PACKAGES_LIMIT
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.dependencies import DependencyRepository
from app.repositories.scans import ScanRepository
from app.repositories.update_frequency import (
    BranchWindowActivity,
)
from app.schemas.analytics import ProjectUpdateSummary, ScanTimelineEntry, UpdateFrequencyMetrics
from app.services.release_history import ReleaseHistory, ReleaseInfo
from app.services.update_frequency import (
    _COMPARISON_CONCURRENCY,
    READY_COVERAGE_RATIO,
    _build_slowest_packages,
    classify_version_change,
    compute_trend,
    compute_update_frequency,
    compute_update_frequency_comparison,
    elect_primary_branch,
    load_outdated_entries,
    rank_summaries,
    select_primary_branch,
    summarise_window,
    window_coverage_status,
    window_cutoff,
)
from app.services.update_frequency_rollup import record_scan_update_delta
from tests.helpers.update_frequency import rollup_metrics
from tests.mocks.fake_mongo import FakeDatabase


def _make_timeline_entry(idx: int, updates: int = 0, outdated: int = 0) -> ScanTimelineEntry:
    return ScanTimelineEntry(
        scan_id=f"scan-{idx}",
        date=datetime(2026, 1, idx + 1, tzinfo=timezone.utc).isoformat(),
        updates_count=updates,
        outdated_count=outdated,
        patch=updates,
        minor=0,
        major=0,
    )


class TestClassifyVersionChange:
    def test_major_bump(self):
        assert classify_version_change("1.0.0", "2.0.0") == "major"

    def test_minor_bump(self):
        assert classify_version_change("1.0.0", "1.1.0") == "minor"

    def test_patch_bump(self):
        assert classify_version_change("1.0.0", "1.0.1") == "patch"

    def test_v_prefix_accepted(self):
        assert classify_version_change("v1.0.0", "v1.0.1") == "patch"

    def test_unparseable_returns_unknown(self):
        assert classify_version_change("abc123", "def456") == "unknown"

    @pytest.mark.parametrize(
        ("old", "new"),
        [
            ("5.3.10.RELEASE", "5.3.9.RELEASE"),
            ("33.0.0-jre", "32.1.3-jre"),
            ("v0.0.0-20220101000000-aaaaaaaaaaaa", "v0.0.0-20210101000000-bbbbbbbbbbbb"),
            ("1.2.3-1ubuntu1", "1.2.3-1"),
        ],
    )
    def test_a_rollback_outside_pep_440_is_a_downgrade(self, old: str, new: str):
        assert classify_version_change(old, new) == "downgrade"

    def test_a_respelling_outside_pep_440_is_no_change(self):
        assert classify_version_change("4.1.100.Final", "4.1.100") == "none"

    def test_a_forward_move_outside_pep_440_stays_unknown(self):
        assert classify_version_change("5.3.9.RELEASE", "5.3.10.RELEASE") == "unknown"

    def test_commit_hashes_are_not_ordered(self):
        # Their letters sort at random, so ordering them would book half of all pin bumps as downgrades.
        old, new = "8f4b7f84864484a7bf31766abe9204da3cbe65b3", "a8eba0b27e820071cde6df949e0beb9ba4906955"
        assert classify_version_change(old, new) == "unknown"

    def test_identical_versions_returns_none(self):
        assert classify_version_change("1.0.0", "1.0.0") == "none"

    def test_identical_with_v_prefix_returns_none(self):
        assert classify_version_change("v1.0.0", "1.0.0") == "none"

    def test_stable_to_prerelease_is_downgrade(self):
        assert classify_version_change("1.0.0", "1.0.0-beta1") == "downgrade"

    def test_major_rollback_is_downgrade(self):
        assert classify_version_change("2.0.0", "1.0.0") == "downgrade"

    def test_minor_rollback_is_downgrade(self):
        assert classify_version_change("1.5.0", "1.4.0") == "downgrade"

    def test_patch_rollback_is_downgrade(self):
        assert classify_version_change("1.0.1", "1.0.0") == "downgrade"

    def test_epoch_bump_is_major(self):
        # An epoch bump resets the release tuple; treat it as the biggest possible jump.
        assert classify_version_change("2024.01.15", "1!1.0.0") == "major"

    def test_epoch_bump_to_lower_release_is_still_major(self):
        # The epoch dominates: 1.0.0 -> 1!0.5.0 moves forward despite the lower tuple.
        assert classify_version_change("1.0.0", "1!0.5.0") == "major"

    def test_epoch_rollback_is_downgrade(self):
        assert classify_version_change("1!1.0.0", "2.0.0") == "downgrade"

    def test_prerelease_to_stable_is_not_no_change(self):
        # 1.0.0-beta1 -> 1.0.0 is a real change (graduation), must not be "none"
        result = classify_version_change("1.0.0-beta1", "1.0.0")
        assert result != "none"
        assert result in ("patch", "prerelease")

    def test_prerelease_to_different_prerelease(self):
        result = classify_version_change("1.0.0-beta1", "1.0.0-beta2")
        assert result != "none"
        assert result in ("patch", "prerelease")

    def test_prerelease_to_higher_patch(self):
        assert classify_version_change("1.0.0-beta1", "1.0.1") == "patch"

    def test_prerelease_to_higher_major(self):
        assert classify_version_change("1.0.0-beta1", "2.0.0") == "major"

    def test_short_version_strings(self):
        assert classify_version_change("1.0", "1.1") == "minor"

    def test_single_component_version(self):
        assert classify_version_change("1", "2") == "major"

    def test_hash_based_versions_unknown(self):
        # Git SHA / build hash version strings cannot be ordered semantically.
        assert classify_version_change("abc1234", "def5678") == "unknown"

    def test_calver_classified_by_release_tuple(self):
        # CalVer maps onto the release tuple via packaging.Version; pinned so regex tweaks cannot change it.
        assert classify_version_change("2024.01.15", "2024.02.01") == "minor"
        assert classify_version_change("2024.01.15", "2025.01.15") == "major"
        assert classify_version_change("2024.01.15", "2024.01.16") == "patch"

    def test_post_release_kept_as_change(self):
        # A PEP 440 post-release comes after the release, so it is a change, not "none".
        result = classify_version_change("1.0.0", "1.0.0.post1")
        assert result != "none"

    def test_local_version_segment_kept_as_change(self):
        # Local versions (1.0.0+build123) are common in private registries.
        result = classify_version_change("1.0.0", "1.0.0+build123")
        assert result != "none"


def _baseline_entry() -> ScanTimelineEntry:
    # Orchestrator timelines always start with the no-predecessor baseline scan.
    return _make_timeline_entry(0, updates=0, outdated=5)


class TestComputeTrend:
    def test_empty_timeline_returns_unknown(self):
        direction, _ = compute_trend([])
        assert direction == "unknown"

    def test_four_scans_returns_unknown(self):
        # Baseline + 3 real entries is still too little signal.
        timeline = [_baseline_entry()] + [_make_timeline_entry(i + 1, updates=2) for i in range(3)]
        direction, detail = compute_trend(timeline)
        assert direction == "unknown"
        assert "enough" in detail.lower()

    def test_consistent_rate_returns_stable(self):
        timeline = [_baseline_entry()] + [_make_timeline_entry(i + 1, updates=2, outdated=5) for i in range(4)]
        direction, _ = compute_trend(timeline)
        assert direction == "stable"

    def test_constant_rate_never_improving_regardless_of_length(self):
        # The structural zero of the baseline entry must not fabricate acceleration.
        for n in (4, 6, 9, 19):
            timeline = [_baseline_entry()] + [_make_timeline_entry(i + 1, updates=3, outdated=7) for i in range(n)]
            direction, _ = compute_trend(timeline)
            assert direction == "stable", f"length {n} classified {direction}"

    def test_improving_trend(self):
        timeline = (
            [_baseline_entry()]
            + [_make_timeline_entry(i + 1, updates=1, outdated=10) for i in range(3)]
            + [_make_timeline_entry(i + 4, updates=10, outdated=10) for i in range(3)]
        )
        direction, _ = compute_trend(timeline)
        assert direction == "improving"

    def test_conflicting_signals_return_stable(self):
        # Updates accelerate while the outdated backlog grows: not "improving".
        timeline = (
            [_baseline_entry()]
            + [_make_timeline_entry(i + 1, updates=1, outdated=2) for i in range(3)]
            + [_make_timeline_entry(i + 4, updates=10, outdated=30) for i in range(3)]
        )
        direction, detail = compute_trend(timeline)
        assert direction == "stable"
        assert "Updates/scan" in detail
        assert "Outdated" in detail


class TestSummariseWindowCoverage:
    def test_coverage_none_when_no_outdated(self):
        m = summarise_window([_make_timeline_entry(0), _make_timeline_entry(30)], Counter(), set(), set(), None, None)
        assert m.update_coverage_pct is None
        assert m.total_outdated_detected == 0
        assert m.outdated_resolved == 0

    def test_coverage_pct_when_outdated_resolved(self):
        m = summarise_window(
            [_make_timeline_entry(0), _make_timeline_entry(30)], Counter(), {"pkg-a", "pkg-b"}, {"pkg-a"}, None, None
        )
        assert m.update_coverage_pct == 50.0
        assert m.total_outdated_detected == 2
        assert m.outdated_resolved == 1


def _seeded(collection: str, docs: list[dict[str, Any]]) -> FakeDatabase:
    """A database holding ``docs`` as given; insert_one would truncate their datetimes to milliseconds."""
    db = FakeDatabase()
    db[collection]._docs.update({doc["_id"]: doc for doc in docs})
    return db


class FakeScanRepo(ScanRepository):
    def __init__(self, scans: list[dict[str, Any]]):
        super().__init__(_seeded("scans", scans))


class FakeDepRepo(DependencyRepository):
    def __init__(self, deps_by_scan: dict[str, list[dict[str, Any]]]):
        docs = [
            {**dep, "_id": f"{scan_id}:{index}", "scan_id": scan_id}
            for scan_id, deps in deps_by_scan.items()
            for index, dep in enumerate(deps)
        ]
        super().__init__(_seeded(self.collection_name, docs))


class FakeAnalysisRepo(AnalysisResultRepository):
    def __init__(self, results: list[dict[str, Any]]):
        docs = [{"_id": f"result-{index}", **result} for index, result in enumerate(results)]
        super().__init__(_seeded(self.collection_name, docs))
        self.queries: list[dict[str, Any]] = []
        find = self.collection.find

        # Hooked on the collection so a read through any inherited repository method is recorded too.
        def recording_find(query: dict[str, Any] | None = None, *args: Any, **kwargs: Any) -> Any:
            self.queries.append(query or {})
            return find(query, *args, **kwargs)

        self.collection.find = recording_find


async def _compute(scans, deps, results=(), **kwargs: Any) -> UpdateFrequencyMetrics:
    return await compute_update_frequency(
        **{
            "project_id": "proj-1",
            "project_name": "Project",
            "branch": "main",
            "scan_repo": FakeScanRepo(scans),
            "dep_repo": FakeDepRepo(deps),
            "analysis_repo": FakeAnalysisRepo(list(results)),
        }
        | kwargs
    )


async def _compare(projects, scans, deps, results=(), **kwargs: Any):
    return await compute_update_frequency_comparison(
        projects, FakeScanRepo(scans), FakeDepRepo(deps), FakeAnalysisRepo(list(results)), **kwargs
    )


_BASE_SCAN_DATE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _make_scan(
    scan_id: str,
    day_offset: int,
    project_id: str = "proj-1",
    branch: str = "main",
    is_rescan: bool = False,
    commit_hash: str | None = None,
) -> dict[str, Any]:
    return {
        "_id": scan_id,
        "created_at": _BASE_SCAN_DATE + timedelta(days=day_offset),
        "status": "completed",
        "project_id": project_id,
        "branch": branch,
        "is_rescan": is_rescan,
        "commit_hash": commit_hash,
    }


def _two_scans() -> list[dict[str, Any]]:
    return [_make_scan("s1", 0), _make_scan("s2", 30)]


def _scan_days_ago(scan_id: str, days: float, **overrides: Any) -> dict[str, Any]:
    """A scan placed relative to now, so a ``window_days`` cutoff includes or excludes it."""
    return _make_scan(scan_id, 0, **overrides) | {"created_at": datetime.now(tz=timezone.utc) - timedelta(days=days)}


def _recent_scans(count: int, spacing_days: int = 1) -> list[dict[str, Any]]:
    now = datetime.now(tz=timezone.utc)
    scans = [_make_scan(f"s{i}", i) for i in range(count)]
    for i, scan in enumerate(scans):
        scan["created_at"] = now - timedelta(days=(count - 1 - i) * spacing_days)
    return scans


def _make_dep(scan_id: str, name: str, version: str, ptype: str = "pypi") -> dict[str, Any]:
    return {
        "scan_id": scan_id,
        "name": name,
        "version": version,
        "type": ptype,
        "purl": f"pkg:{ptype}/{name}@{version}",
    }


def _outdated_result(scan_id: str, entries: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "scan_id": scan_id,
        "analyzer_name": "outdated_packages",
        "result": {"outdated_dependencies": entries},
    }


def _one_scan_each(commit_count: int) -> dict[str, int]:
    return {f"commit-{index}": 1 for index in range(commit_count)}


def _activity(branches: dict[str, tuple[int, int]]) -> dict[str, BranchWindowActivity]:
    """``branch -> (scans in the window, day offset of its newest scan)``."""
    return {
        branch: BranchWindowActivity(_one_scan_each(count), _BASE_SCAN_DATE + timedelta(days=day))
        for branch, (count, day) in branches.items()
    }


class TestSelectPrimaryBranch:
    """One rule for both read paths: the branch that carries the project's history."""

    def test_a_project_without_any_scanned_branch_has_none(self):
        assert select_primary_branch({}, "main", []) is None

    def test_the_default_branch_wins_at_the_two_scan_minimum(self):
        activity = _activity({"main": (2, 1), "develop": (9, 2)})
        assert select_primary_branch(activity, "main", []) == "main"

    def test_a_default_branch_scanned_once_yields_to_the_busiest_branch(self):
        activity = _activity({"main": (1, 5), "develop": (3, 1)})
        assert select_primary_branch(activity, "main", []) == "develop"

    def test_a_deleted_default_branch_is_never_chosen(self):
        activity = _activity({"main": (5, 5), "develop": (2, 1)})
        assert select_primary_branch(activity, "main", ["main"]) == "develop"

    def test_deleted_branches_drop_out_of_the_fallback_too(self):
        activity = _activity({"gone": (9, 5), "develop": (2, 1)})
        assert select_primary_branch(activity, None, ["gone"]) == "develop"

    def test_a_project_whose_branches_are_all_deleted_has_none(self):
        assert select_primary_branch(_activity({"gone": (9, 5)}), None, ["gone"]) is None

    def test_the_busiest_branch_wins_over_the_most_recently_scanned_one(self):
        # The rule both paths promise: a single fresh scan must not hijack a project.
        activity = _activity({"old": (3, 0), "new": (2, 70)})
        assert select_primary_branch(activity, None, []) == "old"

    def test_a_tie_on_scan_count_goes_to_the_branch_scanned_last(self):
        activity = _activity({"stale": (2, 1), "fresh": (2, 30)})
        assert select_primary_branch(activity, None, []) == "fresh"

    def test_a_full_tie_is_broken_by_name_rather_than_by_input_order(self):
        activity = _activity({"alpha": (2, 5), "beta": (2, 5)})
        reversed_activity = dict(reversed(list(activity.items())))
        assert select_primary_branch(activity, None, []) == select_primary_branch(reversed_activity, None, []) == "beta"


class TestWindowCoverageStatus:
    def test_full_coverage_is_ready(self):
        assert window_coverage_status(10, 10) == "ready"

    def test_the_drop_the_fold_makes_on_purpose_still_reads_as_ready(self):
        # Same-commit retries and SBOM-less scans are dropped by design.
        assert window_coverage_status(9, 10) == "ready"

    def test_a_window_the_backfill_barely_reached_is_partial(self):
        # The measured post-deploy state: deltas for only the two newest of ten scans.
        assert window_coverage_status(2, 10) == "partial"

    def test_the_threshold_is_the_documented_ratio(self):
        assert window_coverage_status(80, 100) == "ready"
        assert window_coverage_status(79, 100) == "partial"
        assert READY_COVERAGE_RATIO == 0.8

    def test_more_analyzed_scans_than_the_window_counted_is_ready(self):
        # A scan can land between the two reads; that is not a coverage gap.
        assert window_coverage_status(3, 2) == "ready"


class TestBranchScopedScanSelection:
    @staticmethod
    async def _compute_elected(scans, deps, *, default_branch=None, deleted_branches=None, **kwargs):
        scan_repo = FakeScanRepo(scans)
        if "branch" not in kwargs:
            since = window_cutoff(kwargs.get("window_days"))
            kwargs["branch"] = await elect_primary_branch(scan_repo, "proj-1", since, default_branch, deleted_branches)
        return await _compute(scans, deps, scan_repo=scan_repo, **kwargs)

    @pytest.mark.asyncio
    async def test_mixed_branch_history_analyzes_only_primary_branch(self):
        # Feature-branch scans interleave with main and only they bump pkg-a; unscoped, this counts 4 updates.
        scans = [
            _make_scan("m1", 0, branch="main"),
            _make_scan("f1", 1, branch="feature"),
            _make_scan("m2", 2, branch="main"),
            _make_scan("f2", 3, branch="feature"),
            _make_scan("m3", 4, branch="main"),
        ]
        deps = {
            "m1": [_make_dep("m1", "pkg-a", "1.0.0")],
            "f1": [_make_dep("f1", "pkg-a", "2.0.0")],
            "m2": [_make_dep("m2", "pkg-a", "1.0.0")],
            "f2": [_make_dep("f2", "pkg-a", "2.0.0")],
            "m3": [_make_dep("m3", "pkg-a", "1.0.0")],
        }
        m = await self._compute_elected(scans, deps)
        assert m.branch == "main"
        assert m.scan_count == 3
        assert m.total_updates == 0

    @pytest.mark.asyncio
    async def test_default_branch_preferred_over_newest_scan_branch(self):
        # A single newer feature-branch scan must not hijack a configured default_branch with ample history.
        scans = [
            _make_scan("m1", 0, branch="main"),
            _make_scan("m2", 1, branch="main"),
            _make_scan("m3", 2, branch="main"),
            _make_scan("f1", 3, branch="feature"),
        ]
        deps = {
            "m1": [_make_dep("m1", "pkg-a", "1.0.0")],
            "m2": [_make_dep("m2", "pkg-a", "1.1.0")],
            "m3": [_make_dep("m3", "pkg-a", "1.2.0")],
            "f1": [_make_dep("f1", "pkg-a", "9.0.0")],
        }
        m = await self._compute_elected(scans, deps, default_branch="main")
        assert m.branch == "main"
        assert m.scan_count == 3

    @pytest.mark.asyncio
    async def test_default_branch_wins_at_the_two_scan_minimum(self):
        # Two scans is the least history that keeps default_branch; one fewer falls back.
        scans = [
            _make_scan("m1", 0, branch="main"),
            _make_scan("m2", 1, branch="main"),
            _make_scan("f1", 2, branch="feature"),
        ]
        deps = {
            "m1": [_make_dep("m1", "pkg-a", "1.0.0")],
            "m2": [_make_dep("m2", "pkg-a", "1.0.1")],
            "f1": [_make_dep("f1", "pkg-a", "9.0.0")],
        }
        m = await self._compute_elected(scans, deps, default_branch="main")
        assert m.branch == "main"
        assert m.scan_count == 2
        assert m.total_updates == 1

    @pytest.mark.asyncio
    async def test_default_branch_ignored_when_too_sparse(self):
        scans = [
            _make_scan("d1", 0, branch="release"),
            _make_scan("m1", 1, branch="main"),
            _make_scan("m2", 2, branch="main"),
        ]
        deps = {
            "m1": [_make_dep("m1", "pkg-a", "1.0.0")],
            "m2": [_make_dep("m2", "pkg-a", "1.0.1")],
        }
        m = await self._compute_elected(scans, deps, default_branch="release")
        assert m.branch == "main"
        assert m.scan_count == 2

    @pytest.mark.asyncio
    async def test_rescans_excluded_from_the_analyzed_branch_timeline(self):
        scans = [
            _make_scan("m1", 0, branch="main"),
            _make_scan("m2", 1, branch="main"),
            _make_scan("r1", 2, branch="main", is_rescan=True),
        ]
        deps = {
            "m1": [_make_dep("m1", "pkg-a", "1.0.0")],
            "m2": [_make_dep("m2", "pkg-a", "1.0.1")],
            "r1": [_make_dep("r1", "pkg-a", "0.5.0")],
        }
        m = await self._compute_elected(scans, deps, branch="main")
        assert m.scan_count == 2
        assert all(e.new_version != "0.5.0" for e in m.recent_updates)

    @pytest.mark.asyncio
    async def test_head_commit_storm_does_not_starve_window(self):
        # The newest max_scans scans all share the head commit; distinct older commits must still fill the window.
        scans = [_make_scan(f"h{i}", 100 + i, commit_hash="head") for i in range(5)]
        scans += [_make_scan(f"c{i}", i, commit_hash=f"c{i}") for i in range(5)]
        deps: dict[str, list[dict[str, Any]]] = {}
        for i in range(5):
            deps[f"h{i}"] = [_make_dep(f"h{i}", "pkg-a", "2.0.0")]
        for i in range(5):
            deps[f"c{i}"] = [_make_dep(f"c{i}", "pkg-a", f"1.0.{i}")]
        m = await self._compute_elected(scans, deps, branch="main", max_scans=5)
        # max_scans counts bars, so the storm takes one of the five and leaves four commits.
        assert m.scan_count == 5
        assert m.total_updates == 4

    @pytest.mark.asyncio
    async def test_explicit_branch_parameter_wins(self):
        scans = [
            _make_scan("m1", 0, branch="main"),
            _make_scan("f1", 1, branch="feature"),
            _make_scan("f2", 2, branch="feature"),
            _make_scan("m2", 3, branch="main"),
        ]
        deps = {
            "f1": [_make_dep("f1", "pkg-a", "1.0.0")],
            "f2": [_make_dep("f2", "pkg-a", "1.1.0")],
        }
        m = await self._compute_elected(scans, deps, branch="feature")
        assert m.branch == "feature"
        assert m.scan_count == 2
        assert m.minor_updates == 1

    @pytest.mark.asyncio
    async def test_rescans_are_excluded(self):
        # The newest scan is a rescan with a stale snapshot, so it drives neither branch nor timeline.
        scans = [
            _make_scan("m1", 0, branch="main"),
            _make_scan("m2", 1, branch="main"),
            _make_scan("r1", 2, branch="feature", is_rescan=True),
        ]
        deps = {
            "m1": [_make_dep("m1", "pkg-a", "1.0.0")],
            "m2": [_make_dep("m2", "pkg-a", "1.0.1")],
            "r1": [_make_dep("r1", "pkg-a", "0.9.0")],
        }
        m = await self._compute_elected(scans, deps)
        assert m.branch == "main"
        assert m.scan_count == 2
        assert m.total_updates == 1
        assert all(e.new_version != "0.9.0" for e in m.recent_updates)

    @pytest.mark.asyncio
    async def test_a_single_fresh_scan_on_another_branch_does_not_hijack_the_project(self):
        # The branch that was scanned most owns the numbers, not the newest one.
        scans = [_scan_days_ago(f"o{i}", 80 - i * 10, branch="old") for i in range(3)]
        scans += [_scan_days_ago(f"n{i}", 20 - i * 10, branch="new") for i in range(2)]
        deps = {s["_id"]: [_make_dep(s["_id"], "pkg-a", "1.0.0")] for s in scans}

        m = await self._compute_elected(scans, deps, window_days=90)

        assert m.branch == "old"
        assert m.scan_count == 3

    @pytest.mark.asyncio
    async def test_the_default_branch_needs_its_two_scans_inside_the_window(self):
        # release was busy only before the window, so its whole history must not count inside it.
        scans = [_scan_days_ago(f"r{i}", 200 + i, branch="release") for i in range(10)]
        scans.append(_scan_days_ago("r-recent", 30, branch="release"))
        scans += [_scan_days_ago(f"m{i}", 60 - i * 10, branch="main") for i in range(3)]
        deps = {s["_id"]: [_make_dep(s["_id"], "pkg-a", "1.0.0")] for s in scans}

        m = await self._compute_elected(scans, deps, window_days=90, default_branch="release")

        assert m.branch == "main"
        assert m.scan_count == 3

    @pytest.mark.asyncio
    async def test_deleted_branches_excluded_from_auto_resolution(self):
        scans = [
            _make_scan("m1", 0, branch="main"),
            _make_scan("m2", 1, branch="main"),
            _make_scan("d1", 2, branch="gone"),
        ]
        deps = {
            "m1": [_make_dep("m1", "pkg-a", "1.0.0")],
            "m2": [_make_dep("m2", "pkg-a", "1.0.1")],
        }
        m = await self._compute_elected(scans, deps, deleted_branches=["gone"])
        assert m.branch == "main"
        assert m.scan_count == 2

    @pytest.mark.asyncio
    async def test_a_textual_created_at_drops_the_scan(self):
        # A restored scan can carry created_at as text, which the window aggregation skips, so parsing must too.
        scans = [
            {**_make_scan("s1", 0), "created_at": "2026-01-01T00:00:00Z"},
            {**_make_scan("s2", 30), "created_at": "whenever"},
            _make_scan("s3", 60),
            _make_scan("s4", 90),
        ]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.5.0")],
            "s3": [_make_dep("s3", "pkg-a", "2.0.0")],
            "s4": [_make_dep("s4", "pkg-a", "2.0.1")],
        }
        m = await self._compute_elected(scans, deps)
        assert m.scan_count == 2
        assert [e.scan_id for e in m.scan_timeline] == ["s3", "s4"]
        assert m.total_updates == 1

    @pytest.mark.asyncio
    async def test_a_branch_dated_only_in_text_does_not_win_the_scan_count_view(self):
        # The walk cannot date these scans, so electing their busier branch would leave the view empty.
        scans = [
            {**_make_scan(f"r{i}", i, branch="restored"), "created_at": f"2026-02-0{i + 1}T00:00:00Z"} for i in range(3)
        ]
        scans += [_make_scan("m1", 10), _make_scan("m2", 20)]
        deps = {s["_id"]: [_make_dep(s["_id"], "pkg-a", "1.0.0")] for s in scans}

        m = await self._compute_elected(scans, deps)

        assert (m.branch, m.scan_count) == ("main", 2)

    @pytest.mark.asyncio
    async def test_a_same_commit_scan_storm_becomes_one_bar(self):
        # 5 CI runs of one commit within a day, then a real new commit.
        scans = [
            _make_scan("s0", 0, commit_hash="aaa"),
            *[_make_scan(f"s{i}", 0, commit_hash="bbb") for i in range(1, 6)],
            _make_scan("s6", 1, commit_hash="ccc"),
        ]
        deps = {"s0": [_make_dep("s0", "pkg-a", "1.0.0")]}
        for i in range(1, 6):
            deps[f"s{i}"] = [_make_dep(f"s{i}", "pkg-a", "1.0.1")]
        deps["s6"] = [_make_dep("s6", "pkg-a", "1.1.0")]
        m = await self._compute_elected(scans, deps)
        assert m.scan_count == 3
        assert [e.scan_id for e in m.scan_timeline] == ["s0", "s5", "s6"]
        # The storm's own bump lands on the bar its run named, not on the run's first try.
        assert [e.updates_count for e in m.scan_timeline] == [0, 1, 1]
        assert m.total_updates == 2


class TestIdentityKeying:
    @staticmethod
    def _raw_dep(scan_id: str, name: str, version: str, purl: str, ptype: str = "library") -> dict[str, Any]:
        return {"scan_id": scan_id, "name": name, "version": version, "type": ptype, "purl": purl}

    @pytest.mark.asyncio
    async def test_same_name_different_namespaces_do_not_collide(self):
        # Two maven groups both shipping "jackson-core"; document order flips between scans.
        old_core = self._raw_dep(
            "s1", "jackson-core", "2.21.4", "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.21.4"
        )
        new_core = self._raw_dep("s1", "jackson-core", "3.1.4", "pkg:maven/tools.jackson.core/jackson-core@3.1.4")
        deps = {
            "s1": [old_core, new_core],
            "s2": [
                {**new_core, "scan_id": "s2"},
                {**old_core, "scan_id": "s2"},
            ],
        }
        m = await _compute(_two_scans(), deps)
        assert m.total_updates == 0

    @pytest.mark.asyncio
    async def test_duplicate_identity_survivor_is_order_independent(self):
        # Same package twice per scan (nested dependency trees); insertion order flips.
        v1 = self._raw_dep("s1", "lodash", "1.0.0", "pkg:npm/lodash@1.0.0")
        v2 = self._raw_dep("s1", "lodash", "2.0.0", "pkg:npm/lodash@2.0.0")
        deps = {
            "s1": [v1, v2],
            "s2": [{**v2, "scan_id": "s2"}, {**v1, "scan_id": "s2"}],
        }
        m = await _compute(_two_scans(), deps)
        assert m.total_updates == 0

    @pytest.mark.asyncio
    async def test_a_duplicate_outside_pep_440_keeps_its_highest_version(self):
        purl = "pkg:maven/org.springframework/spring-core@{}"
        older = self._raw_dep("s1", "spring-core", "5.3.9.RELEASE", purl.format("5.3.9.RELEASE"))
        newer = self._raw_dep("s1", "spring-core", "5.3.10.RELEASE", purl.format("5.3.10.RELEASE"))
        deps = {"s1": [older, newer], "s2": [{**newer, "scan_id": "s2"}]}

        m = await _compute(_two_scans(), deps)

        assert m.total_updates == 0

    @pytest.mark.asyncio
    async def test_a_maven_flip_flop_counts_one_update_not_two(self):
        purl = "pkg:maven/org.springframework/spring-core@{}"
        versions = ("5.3.10.RELEASE", "5.3.9.RELEASE", "5.3.10.RELEASE")
        deps = {
            f"s{i}": [self._raw_dep(f"s{i}", "spring-core", version, purl.format(version))]
            for i, version in enumerate(versions, start=1)
        }

        m = await _compute([_make_scan("s1", 0), _make_scan("s2", 10), _make_scan("s3", 20)], deps)

        assert (m.total_updates, m.downgrade_updates, m.unknown_updates) == (1, 1, 1)

    @pytest.mark.asyncio
    async def test_pypi_name_variants_are_one_identity(self):
        # PEP 503 equivalent names (case/underscore/dot) must not read as remove+add.
        deps = {
            "s1": [self._raw_dep("s1", "My_Package", "1.0.0", "pkg:pypi/My_Package@1.0.0")],
            "s2": [self._raw_dep("s2", "my-package", "1.1.0", "pkg:pypi/my-package@1.1.0")],
        }
        m = await _compute(_two_scans(), deps)
        assert m.total_updates == 1
        assert m.recent_updates[0].update_type == "minor"

    @pytest.mark.parametrize(
        ("before", "after", "updates"),
        [
            ("pkg:pypi/PyYAML@6.0", "pkg:pypi/pyyaml@6.0.1", 1),
            ("pkg:pypi/zope.interface@5.0", "pkg:pypi/zope-interface@5.1", 1),
            ("pkg:NPM/x@1.0.0", "pkg:npm/x@1.0.1", 1),
            ("pkg:maven/g1/core@1.0", "pkg:maven/g2/core@1.1", 0),
        ],
    )
    @pytest.mark.asyncio
    async def test_a_respelled_package_is_a_version_bump(self, before, after, updates):
        def dep(scan_id: str, purl: str) -> dict[str, Any]:
            return self._raw_dep(scan_id, parse_purl(purl).name, parse_purl(purl).version, purl)

        m = await _compute(_two_scans(), {"s1": [dep("s1", before)], "s2": [dep("s2", after)]})

        assert m.total_updates == updates

    @pytest.mark.asyncio
    async def test_deps_without_purl_key_by_name_and_type(self):
        deps = {
            "s1": [{"scan_id": "s1", "name": "internal-lib", "version": "1.0.0", "type": "internal", "purl": ""}],
            "s2": [{"scan_id": "s2", "name": "internal-lib", "version": "1.0.1", "type": "internal", "purl": ""}],
        }
        m = await _compute(_two_scans(), deps)
        assert m.total_updates == 1
        assert m.recent_updates[0].package_name == "internal-lib"
        assert m.recent_updates[0].update_type == "patch"

    @pytest.mark.asyncio
    async def test_scoped_npm_packages_do_not_collide(self):
        # Ingest stores npm names without their scope; purls keep it.
        deps = {
            "s1": [
                self._raw_dep("s1", "cdk", "21.0.0", "pkg:npm/%40angular/cdk@21.0.0"),
                self._raw_dep("s1", "core", "21.0.0", "pkg:npm/%40angular/core@21.0.0"),
                self._raw_dep("s1", "core", "7.0.0", "pkg:npm/%40babel/core@7.0.0"),
            ],
            "s2": [
                self._raw_dep("s2", "cdk", "21.2.0", "pkg:npm/%40angular/cdk@21.2.0"),
                self._raw_dep("s2", "core", "21.0.0", "pkg:npm/%40angular/core@21.0.0"),
                self._raw_dep("s2", "core", "7.0.0", "pkg:npm/%40babel/core@7.0.0"),
            ],
        }
        m = await _compute(_two_scans(), deps)
        assert m.total_updates == 1
        assert m.recent_updates[0].package_name == "@angular/cdk"
        assert m.recent_updates[0].update_type == "minor"


class TestOutdatedTracking:
    @pytest.mark.asyncio
    async def test_multi_sbom_outdated_results_are_unioned(self):
        # The engine writes one outdated_packages row per SBOM of a scan.
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0"), _make_dep("s1", "pkg-b", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.0"), _make_dep("s2", "pkg-b", "1.0.0")],
        }
        results = [
            _outdated_result("s1", [{"component": "pkg-a", "current_version": "1.0.0", "latest_version": "2.0.0"}]),
            _outdated_result("s1", [{"component": "pkg-b", "current_version": "1.0.0", "latest_version": "3.0.0"}]),
        ]
        m = await _compute(_two_scans(), deps, results)
        assert m.total_outdated_detected == 2
        assert m.scan_timeline[0].outdated_count == 2

    @pytest.mark.asyncio
    async def test_update_while_still_outdated_is_not_resolved(self):
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.1.0")],
        }
        results = [
            _outdated_result("s1", [{"component": "pkg-a", "current_version": "1.0.0", "latest_version": "3.0.0"}]),
            _outdated_result("s2", [{"component": "pkg-a", "current_version": "1.1.0", "latest_version": "3.0.0"}]),
        ]
        m = await _compute(_two_scans(), deps, results)
        assert m.outdated_resolved == 0
        assert m.update_coverage_pct == 0.0

    @pytest.mark.asyncio
    async def test_resolution_requires_leaving_outdated_set(self):
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "3.0.0")],
        }
        results = [
            _outdated_result("s1", [{"component": "pkg-a", "current_version": "1.0.0", "latest_version": "3.0.0"}]),
            _outdated_result("s2", []),
        ]
        m = await _compute(_two_scans(), deps, results)
        assert m.outdated_resolved == 1
        assert m.update_coverage_pct == 100.0

    @pytest.mark.asyncio
    async def test_removed_package_is_not_resolved(self):
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0"), _make_dep("s1", "pkg-b", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-b", "1.0.0")],
        }
        results = [
            _outdated_result("s1", [{"component": "pkg-a", "current_version": "1.0.0", "latest_version": "3.0.0"}]),
            _outdated_result("s2", []),
        ]
        m = await _compute(_two_scans(), deps, results)
        assert m.outdated_resolved == 0
        assert m.update_coverage_pct == 0.0


_BACKLOG = ("pkg-a", "pkg-b", "pkg-c")


def _backlog_deps(scan_id: str) -> list[dict[str, Any]]:
    return [_make_dep(scan_id, name, "1.0.0") for name in _BACKLOG]


def _backlog_outdated(scan_id: str, names: Sequence[str] = _BACKLOG) -> dict[str, Any]:
    return _outdated_result(
        scan_id,
        [{"component": name, "current_version": "1.0.0", "latest_version": "9.0.0"} for name in names],
    )


class TestUnmeasuredScans:
    """A scan without the outdated analysis has an unknown backlog, not an empty one."""

    @pytest.mark.asyncio
    async def test_missing_final_analysis_is_not_a_cleared_backlog(self):
        # Identical dependency sets: nothing updated, so nothing can have been resolved.
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {sid: _backlog_deps(sid) for sid in ("s1", "s2")}
        m = await _compute(scans, deps, [_backlog_outdated("s1")])
        assert m.total_updates == 0
        assert m.total_outdated_detected == 3
        assert m.outdated_resolved == 0
        assert m.update_coverage_pct == 0.0
        assert [e.outdated_count for e in m.scan_timeline] == [3, None]

    @pytest.mark.asyncio
    async def test_coverage_is_none_when_no_scan_measured_a_backlog(self):
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {sid: _backlog_deps(sid) for sid in ("s1", "s2")}
        m = await _compute(scans, deps, [])
        assert m.update_coverage_pct is None
        assert m.total_outdated_detected == 0
        assert [e.outdated_count for e in m.scan_timeline] == [None, None]

    @pytest.mark.asyncio
    async def test_resolution_across_a_measurement_gap_is_not_credited(self):
        # pkg-b and pkg-c leave the backlog across a scan without analysis, so the transition was never observed.
        scans = [_make_scan("s1", 0), _make_scan("s2", 30), _make_scan("s3", 60)]
        deps = {
            "s1": [*_backlog_deps("s1"), _make_dep("s1", "churn", "1.0.0")],
            "s2": [*_backlog_deps("s2"), _make_dep("s2", "churn", "1.0.0")],
            "s3": [*_backlog_deps("s3"), _make_dep("s3", "churn", "1.1.0")],
        }
        results = [_backlog_outdated("s1"), _backlog_outdated("s3", ["pkg-a"])]
        m = await _compute(scans, deps, results)
        assert m.total_outdated_detected == 3
        assert m.outdated_resolved == 0
        assert m.update_coverage_pct == 0.0
        assert [e.outdated_count for e in m.scan_timeline] == [3, None, 1]
        # churn was updated out of the gap: its predecessor's backlog is unknown, not empty.
        assert m.total_updates == 1
        assert m.recent_updates[0].was_outdated is False

    @pytest.mark.asyncio
    async def test_backlog_stays_listed_when_the_newest_scan_is_unmeasured(self):
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {sid: _backlog_deps(sid) for sid in ("s1", "s2")}
        m = await _compute(scans, deps, [_backlog_outdated("s1")])
        assert sorted(p.name for p in m.slowest_packages) == list(_BACKLOG)
        assert {p.latest_version for p in m.slowest_packages} == {"9.0.0"}

    @pytest.mark.asyncio
    async def test_an_unmeasured_last_scan_does_not_read_as_a_shrinking_backlog(self):
        backlog = [f"pkg-{i}" for i in range(10)]
        scans = [_make_scan(f"s{i}", i * 7) for i in range(6)]
        deps = {
            f"s{i}": [_make_dep(f"s{i}", name, "1.0.0") for name in backlog] + [_make_dep(f"s{i}", "churn", f"1.0.{i}")]
            for i in range(6)
        }
        # The newest scan ran without the analyzer; the backlog never moved.
        results = [_backlog_outdated(f"s{i}", backlog) for i in range(5)]
        m = await _compute(scans, deps, results)
        assert [e.outdated_count for e in m.scan_timeline] == [10, 10, 10, 10, 10, None]
        assert m.trend_direction == "stable"
        assert "~10 outdated" in m.trend_detail


class TestFailedLookups:
    """A package whose deps.dev lookup failed went unmeasured; the rest of its scan did not."""

    @staticmethod
    async def _walk_and_ledger(
        flagged: dict[str, list[str]], failed: dict[str, list[str]]
    ) -> tuple[UpdateFrequencyMetrics, UpdateFrequencyMetrics]:
        db = FakeDatabase()
        for index, (scan_id, names) in enumerate(flagged.items()):
            await db.scans.insert_one(_scan_days_ago(scan_id, 30 * (len(flagged) - 1 - index)))
            await db.dependencies.insert_many(
                [{"_id": f"{scan_id}:{name}", **_make_dep(scan_id, name, "1.0.0")} for name in (*_BACKLOG, "flaky")]
            )
            analysis = _backlog_outdated(scan_id, names)
            if lost := failed.get(scan_id):
                analysis["result"] |= {"partial_components_skipped": len(lost), "lookup_failed_components": lost}
            await db.analysis_results.insert_one({"_id": f"{scan_id}:outdated", **analysis})
            await record_scan_update_delta(db, scan_id)

        live = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=ScanRepository(db),
            dep_repo=DependencyRepository(db),
            analysis_repo=AnalysisResultRepository(db),
            branch="main",
            window_days=90,
        )
        project = {"_id": "proj-1", "name": "Project", "default_branch": None, "deleted_branches": []}
        rolled = await rollup_metrics(db, project, 90)
        assert rolled is not None
        return live, rolled

    @pytest.mark.asyncio
    async def test_a_package_whose_lookup_always_fails_leaves_the_backlog_measured(self):
        flagged = {"s1": list(_BACKLOG), "s2": ["pkg-b", "pkg-c"], "s3": ["pkg-b"]}

        live, rolled = await self._walk_and_ledger(flagged, failed={scan_id: ["flaky"] for scan_id in flagged})

        for metrics in (live, rolled):
            assert (metrics.update_coverage_pct, metrics.outdated_resolved) == (66.7, 2)
            assert [e.outdated_count for e in metrics.scan_timeline] == [3, 2, 1]
        assert (live.outdated_backlog, [p.name for p in live.slowest_packages]) == (1, ["pkg-b"])

    @pytest.mark.asyncio
    async def test_an_outdated_package_whose_lookup_failed_is_not_resolved(self):
        # deps.dev failed for pkg-b in s2 only, and s3 shows it still outdated.
        flagged = {"s1": list(_BACKLOG), "s2": ["pkg-c"], "s3": ["pkg-b"]}

        live, rolled = await self._walk_and_ledger(flagged, failed={"s2": ["pkg-b"]})

        for metrics in (live, rolled):
            assert (metrics.update_coverage_pct, metrics.outdated_resolved) == (66.7, 2)
            assert [e.outdated_count for e in metrics.scan_timeline] == [3, 1, 1]


class TestAggregationAccuracy:
    @pytest.mark.asyncio
    async def test_downgrades_are_not_counted_as_updates(self):
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "2.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.0")],
        }
        m = await _compute(scans, deps)
        assert m.total_updates == 0
        assert m.downgrade_updates == 1
        assert m.scan_timeline[1].updates_count == 0
        assert m.scan_timeline[1].downgrades == 1
        # Still visible in the event list, labeled as what it is.
        assert m.recent_updates[0].update_type == "downgrade"

    @pytest.mark.asyncio
    async def test_subday_precision_in_time_range(self):
        # 36h between scans must count as 1.5 days, not truncate to 1.
        scans = [
            _make_scan("s1", 0),
            {**_make_scan("s2", 1), "created_at": _BASE_SCAN_DATE + timedelta(hours=36)},
        ]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.1")],
        }
        m = await _compute(scans, deps)
        assert m.time_range_days == pytest.approx(1.5)

    @staticmethod
    async def _one_update_over(hours: int, window_days: int | None):
        now = datetime.now(tz=timezone.utc)
        scans = [
            {**_make_scan("s1", 0), "created_at": now - timedelta(hours=hours)},
            {**_make_scan("s2", 1), "created_at": now},
        ]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.1")],
        }
        return await _compute(scans, deps, window_days=window_days, hard_limit=10)

    @pytest.mark.asyncio
    async def test_the_monthly_rate_measures_the_window_not_the_scan_cadence(self):
        fast = await self._one_update_over(36, window_days=None)
        slow = await self._one_update_over(24 * 60, window_days=None)
        # No window: extrapolating one update would give the fast project 20/month, the slow one 0.5/month.
        assert fast.updates_per_month is None
        assert slow.updates_per_month is None

    @pytest.mark.asyncio
    async def test_the_monthly_rate_is_the_same_for_both_cadences_in_one_window(self):
        # window_days is only the rate denominator here; both scan pairs fall inside the cutoff.
        expected = round(1 / (90 / 30.44), 2)
        assert (await self._one_update_over(36, window_days=90)).updates_per_month == expected
        assert (await self._one_update_over(24 * 60, window_days=90)).updates_per_month == expected

    @pytest.mark.asyncio
    async def test_slowest_packages_only_lists_still_outdated_with_fresh_versions(self):
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0"), _make_dep("s1", "pkg-b", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "3.0.0"), _make_dep("s2", "pkg-b", "1.2.0")],
        }
        results = [
            _outdated_result(
                "s1",
                [
                    {"component": "pkg-a", "current_version": "1.0.0", "latest_version": "3.0.0"},
                    {"component": "pkg-b", "current_version": "1.0.0", "latest_version": "9.9.9"},
                ],
            ),
            _outdated_result(
                "s2",
                [{"component": "pkg-b", "current_version": "1.0.0", "latest_version": "9.9.9"}],
            ),
        ]
        m = await _compute(scans, deps, results)
        names = [p.name for p in m.slowest_packages]
        assert names == ["pkg-b"]  # pkg-a was resolved; only remaining backlog is listed
        assert m.slowest_packages[0].current_version == "1.2.0"  # from the final scan, not stale analyzer data

    @pytest.mark.asyncio
    async def test_avg_cadence_is_not_floored_for_subday_histories(self):
        scans = [
            _make_scan("s1", 0),
            {**_make_scan("s2", 1), "created_at": _BASE_SCAN_DATE + timedelta(hours=12)},
        ]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.1")],
        }
        m = await _compute(scans, deps)
        assert m.avg_days_between_scans == 0.5

    @pytest.mark.asyncio
    async def test_slowest_current_version_not_borrowed_from_same_name_sibling(self):
        # Two npm packages stored as bare "core", one outdated; the backlog row must not show the sibling's version.
        def _npm(scan_id: str, scope: str, version: str) -> dict[str, Any]:
            return {
                "scan_id": scan_id,
                "name": "core",
                "version": version,
                "type": "library",
                "purl": f"pkg:npm/%40{scope}/core@{version}",
            }

        deps = {
            "s1": [_npm("s1", "babel", "7.0.0"), _npm("s1", "angular", "21.0.0")],
            "s2": [_npm("s2", "babel", "7.0.0"), _npm("s2", "angular", "21.2.0")],
        }
        results = [
            _outdated_result("s1", [{"component": "core", "current_version": "7.0.0", "latest_version": "7.5.0"}]),
            _outdated_result("s2", [{"component": "core", "current_version": "7.0.0", "latest_version": "7.5.0"}]),
        ]
        m = await _compute(_two_scans(), deps, results)
        assert m.slowest_packages[0].name == "core"
        assert m.slowest_packages[0].current_version == "7.0.0"

    @pytest.mark.asyncio
    async def test_package_types_use_purl_ecosystem(self):
        # CycloneDX stores type "library"; the ecosystem must come from the purl.
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {
            "s1": [
                {
                    "scan_id": "s1",
                    "name": "jackson-core",
                    "version": "2.0.0",
                    "type": "library",
                    "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.0.0",
                }
            ],
            "s2": [
                {
                    "scan_id": "s2",
                    "name": "jackson-core",
                    "version": "2.1.0",
                    "type": "library",
                    "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.1.0",
                }
            ],
        }
        m = await _compute(scans, deps)
        assert m.dominant_ecosystem == "maven"
        assert m.recent_updates[0].package_type == "maven"

    @pytest.mark.asyncio
    async def test_dominant_ecosystem_is_what_the_newest_scan_holds(self):
        # Packages the project dropped two scans ago must not keep it "mixed" after a migration.
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {
            "s1": [_make_dep("s1", f"js{i}", "1.0.0", "npm") for i in range(4)],
            "s2": [_make_dep("s2", "js0", "1.0.0", "npm")] + [_make_dep("s2", f"py{i}", "1.0.0") for i in range(4)],
        }
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
            branch="main",
        )
        assert m.dominant_ecosystem == "pypi"


class TestStreamingOrchestrator:
    @pytest.mark.asyncio
    async def test_basic_two_scan_history(self):
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0"), _make_dep("s1", "pkg-b", "2.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.1"), _make_dep("s2", "pkg-b", "3.0.0")],
        }
        m = await _compute(scans, deps)

        assert m.scan_count == 2
        assert m.total_updates == 2
        assert m.patch_updates == 1  # pkg-a 1.0.0 -> 1.0.1
        assert m.major_updates == 1  # pkg-b 2.0.0 -> 3.0.0

    @pytest.mark.asyncio
    async def test_recent_updates_capped_at_30(self):
        # Every dep changes in each of 50 scans; recent_updates keeps only the last 30 events.
        scans = [_make_scan(f"s{i}", i) for i in range(50)]
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")] for i in range(50)}
        m = await _compute(scans, deps, max_scans=100)

        assert m.scan_count == 50
        assert m.total_updates == 49  # 50 scans -> 49 transitions
        assert len(m.recent_updates) == 30
        # newest first
        assert m.recent_updates[0].new_version == "1.0.49"

    @pytest.mark.asyncio
    async def test_default_takes_newest_scans_not_oldest(self):
        scans = [_make_scan(f"s{i}", i) for i in range(30)]
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")] for i in range(30)}
        m = await _compute(scans, deps, max_scans=5)

        assert m.scan_count == 5
        # The newest 5 scans must drive recent_updates (1.0.26..1.0.29), not the oldest 5 (1.0.1..1.0.4).
        latest_versions = {e.new_version for e in m.recent_updates}
        assert "1.0.29" in latest_versions
        assert "1.0.0" not in latest_versions

    @pytest.mark.asyncio
    async def test_window_days_filters_scans(self):
        # Twenty scans two days apart; an 11-day window holds the newest six.
        scans = _recent_scans(20, spacing_days=2)
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")] for i in range(20)}

        m = await _compute(scans, deps, window_days=11)

        assert m.scan_count == 6
        assert m.total_updates == 5

    @pytest.mark.asyncio
    async def test_observations_bounded_for_high_churn_history(self):
        # 200 scans x 5 packages = 1000 (pkg, version) pairs, which the orchestrator must handle bounded.
        scans = [_make_scan(f"s{i}", i) for i in range(200)]
        deps: dict[str, list[dict[str, Any]]] = {}
        for i in range(200):
            deps[f"s{i}"] = [_make_dep(f"s{i}", f"pkg-{p}", f"1.{i}.{p}") for p in range(5)]
        m = await _compute(scans, deps, max_scans=200)
        assert m.scan_count == 200
        assert m.total_updates == 199 * 5

    @pytest.mark.asyncio
    async def test_a_single_scan_supports_no_comparison(self):
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo([_make_scan("s1", 0)]),
            dep_repo=FakeDepRepo({"s1": [_make_dep("s1", "pkg-a", "1.0.0")]}),
            analysis_repo=FakeAnalysisRepo([]),
            branch="main",
        )
        assert (m.scan_count, m.branch, m.trend_direction, m.update_coverage_pct) == (1, "main", "unknown", None)
        assert m.first_scan_date == m.last_scan_date == _BASE_SCAN_DATE.isoformat()
        assert m.scan_timeline == []

    @pytest.mark.asyncio
    async def test_no_release_fetcher_yields_none_upstream_metrics(self):
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.1")],
        }
        m = await _compute(scans, deps)
        assert m.upstream_releases_last_12m_median is None
        assert m.upstream_days_between_releases_median is None
        assert m.upstream_days_since_latest_release_median is None
        assert m.adoption_latency_days_median is None

    @pytest.mark.asyncio
    async def test_a_rollback_to_an_old_version_is_no_adoption(self):
        """Returning to a years-old release must not add years to the adoption latency."""
        scans = [_scan_days_ago("s1", 60), _scan_days_ago("s2", 30), _scan_days_ago("s3", 0)]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "2.0.0")],
            "s3": [_make_dep("s3", "pkg-a", "1.0.0")],
        }
        history: ReleaseHistory = {
            ("pypi", "pkg-a"): [
                ReleaseInfo(version="1.0.0", published_at=scans[0]["created_at"] - timedelta(days=1400)),
                ReleaseInfo(version="2.0.0", published_at=scans[1]["created_at"] - timedelta(days=12)),
            ],
        }
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
            branch="main",
            release_fetcher=SimpleNamespace(fetch=AsyncMock(return_value=history)),
        )
        assert m.downgrade_updates == 1
        assert m.adoption_latency_days_median == 12.0

    @pytest.mark.asyncio
    async def test_release_fetcher_populates_upstream_metrics(self):
        # One update, pkg-a 1.0.0 -> 1.0.1; upstream 1.0.0 is 100d older than scan 0, 1.0.1 20d older than scan 1.
        scans = [_scan_days_ago("s1", 30), _scan_days_ago("s2", 0)]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.1")],
        }
        scan0_date = scans[0]["created_at"]
        scan1_date = scans[1]["created_at"]
        history: ReleaseHistory = {
            ("pypi", "pkg-a"): [
                ReleaseInfo(version="1.0.0", published_at=scan0_date - timedelta(days=100)),
                ReleaseInfo(version="1.0.1", published_at=scan1_date - timedelta(days=20)),
            ],
        }

        class FakeFetcher:
            def __init__(self, h: ReleaseHistory):
                self._h = h
                self.calls: list[Sequence[tuple[str, str]]] = []

            async def fetch(self, packages: Sequence[tuple[str, str]]) -> ReleaseHistory:
                self.calls.append(list(packages))
                return self._h

        fetcher = FakeFetcher(history)
        m = await _compute(scans, deps, release_fetcher=fetcher)

        # 1.0.1 came out 20d before scan 1; 1.0.0's first appearance predates the window, so it is not counted.
        assert m.adoption_latency_days_median == 20.0

        # The window uses the real clock, so the scans end at now and both releases (130d, 20d old) count.
        assert m.upstream_releases_last_12m_median == 2.0

        assert m.upstream_days_since_latest_release_median == 20.0

        assert len(fetcher.calls) == 1
        assert ("pypi", "pkg-a") in fetcher.calls[0]

    @pytest.mark.asyncio
    async def test_window_overrides_max_scans_when_it_holds_more(self):
        # 30 daily scans, max_scans=5, a window spanning them all (hard_limit-bounded load).
        scans = _recent_scans(30)
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")] for i in range(30)}

        m = await _compute(scans, deps, max_scans=5, window_days=40)
        assert m.scan_count == 30, "the calendar window should trump max_scans when it contains more scans"

    @pytest.mark.asyncio
    async def test_hard_limit_caps_runaway_queries(self):
        # 2500 scans inside the window, so only the hard_limit cap stops a whole-collection load.
        scans = _recent_scans(2500)
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")] for i in range(2500)}

        m = await _compute(scans, deps, max_scans=5, window_days=3000, hard_limit=100)
        assert m.scan_count == 100
        # And the response says so: every number above covers 100 of the branch's 2500 scans.
        assert m.window_scan_cap == 100

    @pytest.mark.asyncio
    async def test_a_window_read_whole_names_no_cap(self):
        scans = _recent_scans(30)
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")] for i in range(30)}

        m = await _compute(scans, deps, max_scans=5, window_days=3000, hard_limit=100)

        assert m.window_scan_cap is None

    @staticmethod
    def _two_scan_project(pid: str, pkg: str, versions: tuple[str, str]) -> tuple[list, dict]:
        # Inside the comparison's calendar window, which it ranks over.
        now = datetime.now(tz=timezone.utc)
        scans = [_make_scan(f"{pid}-s1", 0, project_id=pid), _make_scan(f"{pid}-s2", 30, project_id=pid)]
        scans[0]["created_at"] = now - timedelta(days=30)
        scans[1]["created_at"] = now
        deps = {
            f"{pid}-s1": [_make_dep(f"{pid}-s1", pkg, versions[0])],
            f"{pid}-s2": [_make_dep(f"{pid}-s2", pkg, versions[1])],
        }
        return scans, deps

    @pytest.mark.asyncio
    async def test_unmeasured_coverage_ranks_after_measured(self):
        # proj-a measures 100% coverage; proj-b, never outdated, has None and must not outrank or beat it.
        scans_a, deps_a = self._two_scan_project("proj-a", "pkg-a", ("1.0.0", "3.0.0"))
        scans_b, deps_b = self._two_scan_project("proj-b", "pkg-b", ("1.0.0", "1.0.1"))
        results = [
            _outdated_result(
                "proj-a-s1", [{"component": "pkg-a", "current_version": "1.0.0", "latest_version": "3.0.0"}]
            ),
        ]

        result = await _compare(
            [{"_id": "proj-b", "name": "Unmeasured"}, {"_id": "proj-a", "name": "Measured"}],
            scans_a + scans_b,
            {**deps_a, **deps_b},
            results,
        )

        assert [p.project_name for p in result.projects] == ["Measured", "Unmeasured"]
        assert result.best_project == "Measured"
        # A single measured project cannot be both best and worst.
        assert result.worst_project is None
        assert result.skipped_insufficient_data == 0

    @pytest.mark.asyncio
    async def test_all_unmeasured_yields_no_best_worst_and_null_avg(self):
        scans_a, deps_a = self._two_scan_project("proj-a", "pkg-a", ("1.0.0", "1.0.1"))
        scans_b, deps_b = self._two_scan_project("proj-b", "pkg-b", ("1.0.0", "1.0.1"))

        result = await _compare(
            [{"_id": "proj-a", "name": "A"}, {"_id": "proj-b", "name": "B"}], scans_a + scans_b, {**deps_a, **deps_b}
        )

        assert result.best_project is None
        assert result.worst_project is None
        assert result.team_avg_coverage_pct is None

    @pytest.mark.asyncio
    async def test_projects_without_enough_scans_are_counted_as_skipped(self):
        scans_a, deps_a = self._two_scan_project("proj-a", "pkg-a", ("1.0.0", "1.0.1"))
        single_scan = [_make_scan("proj-c-s1", 0, project_id="proj-c")]
        single_scan[0]["created_at"] = datetime.now(tz=timezone.utc)

        result = await _compare(
            [{"_id": "proj-a", "name": "A"}, {"_id": "proj-c", "name": "C"}], scans_a + single_scan, deps_a
        )

        assert [(p.project_name, p.data_status) for p in result.projects] == [
            ("A", "ready"),
            ("C", "insufficient_data"),
        ]
        assert result.skipped_insufficient_data == 1

    @pytest.mark.asyncio
    async def test_a_project_whose_summary_cannot_be_built_is_counted_rather_than_lost(self):
        # The summary is built outside the per-project guard, so its failure must not drop the project.
        scans_a, deps_a = self._two_scan_project("proj-a", "pkg-a", ("1.0.0", "1.0.1"))
        scans_b, deps_b = self._two_scan_project("proj-b", "pkg-b", ("2.0.0", "2.1.0"))
        projects = [{"_id": "proj-a", "name": "A"}, {"_id": "proj-b", "name": "B"}]

        real_compute = update_frequency_module.compute_update_frequency

        async def _bad_ratio_for_b(**kwargs):
            metrics = await real_compute(**kwargs)
            if kwargs["project_id"] == "proj-b":
                # Survives here and fails only when the summary is built, outside the guard.
                metrics.granularity_ratio = {"patch": "not a number"}
            return metrics

        with patch.object(update_frequency_module, "compute_update_frequency", _bad_ratio_for_b):
            result = await _compare(projects, scans_a + scans_b, {**deps_a, **deps_b})

        assert {p.project_name for p in result.projects} == {"A", "B"}
        assert result.skipped_error == 1

    @pytest.mark.asyncio
    async def test_outdated_loaded_per_pair_not_upfront(self):
        scans = [_make_scan(f"s{i}", i) for i in range(5)]
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", "1.0.0")] for i in range(5)}
        results = [_outdated_result(f"s{i}", []) for i in range(5)]

        analysis_repo = FakeAnalysisRepo(results)

        await _compute(scans, deps, analysis_repo=analysis_repo)

        assert [q.get("scan_id") for q in analysis_repo.queries] == [f"s{i}" for i in range(5)]

    @pytest.mark.asyncio
    async def test_completed_filter_applied_before_limit(self):
        # The newest scans all failed, so status must be filtered in the query for completed ones to surface.
        completed = [_make_scan(f"c{i}", i) for i in range(6)]  # days 0..5, completed
        failed = [
            {**_make_scan(f"f{i}", 10 + i), "status": "failed"} for i in range(20)
        ]  # days 10..29, failed -> these are the newest 20
        scans = completed + failed
        deps = {f"c{i}": [_make_dep(f"c{i}", "pkg-a", f"1.0.{i}")] for i in range(6)}
        m = await _compute(scans, deps, max_scans=20)

        assert m.scan_count == 6, "completed scans must survive the fetch limit even when the newest scans failed"
        assert m.total_updates == 5

    @pytest.mark.asyncio
    async def test_maven_upstream_uses_deps_dev_name(self):
        # Maven rows store only the artifact, but deps.dev needs group:artifact, so observations are re-keyed.
        def _maven_dep(scan_id: str, version: str) -> dict[str, Any]:
            return {
                "scan_id": scan_id,
                "name": "log4j-core",  # DB name = artifact only
                "version": version,
                "type": "maven",
                "purl": f"pkg:maven/org.apache.logging.log4j/log4j-core@{version}",
            }

        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {"s1": [_maven_dep("s1", "2.14.0")], "s2": [_maven_dep("s2", "2.17.0")]}
        scan1_date = scans[1]["created_at"]
        registry_name = "org.apache.logging.log4j:log4j-core"
        history: ReleaseHistory = {
            ("maven", registry_name): [
                ReleaseInfo(version="2.14.0", published_at=scans[0]["created_at"] - timedelta(days=100)),
                ReleaseInfo(version="2.17.0", published_at=scan1_date - timedelta(days=15)),
            ],
        }

        class FakeFetcher:
            def __init__(self, h: ReleaseHistory):
                self._h = h
                self.calls: list[Sequence[tuple[str, str]]] = []

            async def fetch(self, packages: Sequence[tuple[str, str]]) -> ReleaseHistory:
                self.calls.append(list(packages))
                return self._h

        fetcher = FakeFetcher(history)
        m = await _compute(scans, deps, release_fetcher=fetcher)

        assert ("maven", registry_name) in fetcher.calls[0]
        assert ("maven", "log4j-core") not in fetcher.calls[0]
        # Observations re-keyed to the deps.dev name -> adoption latency resolves (15d).
        assert m.adoption_latency_days_median == 15.0

    @pytest.mark.asyncio
    async def test_an_ecosystem_deps_dev_does_not_serve_is_never_requested(self):
        def _composer_dep(scan_id: str, version: str) -> dict[str, Any]:
            return {
                "scan_id": scan_id,
                "name": "framework",
                "version": version,
                "type": "library",
                "purl": f"pkg:composer/laravel/framework@{version}",
            }

        class FakeFetcher:
            def __init__(self):
                self.calls: list[Sequence[tuple[str, str]]] = []

            async def fetch(self, packages: Sequence[tuple[str, str]]) -> ReleaseHistory:
                self.calls.append(list(packages))
                return {}

        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {"s1": [_composer_dep("s1", "10.0.0")], "s2": [_composer_dep("s2", "10.1.0")]}
        fetcher = FakeFetcher()
        await _compute(scans, deps, release_fetcher=fetcher)

        assert fetcher.calls == []

    def test_comparison_semaphore_reusable_across_event_loops(self):
        # A module-global semaphore binds to the first loop; reproducing needs more projects than the limit.
        n_projects = _COMPARISON_CONCURRENCY + 2  # 5 > concurrency limit of 3

        class _SuspendingScanRepo(FakeScanRepo):
            async def find_many_raw(self, *args, **kwargs):
                await asyncio.sleep(0)  # yield to the loop while holding the semaphore
                return await super().find_many_raw(*args, **kwargs)

        class _SuspendingDepRepo(FakeDepRepo):
            async def find_all_raw(self, *args, **kwargs):
                await asyncio.sleep(0)
                return await super().find_all_raw(*args, **kwargs)

        projects = [{"_id": f"proj-{i}", "name": f"Project {i}"} for i in range(n_projects)]
        all_scans: list[dict[str, Any]] = []
        deps: dict[str, list[dict[str, Any]]] = {}
        for i in range(n_projects):
            pid = f"proj-{i}"
            s1, s2 = f"{pid}-s1", f"{pid}-s2"
            now = datetime.now(tz=timezone.utc)
            all_scans.append(_make_scan(s1, 0, project_id=pid) | {"created_at": now - timedelta(days=30)})
            all_scans.append(_make_scan(s2, 30, project_id=pid) | {"created_at": now})
            deps[s1] = [_make_dep(s1, "pkg-a", "1.0.0")]
            deps[s2] = [_make_dep(s2, "pkg-a", "1.0.1")]

        async def _run():
            return await compute_update_frequency_comparison(
                projects=projects,
                scan_repo=_SuspendingScanRepo(all_scans),
                dep_repo=_SuspendingDepRepo(deps),
                analysis_repo=FakeAnalysisRepo([]),
            )

        first = asyncio.run(_run())
        # A fresh loop: a semaphore bound to the first one would raise in waiters, which gather swallows silently.
        second = asyncio.run(_run())
        assert len(first.projects) == n_projects
        assert len(second.projects) == n_projects


_DIFFERENTIAL_FIELDS = (
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
    "avg_days_between_scans",
    "trend_direction",
    "scan_timeline",
)


class TestBranchRuleDifferential:
    _PROJECT = "proj-diff"
    _WINDOW = 90

    @staticmethod
    async def _seed(db: FakeDatabase, scan_id: str, days_ago: float, branch: str, version: str) -> None:
        await db.scans.insert_one(
            {
                "_id": scan_id,
                "project_id": TestBranchRuleDifferential._PROJECT,
                "branch": branch,
                "created_at": datetime.now(tz=timezone.utc) - timedelta(days=days_ago),
                "commit_hash": f"commit-{scan_id}",
                "status": "completed",
                "is_rescan": False,
            }
        )
        await db.dependencies.insert_one(
            {"_id": f"{scan_id}:pkg-a", "scan_id": scan_id, "name": "pkg-a", "version": version, "type": "library"}
            | {"purl": f"pkg:pypi/pkg-a@{version}"}
        )

    async def _live(self, db: FakeDatabase) -> UpdateFrequencyMetrics:
        branch = await elect_primary_branch(ScanRepository(db), self._PROJECT, window_cutoff(self._WINDOW), None, [])
        return await compute_update_frequency(
            project_id=self._PROJECT,
            project_name="Diff",
            scan_repo=ScanRepository(db),
            dep_repo=DependencyRepository(db),
            analysis_repo=AnalysisResultRepository(db),
            branch=branch,
            window_days=self._WINDOW,
        )

    async def _rollup(self, db: FakeDatabase) -> UpdateFrequencyMetrics:
        project = {"_id": self._PROJECT, "name": "Diff", "default_branch": None, "deleted_branches": []}
        rolled = await rollup_metrics(db, project, self._WINDOW)
        assert rolled is not None
        return rolled

    @pytest.mark.asyncio
    async def test_a_busy_branch_beats_a_fresher_one_on_both_paths(self):
        # In production the newest scan's branch is not always the project's branch, which decides every field.
        db = FakeDatabase()
        for i, version in enumerate(("1.0.0", "1.1.0", "2.0.0")):
            await self._seed(db, f"o{i}", 80 - i * 10, "old", version)
        for i, version in enumerate(("5.0.0", "5.0.1")):
            await self._seed(db, f"n{i}", 20 - i * 10, "new", version)
        for scan in sorted(await db.scans.find({}).to_list(None), key=lambda s: (s["created_at"], s["_id"])):
            await record_scan_update_delta(db, scan["_id"])

        live = await self._live(db)
        rolled = await self._rollup(db)

        assert {
            field: (getattr(live, field), getattr(rolled, field))
            for field in _DIFFERENTIAL_FIELDS
            if getattr(live, field) != getattr(rolled, field)
        } == {}
        assert live.branch == "old"
        assert (live.scan_count, live.total_updates, live.minor_updates, live.major_updates) == (3, 2, 1, 1)

    @pytest.mark.asyncio
    async def test_a_branch_scanned_only_for_findings_wins_on_neither_path(self):
        # A findings-only pipeline stores no dependencies, so its commits compare nothing.
        db = FakeDatabase()
        for i, version in enumerate(("1.0.0", "1.1.0", "2.0.0")):
            await self._seed(db, f"m{i}", 30 - i * 10, "main", version)
        for i in range(5):
            await db.scans.insert_one(
                {
                    "_id": f"sast{i}",
                    "project_id": self._PROJECT,
                    "branch": "develop",
                    "created_at": datetime.now(tz=timezone.utc) - timedelta(days=5 - i),
                    "commit_hash": f"commit-sast{i}",
                    "status": "completed",
                    "is_rescan": False,
                    "sbom_refs": [],
                }
            )
        for scan in sorted(await db.scans.find({}).to_list(None), key=lambda s: (s["created_at"], s["_id"])):
            await record_scan_update_delta(db, scan["_id"])

        live = await self._live(db)
        assert (live.branch, live.total_updates) == ("main", 2)
        rolled = await self._rollup(db)
        assert (rolled.branch, rolled.total_updates) == ("main", 2)


class TestTheLiveWalkIsAlwaysFullyCovered:
    """The walk reads the scans coverage is measured against, so it never reports partial."""

    @staticmethod
    def _retry_storm_project(pid: str) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
        scans = [_scan_days_ago(f"{pid}-s0", 60, project_id=pid, commit_hash="c0")]
        scans += [_scan_days_ago(f"{pid}-r{i}", 59 - i, project_id=pid, commit_hash="c1") for i in range(8)]
        scans.append(_scan_days_ago(f"{pid}-s9", 50, project_id=pid, commit_hash="c2"))
        deps = {s["_id"]: [_make_dep(s["_id"], "pkg-a", "1.0.0")] for s in scans}
        deps[f"{pid}-s9"] = [_make_dep(f"{pid}-s9", "pkg-a", "2.0.0")]
        return scans, deps

    @staticmethod
    def _steady_project(pid: str) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
        scans = [_scan_days_ago(f"{pid}-s1", 30, project_id=pid), _scan_days_ago(f"{pid}-s2", 1, project_id=pid)]
        deps = {
            f"{pid}-s1": [_make_dep(f"{pid}-s1", "pkg-b", "1.0.0")],
            f"{pid}-s2": [_make_dep(f"{pid}-s2", "pkg-b", "1.0.1")],
        }
        return scans, deps

    @pytest.mark.asyncio
    async def test_a_retry_storm_leaves_a_project_fully_covered(self):
        # Both paths give a retry run one bar, so counting retries as missing coverage would drop a healthy project.
        scans, deps = self._retry_storm_project("proj-retry")

        result = await _compare([{"_id": "proj-retry", "name": "Retry"}], scans, deps)

        row = result.projects[0]
        assert row.data_status == "ready"
        assert (row.scan_count, row.total_updates) == (3, 1)
        assert result.partial_projects == 0

    @pytest.mark.asyncio
    async def test_scans_older_than_the_window_do_not_make_a_project_look_partial(self):
        # Coverage is measured against the window the numbers describe, not the project's whole history.
        scans, deps = self._steady_project("proj-ready")
        scans += [_scan_days_ago(f"ancient-{i}", 200 + i, project_id="proj-ready") for i in range(100)]

        result = await _compare([{"_id": "proj-ready", "name": "Ready"}], scans, deps)

        assert [p.data_status for p in result.projects] == ["ready"]

    @pytest.mark.asyncio
    async def test_scans_the_walk_cannot_date_leave_coverage_alone(self):
        # A restore can store a scan date as text, which a date range skips on both sides alike.
        scans, deps = self._steady_project("proj-thin")
        scans += [
            _scan_days_ago(f"undated-{i}", 20 + i, project_id="proj-thin") | {"created_at": "not a date"}
            for i in range(8)
        ]

        result = await _compare([{"_id": "proj-thin", "name": "Thin"}], scans, deps)

        row = result.projects[0]
        assert (row.data_status, row.scan_count) == ("ready", 2)
        assert result.partial_projects == 0


class TestWindowCutoff:
    def test_no_window_returns_none(self):
        assert window_cutoff(None) is None

    def test_window_days_translates_to_a_cutoff_in_the_past(self):
        before = datetime.now(tz=timezone.utc)
        result = window_cutoff(30)
        after = datetime.now(tz=timezone.utc)

        assert result is not None
        assert before - timedelta(days=30) <= result <= after - timedelta(days=30)

    def test_result_is_utc_aware(self):
        # A naive cutoff compares wrong against the UTC dates Mongo stores.
        result = window_cutoff(365)
        assert result is not None
        assert result.utcoffset() == timedelta(0)

    def test_the_longest_allowed_window_does_not_overflow(self):
        result = window_cutoff(3650)
        assert result is not None
        assert result.year < datetime.now(tz=timezone.utc).year


class TestRecentUpdatesSelection:
    """One limit and one order for the list, so the walk and the ledger keep the same events."""

    @pytest.mark.asyncio
    async def test_a_scan_with_more_changes_than_the_limit_keeps_the_ranked_ones(self):
        changed = RECENT_UPDATES_LIMIT + 10
        scans = [_make_scan("s0", 0), _make_scan("s1", 1)]
        deps = {
            "s0": [_make_dep("s0", f"pkg{i:03d}", "1.0.0") for i in range(changed)],
            # The last package by name takes a major bump, which ranking must pull past the document-order limit.
            "s1": [_make_dep("s1", f"pkg{i:03d}", "2.0.0" if i == changed - 1 else "1.0.1") for i in range(changed)],
        }

        m = await _compute(scans, deps)

        assert len(m.recent_updates) == RECENT_UPDATES_LIMIT
        assert m.recent_updates[0].package_name == f"pkg{changed - 1:03d}"
        assert m.recent_updates[0].update_type == "major"
        assert [event.package_name for event in m.recent_updates[1:]] == [
            f"pkg{i:03d}" for i in range(RECENT_UPDATES_LIMIT - 1)
        ]

    @pytest.mark.asyncio
    async def test_the_newest_scan_comes_first(self):
        scans = [_make_scan("s0", 0), _make_scan("s1", 1), _make_scan("s2", 2)]
        deps = {
            "s0": [_make_dep("s0", "pkg-a", "1.0.0")],
            "s1": [_make_dep("s1", "pkg-a", "1.0.1")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.2")],
        }

        m = await _compute(scans, deps)

        assert [event.new_version for event in m.recent_updates] == ["1.0.2", "1.0.1"]


class TestSlowestPackagesCut:
    @staticmethod
    def _rows(package_outdated_counts, latest_outdated):
        return _build_slowest_packages(package_outdated_counts, {}, {}, latest_outdated, {})

    def test_packages_tied_on_scans_are_ordered_by_name(self):
        tied = {f"pkg{i:02d}": 3 for i in range(SLOWEST_PACKAGES_LIMIT + 5)}
        # Insertion order is Mongo document order, which is not stable across requests.
        shuffled = dict(reversed(list(tied.items())))

        rows, _backlog = self._rows(shuffled, set(tied))

        assert [row.name for row in rows] == sorted(tied)[:SLOWEST_PACKAGES_LIMIT]

    def test_the_name_tie_break_and_the_cut_ignore_case(self):
        fillers = {f"m{i:02d}": 3 for i in range(SLOWEST_PACKAGES_LIMIT - 2)}
        counts = {"Zlib": 3, **fillers, "élan": 3, "axios": 3}

        rows, _backlog = self._rows(counts, set(counts))

        assert [row.name for row in rows] == ["axios", "élan", *fillers]

    def test_a_higher_count_still_outranks_the_name(self):
        counts = {"zzz": 9, "aaa": 1}

        rows, _backlog = self._rows(counts, set(counts))

        assert [row.name for row in rows] == ["zzz", "aaa"]

    def test_the_backlog_is_counted_before_the_table_is_cut(self):
        backlog_size = SLOWEST_PACKAGES_LIMIT + 7
        counts = {f"pkg{i:02d}": 2 for i in range(backlog_size)}

        rows, backlog = self._rows(counts, set(counts))

        assert len(rows) == SLOWEST_PACKAGES_LIMIT
        assert backlog == backlog_size

    def test_resolved_packages_are_not_backlog(self):
        counts = {"still-outdated": 4, "resolved": 9}

        rows, backlog = self._rows(counts, {"still-outdated"})

        assert [row.name for row in rows] == ["still-outdated"]
        assert backlog == 1


class TestOutdatedRowsPerScan:
    """One row is stored per SBOM; the backlog is their union, so every row must be read."""

    _SBOMS_PER_SCAN = 60

    def _repo(self) -> FakeAnalysisRepo:
        return FakeAnalysisRepo(
            [
                {
                    "scan_id": "scan-1",
                    "analyzer_name": "outdated_packages",
                    "result": {
                        "outdated_dependencies": [{"component": f"pkg{i:03d}"}],
                        "partial_components_skipped": 1,
                        "lookup_failed_components": [f"lost{i:03d}"],
                    },
                }
                for i in range(self._SBOMS_PER_SCAN)
            ]
        )

    @pytest.mark.asyncio
    async def test_a_monorepo_posting_many_sboms_keeps_every_backlog_row(self):
        loaded = await load_outdated_entries(self._repo(), "scan-1")

        assert loaded is not None
        entries, failed = loaded
        assert [e["component"] for e in entries] == [f"pkg{i:03d}" for i in range(self._SBOMS_PER_SCAN)]
        assert failed == {f"lost{i:03d}" for i in range(self._SBOMS_PER_SCAN)}

    @pytest.mark.asyncio
    async def test_a_scan_with_no_outdated_analysis_is_unmeasured_not_empty(self):
        entries = await load_outdated_entries(FakeAnalysisRepo([]), "scan-1")

        assert entries is None


class TestRankSummaries:
    @staticmethod
    def _summary(name: str, status: str, rate: float | None, coverage: float | None = None):
        return ProjectUpdateSummary(
            project_id=name.lower(),
            project_name=name,
            data_status=status,
            window_days=90,
            updates_per_month=rate,
            update_coverage_pct=coverage,
        )

    def test_a_partial_project_stays_out_of_the_team_average(self):
        """A partial row measures a shorter stretch, so its rate is not comparable."""
        result = rank_summaries(
            [
                self._summary("Ready", "ready", 4.0, coverage=100.0),
                self._summary("Partial", "partial", 10.0, coverage=100.0),
            ]
        )

        assert result.team_avg_updates_per_month == 4.0
        assert result.partial_projects == 1

    @pytest.mark.parametrize(
        ("status", "rate", "coverage"),
        [
            ("ready", 2.0, 50.0),
            ("ready", 2.0, None),
            ("partial", 2.0, None),
            ("pending", None, None),
            ("insufficient_data", None, None),
            ("error", None, None),
        ],
    )
    def test_a_list_orders_names_on_as_many_updates_whatever_their_case(self, status, rate, coverage):
        names = ["zeta", "Beta", "alpha", "Élan"]

        result = rank_summaries([self._summary(name, status, rate, coverage) for name in names])

        assert [p.project_name for p in result.projects] == ["alpha", "Beta", "Élan", "zeta"]

    def test_an_unavailable_rate_ranks_below_a_measured_zero(self):
        result = rank_summaries(
            [
                self._summary("NoRate", "ready", None),
                self._summary("Idle", "ready", 0.0),
            ]
        )

        assert [p.project_name for p in result.projects] == ["Idle", "NoRate"]
