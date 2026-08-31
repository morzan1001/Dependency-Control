"""Tests for update frequency analysis (version classification, trend, aggregates, streaming orchestrator)."""

import asyncio
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch

import pytest

import app.services.update_frequency as update_frequency_module
from app.repositories import AnalysisResultRepository, DependencyRepository, ScanRepository
from app.repositories.update_frequency import (
    BranchWindowActivity,
    ScanOutdatedSetRepository,
    ScanUpdateDeltaRepository,
    window_scans_by_branch,
)
from app.schemas.analytics import ScanTimelineEntry, UpdateFrequencyMetrics
from app.services.release_history import ReleaseHistory, ReleaseInfo
from app.services.update_frequency import (
    _COMPARISON_CONCURRENCY,
    READY_COVERAGE_RATIO,
    _aggregate_metrics,
    _dominant_ecosystem,
    _empty_metrics,
    classify_version_change,
    compute_trend,
    compute_update_frequency,
    compute_update_frequency_comparison,
    select_primary_branch,
    window_coverage_status,
    window_cutoff,
)
from app.services.update_frequency_fold import fold_window, select_window
from app.services.update_frequency_rollup import record_scan_update_delta
from tests.mocks.fake_mongo import FakeDatabase, _bson_sort_key


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

    def test_one_unparseable_returns_unknown(self):
        assert classify_version_change("1.0.0", "abc") == "unknown"

    # identical versions must NOT be classified as "patch"
    def test_identical_versions_returns_none(self):
        assert classify_version_change("1.0.0", "1.0.0") == "none"

    def test_identical_with_v_prefix_returns_none(self):
        assert classify_version_change("v1.0.0", "1.0.0") == "none"

    # pre-release identifiers must be respected
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
        # 1.0.0-beta1 -> 1.0.0-beta2: same release tuple, different prerelease
        result = classify_version_change("1.0.0-beta1", "1.0.0-beta2")
        assert result != "none"
        assert result in ("patch", "prerelease")

    def test_prerelease_to_higher_patch(self):
        # 1.0.0-beta1 -> 1.0.1 spans both prerelease and patch — should be patch
        assert classify_version_change("1.0.0-beta1", "1.0.1") == "patch"

    def test_prerelease_to_higher_major(self):
        assert classify_version_change("1.0.0-beta1", "2.0.0") == "major"

    def test_short_version_strings(self):
        # Versions like "1.0" should still parse and classify
        assert classify_version_change("1.0", "1.1") == "minor"

    def test_single_component_version(self):
        # A bare "1" -> "2" is a major change
        assert classify_version_change("1", "2") == "major"

    def test_hash_based_versions_unknown(self):
        # Git SHA / build hash version strings cannot be ordered semantically.
        assert classify_version_change("abc1234", "def5678") == "unknown"

    def test_calver_classified_by_release_tuple(self):
        # CalVer maps onto the release tuple via packaging.Version; behavior pinned so regex tweaks can't silently change it.
        assert classify_version_change("2024.01.15", "2024.02.01") == "minor"
        assert classify_version_change("2024.01.15", "2025.01.15") == "major"
        assert classify_version_change("2024.01.15", "2024.01.16") == "patch"

    def test_post_release_kept_as_change(self):
        # PEP 440 post-releases are "after the release" — different identity,
        # so 1.0.0 -> 1.0.0.post1 must register as some kind of change, not "none".
        result = classify_version_change("1.0.0", "1.0.0.post1")
        assert result != "none"

    def test_local_version_segment_kept_as_change(self):
        # Local versions (1.0.0+build123) are common in private registries.
        result = classify_version_change("1.0.0", "1.0.0+build123")
        assert result != "none"


class TestDominantEcosystem:
    """Pin the >=70% threshold for assigning a single ecosystem label."""

    def test_pure_single_type(self):
        assert _dominant_ecosystem({"a": "pypi", "b": "pypi", "c": "pypi"}) == "pypi"

    def test_clear_majority_returns_majority(self):
        # 8 pypi + 1 npm + 1 maven = 80% pypi, above the threshold.
        deps = {f"py{i}": "pypi" for i in range(8)}
        deps["js"] = "npm"
        deps["mv"] = "maven"
        assert _dominant_ecosystem(deps) == "pypi"

    def test_balanced_mix_returns_mixed(self):
        # 5 pypi + 5 npm = 50/50, below the 70% bar.
        deps = {f"p{i}": "pypi" for i in range(5)}
        deps.update({f"n{i}": "npm" for i in range(5)})
        assert _dominant_ecosystem(deps) == "mixed"

    def test_empty_returns_none(self):
        # Nothing to classify — surface as None rather than inventing a default.
        assert _dominant_ecosystem({}) is None

    def test_unknown_types_excluded_from_majority(self):
        # "unknown" never wins a majority; it's noise from missing PURL data.
        deps = {f"p{i}": "pypi" for i in range(3)}
        deps.update({f"u{i}": "unknown" for i in range(7)})
        # 3 known (all pypi) -> pypi is 100% of *classified* deps.
        assert _dominant_ecosystem(deps) == "pypi"


def _baseline_entry() -> ScanTimelineEntry:
    # Orchestrator timelines always start with the no-predecessor baseline scan.
    return _make_timeline_entry(0, updates=0, outdated=5)


class TestComputeTrend:
    # trend is "unknown" when there isn't enough data, not "stable"
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


class TestEmptyMetrics:
    # empty metrics use "unknown" trend, not "stable"
    def test_empty_metrics_trend_is_unknown(self):
        m = _empty_metrics("p1", "Project One", 0, "")
        assert m.trend_direction == "unknown"

    # empty metrics have null coverage (no outdated history yet)
    def test_empty_metrics_coverage_is_none(self):
        m = _empty_metrics("p1", "Project One", 0, "")
        assert m.update_coverage_pct is None


class TestAggregateMetricsCoverage:
    # coverage is None when nothing has ever been outdated
    def test_coverage_none_when_no_outdated(self):
        m = _aggregate_metrics(
            type_counter=Counter(),
            recent_events=[],
            bars=[_make_timeline_entry(0), _make_timeline_entry(30)],
            ever_outdated=set(),
            ever_resolved=set(),
            dep_type_map={},
            package_outdated_counts={},
            package_latest_info={},
            project_id="p1",
            project_name="Project One",
        )
        assert m.update_coverage_pct is None
        assert m.total_outdated_detected == 0
        assert m.outdated_resolved == 0

    def test_coverage_pct_when_outdated_resolved(self):
        m = _aggregate_metrics(
            type_counter=Counter(),
            recent_events=[],
            bars=[_make_timeline_entry(0), _make_timeline_entry(30)],
            ever_outdated={"pkg-a", "pkg-b"},
            ever_resolved={"pkg-a"},
            dep_type_map={},
            package_outdated_counts={"pkg-a": 1, "pkg-b": 2},
            package_latest_info={},
            project_id="p1",
            project_name="Project One",
        )
        assert m.update_coverage_pct == 50.0
        assert m.total_outdated_detected == 2
        assert m.outdated_resolved == 1


# --- Fake repos for streaming-orchestrator tests ---


def _apply_projection(doc: dict[str, Any], projection: dict[str, int] | None) -> dict[str, Any]:
    """Mongo inclusion projection: only the named fields survive, plus _id unless excluded."""
    if not projection:
        return dict(doc)
    keep = {field for field, include in projection.items() if include}
    if projection.get("_id", 1):
        keep.add("_id")
    else:
        keep.discard("_id")
    return {k: v for k, v in doc.items() if k in keep}


def _matches_scan_query(scan: dict[str, Any], query: dict[str, Any]) -> bool:
    for field, cond in query.items():
        value = scan.get(field)
        if isinstance(cond, dict):
            if "$ne" in cond and value == cond["$ne"]:
                return False
            if "$nin" in cond and value in cond["$nin"]:
                return False
            if "$in" in cond and value not in cond["$in"]:
                return False
        elif value != cond:
            return False
    return True


class FakeScanRepo:
    def __init__(self, scans: list[dict[str, Any]]):
        # scans must include _id, created_at, status, project_id, branch
        self._scans = scans

    def _filtered(self, query: dict[str, Any], sort: list[tuple[str, int]] | None) -> list[dict[str, Any]]:
        matched = [s for s in self._scans if _matches_scan_query(s, query)]
        if sort:
            for field, order in reversed(sort):
                matched.sort(key=lambda s, f=field: _bson_sort_key(s.get(f)), reverse=(order == -1))
        return matched

    async def find_many_raw(
        self,
        query: dict[str, Any],
        sort: list[tuple[str, int]] | None = None,
        skip: int = 0,
        limit: int | None = None,
        projection: dict[str, int] | None = None,
    ) -> list[dict[str, Any]]:
        # Mirrors ScanRepository.find_many_raw: filter by the query (incl. status),
        # sort, then apply the limit — status is filtered BEFORE the limit.
        matched = self._filtered(query, sort)
        matched = matched[skip : skip + limit] if limit is not None else matched[skip:]
        return [_apply_projection(s, projection) for s in matched]

    async def aggregate(self, pipeline: list[dict[str, Any]], limit: int | None = None) -> list[dict[str, Any]]:
        # Run the real pipeline through the fake Mongo engine rather than
        # reimplementing it: a pipeline that would not answer in Mongo must not
        # answer here either, down to the naive UTC datetimes it stores.
        db = FakeDatabase()
        for scan in self._scans:
            await db.scans.insert_one(dict(scan))
        return await db.scans.aggregate(pipeline).to_list(limit)


class FakeDepRepo:
    def __init__(self, deps_by_scan: dict[str, list[dict[str, Any]]]):
        self._deps_by_scan = deps_by_scan
        self.calls: list[str] = []  # tracks every find_all query for assertions

    async def find_all(
        self,
        query: dict[str, Any],
        projection: dict[str, int] | None = None,
    ) -> list[dict[str, Any]]:
        scan_id = query.get("scan_id")
        self.calls.append(scan_id)
        return [_apply_projection(d, projection) for d in self._deps_by_scan.get(scan_id, [])]


class FakeAnalysisRepo:
    def __init__(self, results: list[dict[str, Any]]):
        self._results = results
        self.queries: list[dict[str, Any]] = []

    async def find_many_raw(
        self,
        query: dict[str, Any],
        limit: int = 1000,
        projection: dict[str, int] | None = None,
    ) -> list[dict[str, Any]]:
        self.queries.append(query)
        scan_filter = query.get("scan_id")
        analyzer = query.get("analyzer_name")
        out = []
        for r in self._results:
            if isinstance(scan_filter, dict):
                ids = scan_filter.get("$in", [])
                if r["scan_id"] not in ids:
                    continue
            elif scan_filter is not None and r["scan_id"] != scan_filter:
                continue
            if analyzer is not None and r["analyzer_name"] != analyzer:
                continue
            out.append(_apply_projection(r, projection))
        return out[:limit]


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


def _scan_days_ago(scan_id: str, days: float, **overrides: Any) -> dict[str, Any]:
    """A scan placed relative to now, so a ``window_days`` cutoff includes or excludes it."""
    return _make_scan(scan_id, 0, **overrides) | {"created_at": datetime.now(tz=timezone.utc) - timedelta(days=days)}


def _recent_scans(count: int, spacing_days: int = 1) -> list[dict[str, Any]]:
    """Scans ending at now, so a ``window_days`` cutoff can select a known suffix."""
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
    """A window whose commits were each scanned once, the shape most cases only need."""
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
    """The timeline must cover exactly one branch and exclude rescans/storms."""

    @staticmethod
    async def _compute(scans, deps, **kwargs):
        return await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
            **kwargs,
        )

    @pytest.mark.asyncio
    async def test_mixed_branch_history_analyzes_only_primary_branch(self):
        # Feature-branch scans interleave with main; the feature branch bumps
        # pkg-a, main never does. Without branch scoping this counts 4 updates.
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
        m = await self._compute(scans, deps)
        assert m.branch == "main"
        assert m.scan_count == 3
        assert m.total_updates == 0

    @pytest.mark.asyncio
    async def test_default_branch_preferred_over_newest_scan_branch(self):
        # main has ample history; a single newer scan on a feature branch must
        # not hijack the analysis when default_branch is configured.
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
        m = await self._compute(scans, deps, default_branch="main")
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
        m = await self._compute(scans, deps, default_branch="main")
        assert m.branch == "main"
        assert m.scan_count == 2
        assert m.total_updates == 1

    @pytest.mark.asyncio
    async def test_default_branch_ignored_when_too_sparse(self):
        # default_branch has a single scan -> fall back to the active branch.
        scans = [
            _make_scan("d1", 0, branch="release"),
            _make_scan("m1", 1, branch="main"),
            _make_scan("m2", 2, branch="main"),
        ]
        deps = {
            "m1": [_make_dep("m1", "pkg-a", "1.0.0")],
            "m2": [_make_dep("m2", "pkg-a", "1.0.1")],
        }
        m = await self._compute(scans, deps, default_branch="release")
        assert m.branch == "main"
        assert m.scan_count == 2

    @pytest.mark.asyncio
    async def test_rescans_excluded_from_the_analyzed_branch_timeline(self):
        # A rescan ON the analyzed branch must not enter the timeline.
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
        m = await self._compute(scans, deps, branch="main")
        assert m.scan_count == 2
        assert all(e.new_version != "0.5.0" for e in m.recent_updates)

    @pytest.mark.asyncio
    async def test_head_commit_storm_does_not_starve_window(self):
        # The newest max_scans raw scans are all the same head commit; distinct
        # older commits must still fill the window.
        scans = [_make_scan(f"h{i}", 100 + i, commit_hash="head") for i in range(5)]
        scans += [_make_scan(f"c{i}", i, commit_hash=f"c{i}") for i in range(5)]
        deps: dict[str, list[dict[str, Any]]] = {}
        for i in range(5):
            deps[f"h{i}"] = [_make_dep(f"h{i}", "pkg-a", "2.0.0")]
        for i in range(5):
            deps[f"c{i}"] = [_make_dep(f"c{i}", "pkg-a", f"1.0.{i}")]
        m = await self._compute(scans, deps, branch="main", max_scans=5)
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
        m = await self._compute(scans, deps, branch="feature")
        assert m.branch == "feature"
        assert m.scan_count == 2
        assert m.minor_updates == 1

    @pytest.mark.asyncio
    async def test_rescans_are_excluded(self):
        # The newest scan is a rescan carrying a stale snapshot; it must drive
        # neither branch resolution nor the timeline.
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
        m = await self._compute(scans, deps)
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

        m = await self._compute(scans, deps, window_days=90)

        assert m.branch == "old"
        assert m.scan_count == 3

    @pytest.mark.asyncio
    async def test_the_default_branch_needs_its_two_scans_inside_the_window(self):
        # release was busy before the window and scanned once inside it; counting
        # its whole history would hand it a window it cannot describe.
        scans = [_scan_days_ago(f"r{i}", 200 + i, branch="release") for i in range(10)]
        scans.append(_scan_days_ago("r-recent", 30, branch="release"))
        scans += [_scan_days_ago(f"m{i}", 60 - i * 10, branch="main") for i in range(3)]
        deps = {s["_id"]: [_make_dep(s["_id"], "pkg-a", "1.0.0")] for s in scans}

        m = await self._compute(scans, deps, window_days=90, default_branch="release")

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
        m = await self._compute(scans, deps, deleted_branches=["gone"])
        assert m.branch == "main"
        assert m.scan_count == 2

    @pytest.mark.asyncio
    async def test_naive_created_at_is_coerced_to_utc(self):
        # Motor returns naive UTC datetimes; the tz-aware window cutoff and the
        # downstream date math must both survive that.
        naive = (datetime.now(tz=timezone.utc) - timedelta(days=40)).replace(tzinfo=None)
        scans = [
            {**_make_scan("s1", 0), "created_at": naive},
            {**_make_scan("s2", 30), "created_at": naive + timedelta(days=30)},
        ]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.1")],
        }
        m = await self._compute(scans, deps, window_days=60)
        assert m.scan_count == 2
        assert m.first_scan_date.endswith("+00:00")
        assert m.last_scan_date.endswith("+00:00")

    @pytest.mark.asyncio
    async def test_a_textual_created_at_drops_the_scan(self):
        # Archive restore inserts bundle JSON verbatim and JSON has no date type, so a
        # restored scan can carry created_at as text. A range query brackets to its
        # bound's BSON type, so the window aggregation and the backfill both skip such
        # a scan; parsing it here would put it on a timeline nothing else accounts for.
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
        m = await self._compute(scans, deps)
        assert m.scan_count == 2
        assert [e.scan_id for e in m.scan_timeline] == ["s3", "s4"]
        assert m.total_updates == 1

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
        m = await self._compute(scans, deps)
        assert m.scan_count == 3
        assert [e.scan_id for e in m.scan_timeline] == ["s0", "s5", "s6"]
        # The storm's own bump lands on the bar its run named, not on the run's first try.
        assert [e.updates_count for e in m.scan_timeline] == [0, 1, 1]
        assert m.total_updates == 2


class TestIdentityKeying:
    """Version diffing must key on purl identity, not the bare dependency name."""

    @staticmethod
    def _raw_dep(scan_id: str, name: str, version: str, purl: str, ptype: str = "library") -> dict[str, Any]:
        return {"scan_id": scan_id, "name": name, "version": version, "type": ptype, "purl": purl}

    async def _compute(self, deps: dict[str, list[dict[str, Any]]]):
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        return await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
        )

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
        m = await self._compute(deps)
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
        m = await self._compute(deps)
        assert m.total_updates == 0

    @pytest.mark.asyncio
    async def test_pypi_name_variants_are_one_identity(self):
        # PEP 503 equivalent names (case/underscore/dot) must not read as remove+add.
        deps = {
            "s1": [self._raw_dep("s1", "My_Package", "1.0.0", "pkg:pypi/My_Package@1.0.0")],
            "s2": [self._raw_dep("s2", "my-package", "1.1.0", "pkg:pypi/my-package@1.1.0")],
        }
        m = await self._compute(deps)
        assert m.total_updates == 1
        assert m.recent_updates[0].update_type == "minor"

    @pytest.mark.asyncio
    async def test_deps_without_purl_key_by_name_and_type(self):
        # The non-purl fallback identity path must still diff correctly.
        deps = {
            "s1": [{"scan_id": "s1", "name": "internal-lib", "version": "1.0.0", "type": "internal", "purl": ""}],
            "s2": [{"scan_id": "s2", "name": "internal-lib", "version": "1.0.1", "type": "internal", "purl": ""}],
        }
        m = await self._compute(deps)
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
        m = await self._compute(deps)
        assert m.total_updates == 1
        assert m.recent_updates[0].package_name == "@angular/cdk"
        assert m.recent_updates[0].update_type == "minor"


class TestOutdatedTracking:
    """Outdated results union across SBOMs; resolution means leaving the outdated set."""

    @staticmethod
    async def _compute(deps, analysis_results):
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        return await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo(analysis_results),
        )

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
        m = await self._compute(deps, results)
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
        m = await self._compute(deps, results)
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
        m = await self._compute(deps, results)
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
        m = await self._compute(deps, results)
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
    """A scan carrying no outdated analysis is not a scan with an empty backlog.

    Roughly one scan in thirty ships without an SBOM and therefore without the
    analysis, so every metric derived from the backlog has to survive the gap.
    """

    @staticmethod
    async def _compute(scans, deps, analysis_results):
        return await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo(analysis_results),
        )

    @pytest.mark.asyncio
    async def test_missing_final_analysis_is_not_a_cleared_backlog(self):
        # Identical dependency sets: nothing was updated, so nothing can have
        # been resolved either.
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {sid: _backlog_deps(sid) for sid in ("s1", "s2")}
        m = await self._compute(scans, deps, [_backlog_outdated("s1")])
        assert m.total_updates == 0
        assert m.total_outdated_detected == 3
        assert m.outdated_resolved == 0
        assert m.update_coverage_pct == 0.0
        assert [e.outdated_count for e in m.scan_timeline] == [3, None]

    @pytest.mark.asyncio
    async def test_coverage_is_none_when_no_scan_measured_a_backlog(self):
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {sid: _backlog_deps(sid) for sid in ("s1", "s2")}
        m = await self._compute(scans, deps, [])
        assert m.update_coverage_pct is None
        assert m.total_outdated_detected == 0
        assert [e.outdated_count for e in m.scan_timeline] == [None, None]

    @pytest.mark.asyncio
    async def test_resolution_across_a_measurement_gap_is_not_credited(self):
        # pkg-b and pkg-c leave the backlog, but the only scan in between
        # carries no analysis, so the transition was never observed.
        scans = [_make_scan("s1", 0), _make_scan("s2", 30), _make_scan("s3", 60)]
        deps = {
            "s1": [*_backlog_deps("s1"), _make_dep("s1", "churn", "1.0.0")],
            "s2": [*_backlog_deps("s2"), _make_dep("s2", "churn", "1.0.0")],
            "s3": [*_backlog_deps("s3"), _make_dep("s3", "churn", "1.1.0")],
        }
        results = [_backlog_outdated("s1"), _backlog_outdated("s3", ["pkg-a"])]
        m = await self._compute(scans, deps, results)
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
        m = await self._compute(scans, deps, [_backlog_outdated("s1")])
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
        m = await self._compute(scans, deps, results)
        assert [e.outdated_count for e in m.scan_timeline] == [10, 10, 10, 10, 10, None]
        assert m.trend_direction == "stable"
        assert "~10 outdated" in m.trend_detail


class TestAggregationAccuracy:
    @pytest.mark.asyncio
    async def test_downgrades_are_not_counted_as_updates(self):
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "2.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.0")],
        }
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
        )
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
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
        )
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
        return await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
            window_days=window_days,
            hard_limit=10,
        )

    @pytest.mark.asyncio
    async def test_the_monthly_rate_measures_the_window_not_the_scan_cadence(self):
        fast = await self._one_update_over(36, window_days=None)
        slow = await self._one_update_over(24 * 60, window_days=None)
        # No window: extrapolating one update to a monthly rate would say 20/month
        # for the fast project and 0.5/month for the slow one on identical activity.
        assert fast.updates_per_month is None
        assert slow.updates_per_month is None

    @pytest.mark.asyncio
    async def test_the_monthly_rate_is_the_same_for_both_cadences_in_one_window(self):
        # window_days here is only the rate denominator; both scan pairs fall
        # inside the cutoff, so the selection itself is unaffected.
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
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo(results),
        )
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
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
        )
        assert m.avg_days_between_scans == 0.5

    @pytest.mark.asyncio
    async def test_slowest_current_version_not_borrowed_from_same_name_sibling(self):
        # Two npm packages stored under the bare name "core"; one is outdated,
        # the other up-to-date. The backlog row must not show the sibling's version.
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
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo([_make_scan("s1", 0), _make_scan("s2", 30)]),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo(results),
        )
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
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
        )
        assert m.dominant_ecosystem == "maven"
        assert m.recent_updates[0].package_type == "maven"


class TestStreamingOrchestrator:
    @pytest.mark.asyncio
    async def test_basic_two_scan_history(self):
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0"), _make_dep("s1", "pkg-b", "2.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.1"), _make_dep("s2", "pkg-b", "3.0.0")],
        }
        scan_repo = FakeScanRepo(scans)
        dep_repo = FakeDepRepo(deps)
        analysis_repo = FakeAnalysisRepo([])

        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=scan_repo,
            dep_repo=dep_repo,
            analysis_repo=analysis_repo,
        )

        assert m.scan_count == 2
        assert m.total_updates == 2
        assert m.patch_updates == 1  # pkg-a 1.0.0 -> 1.0.1
        assert m.major_updates == 1  # pkg-b 2.0.0 -> 3.0.0

    @pytest.mark.asyncio
    async def test_recent_updates_capped_at_30(self):
        # Build 50 scans where every dep changes each scan -> 50 update events.
        # The streaming buffer must keep only the last 30 in `recent_updates`.
        scans = [_make_scan(f"s{i}", i) for i in range(50)]
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")] for i in range(50)}
        scan_repo = FakeScanRepo(scans)
        dep_repo = FakeDepRepo(deps)
        analysis_repo = FakeAnalysisRepo([])

        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=scan_repo,
            dep_repo=dep_repo,
            analysis_repo=analysis_repo,
            max_scans=100,
        )

        assert m.scan_count == 50
        assert m.total_updates == 49  # 50 scans -> 49 transitions
        assert len(m.recent_updates) == 30
        # newest first
        assert m.recent_updates[0].new_version == "1.0.49"

    @pytest.mark.asyncio
    async def test_default_takes_newest_scans_not_oldest(self):
        # 30 scans, max_scans=5 — analysis must use the newest 5, not the oldest 5.
        scans = [_make_scan(f"s{i}", i) for i in range(30)]
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")] for i in range(30)}
        scan_repo = FakeScanRepo(scans)
        dep_repo = FakeDepRepo(deps)
        analysis_repo = FakeAnalysisRepo([])

        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=scan_repo,
            dep_repo=dep_repo,
            analysis_repo=analysis_repo,
            max_scans=5,
        )

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

        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
            window_days=11,
        )

        assert m.scan_count == 6
        assert m.total_updates == 5

    @pytest.mark.asyncio
    async def test_observations_bounded_for_high_churn_history(self):
        # 200 scans x 5 packages = 1000 (pkg, version) pairs; the orchestrator must stay bounded and still produce metrics.
        scans = [_make_scan(f"s{i}", i) for i in range(200)]
        deps: dict[str, list[dict[str, Any]]] = {}
        for i in range(200):
            deps[f"s{i}"] = [_make_dep(f"s{i}", f"pkg-{p}", f"1.{i}.{p}") for p in range(5)]
        scan_repo = FakeScanRepo(scans)
        dep_repo = FakeDepRepo(deps)
        analysis_repo = FakeAnalysisRepo([])

        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=scan_repo,
            dep_repo=dep_repo,
            analysis_repo=analysis_repo,
            max_scans=200,
        )
        # Headline: it returns at all and reports 200 scans plus the
        # right number of update events (199 transitions x 5 packages).
        assert m.scan_count == 200
        assert m.total_updates == 199 * 5

    @pytest.mark.asyncio
    async def test_no_release_fetcher_yields_none_upstream_metrics(self):
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.1")],
        }
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
        )
        assert m.upstream_releases_last_12m_median is None
        assert m.upstream_days_between_releases_median is None
        assert m.upstream_days_since_latest_release_median is None
        assert m.adoption_latency_days_median is None

    @pytest.mark.asyncio
    async def test_release_fetcher_populates_upstream_metrics(self):
        # Two scans, one update event (pkg-a 1.0.0 -> 1.0.1).
        # Upstream history: 1.0.0 published 100d before scan 0, 1.0.1 20d before scan 1.
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.1")],
        }
        scan0_date = scans[0]["created_at"]
        scan1_date = scans[1]["created_at"]
        history: ReleaseHistory = {
            "pkg-a": [
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
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
            release_fetcher=fetcher,
        )

        # Adoption latency: 1.0.1 published 20d before scan 1 -> latency 20.
        # Older 1.0.0 was already in scan 0 (we don't observe its first appearance).
        assert m.adoption_latency_days_median == 20.0

        # Two releases for pkg-a, both within the last 365d -> median count = 2
        assert m.upstream_releases_last_12m_median == 2.0

        # Days since latest release: ref is "now" but our latest is ~20d before scan 1
        # which is well in the past of "now". The exact number depends on test runtime,
        # so just sanity-check the field is populated and positive.
        assert m.upstream_days_since_latest_release_median is not None
        assert m.upstream_days_since_latest_release_median > 0

        # Fetcher must have been called once with the unique packages from the scans.
        assert len(fetcher.calls) == 1
        assert ("pypi", "pkg-a") in fetcher.calls[0]

    @pytest.mark.asyncio
    async def test_window_overrides_max_scans_when_it_holds_more(self):
        # 30 daily scans, max_scans=5, a window spanning them all (hard_limit-bounded load).
        scans = _recent_scans(30)
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")] for i in range(30)}

        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
            max_scans=5,
            window_days=40,
        )
        assert m.scan_count == 30, "the calendar window should trump max_scans when it contains more scans"

    @pytest.mark.asyncio
    async def test_hard_limit_caps_runaway_queries(self):
        # 2500 scans inside the window -> the hard_limit safety cap must keep
        # us from loading the whole collection.
        scans = _recent_scans(2500)
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")] for i in range(2500)}

        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
            max_scans=5,
            window_days=3000,
            hard_limit=100,
        )
        # Only the newest 100 scans should be analysed under the safety cap.
        assert m.scan_count == 100

    @staticmethod
    def _two_scan_project(pid: str, pkg: str, versions: tuple[str, str]) -> tuple[list, dict]:
        # Inside the comparison's calendar window, which is what it now ranks over.
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
        # proj-a: pkg outdated then resolved -> measured 100% coverage.
        # proj-b: nothing ever outdated -> coverage None; must NOT outrank a
        # measured project or be crowned best_project.
        scans_a, deps_a = self._two_scan_project("proj-a", "pkg-a", ("1.0.0", "3.0.0"))
        scans_b, deps_b = self._two_scan_project("proj-b", "pkg-b", ("1.0.0", "1.0.1"))
        results = [
            _outdated_result(
                "proj-a-s1", [{"component": "pkg-a", "current_version": "1.0.0", "latest_version": "3.0.0"}]
            ),
        ]

        result = await compute_update_frequency_comparison(
            projects=[{"_id": "proj-b", "name": "Unmeasured"}, {"_id": "proj-a", "name": "Measured"}],
            scan_repo=FakeScanRepo(scans_a + scans_b),
            dep_repo=FakeDepRepo({**deps_a, **deps_b}),
            analysis_repo=FakeAnalysisRepo(results),
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

        result = await compute_update_frequency_comparison(
            projects=[{"_id": "proj-a", "name": "A"}, {"_id": "proj-b", "name": "B"}],
            scan_repo=FakeScanRepo(scans_a + scans_b),
            dep_repo=FakeDepRepo({**deps_a, **deps_b}),
            analysis_repo=FakeAnalysisRepo([]),
        )

        assert result.best_project is None
        assert result.worst_project is None
        assert result.team_avg_coverage_pct is None

    @pytest.mark.asyncio
    async def test_projects_without_enough_scans_are_counted_as_skipped(self):
        scans_a, deps_a = self._two_scan_project("proj-a", "pkg-a", ("1.0.0", "1.0.1"))
        single_scan = [_make_scan("proj-c-s1", 0, project_id="proj-c")]
        single_scan[0]["created_at"] = datetime.now(tz=timezone.utc)

        result = await compute_update_frequency_comparison(
            projects=[{"_id": "proj-a", "name": "A"}, {"_id": "proj-c", "name": "C"}],
            scan_repo=FakeScanRepo(scans_a + single_scan),
            dep_repo=FakeDepRepo(deps_a),
            analysis_repo=FakeAnalysisRepo([]),
        )

        assert [(p.project_name, p.data_status) for p in result.projects] == [
            ("A", "ready"),
            ("C", "insufficient_data"),
        ]
        assert result.skipped_insufficient_data == 1

    @pytest.mark.asyncio
    async def test_a_project_whose_summary_cannot_be_built_is_counted_rather_than_lost(self):
        # Building the summary happens outside the per-project guard, so a schema
        # violation there reaches asyncio.gather(return_exceptions=True) as the
        # exception itself. Such a project must not vanish from every counter.
        scans_a, deps_a = self._two_scan_project("proj-a", "pkg-a", ("1.0.0", "1.0.1"))
        scans_b, deps_b = self._two_scan_project("proj-b", "pkg-b", ("2.0.0", "2.1.0"))
        projects = [{"_id": "proj-a", "name": "A"}, {"_id": "proj-b", "name": "B"}]

        real_compute = update_frequency_module.compute_update_frequency

        async def _bad_ratio_for_b(**kwargs):
            metrics = await real_compute(**kwargs)
            if kwargs["project_id"] == "proj-b":
                # Survives here and fails when the summary is built, which is
                # outside the guard.
                metrics.granularity_ratio = {"patch": "not a number"}
            return metrics

        with patch.object(update_frequency_module, "compute_update_frequency", _bad_ratio_for_b):
            result = await compute_update_frequency_comparison(
                projects=projects,
                scan_repo=FakeScanRepo(scans_a + scans_b),
                dep_repo=FakeDepRepo({**deps_a, **deps_b}),
                analysis_repo=FakeAnalysisRepo([]),
            )

        assert {p.project_name for p in result.projects} == {"A", "B"}
        assert result.skipped_error == 1

    @pytest.mark.asyncio
    async def test_outdated_loaded_per_pair_not_upfront(self):
        # Must NOT issue a single bulk find_many across all scan_ids.
        scans = [_make_scan(f"s{i}", i) for i in range(5)]
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", "1.0.0")] for i in range(5)}
        results = [_outdated_result(f"s{i}", []) for i in range(5)]

        scan_repo = FakeScanRepo(scans)
        dep_repo = FakeDepRepo(deps)
        analysis_repo = FakeAnalysisRepo(results)

        await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=scan_repo,
            dep_repo=dep_repo,
            analysis_repo=analysis_repo,
        )

        # No call should use {"$in": [...all scan ids...]}; calls are per-scan.
        for q in analysis_repo.queries:
            scan_filter = q.get("scan_id")
            assert not isinstance(scan_filter, dict), (
                f"analysis results loaded with bulk scan filter {scan_filter}; expected per-scan loading"
            )

    @pytest.mark.asyncio
    async def test_completed_filter_applied_before_limit(self):
        # The newest max_scans scans are all failed with a long completed history underneath; status must be filtered in the query so older completed scans surface.
        completed = [_make_scan(f"c{i}", i) for i in range(6)]  # days 0..5, completed
        failed = [
            {**_make_scan(f"f{i}", 10 + i), "status": "failed"} for i in range(20)
        ]  # days 10..29, failed -> these are the newest 20
        scans = completed + failed
        deps = {f"c{i}": [_make_dep(f"c{i}", "pkg-a", f"1.0.{i}")] for i in range(6)}
        scan_repo = FakeScanRepo(scans)
        dep_repo = FakeDepRepo(deps)
        analysis_repo = FakeAnalysisRepo([])

        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=scan_repo,
            dep_repo=dep_repo,
            analysis_repo=analysis_repo,
            max_scans=20,
        )

        assert m.scan_count == 6, "completed scans must survive the fetch limit even when the newest scans failed"
        assert m.total_updates == 5

    @pytest.mark.asyncio
    async def test_maven_upstream_uses_deps_dev_name(self):
        # Maven components store only the artifact as the DB name, but deps.dev needs "group:artifact"; the spec must use that name and re-key observations so adoption-latency resolves.
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
            registry_name: [
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
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
            release_fetcher=fetcher,
        )

        # The fetcher must be asked for the group:artifact name, not the bare artifact.
        assert ("maven", registry_name) in fetcher.calls[0]
        assert ("maven", "log4j-core") not in fetcher.calls[0]
        # Observations re-keyed to the deps.dev name -> adoption latency resolves (15d).
        assert m.adoption_latency_days_median == 15.0

    def test_comparison_semaphore_reusable_across_event_loops(self):
        # The concurrency semaphore must be created per call so it binds to the
        # loop running the gather; a module-global one binds to the first loop and
        # then raises "bound to a different event loop". Reproducing needs genuine
        # contention: more projects than _COMPARISON_CONCURRENCY AND work that
        # suspends (asyncio.sleep(0)) while holding the semaphore.
        n_projects = _COMPARISON_CONCURRENCY + 2  # 5 > concurrency limit of 3

        class _SuspendingScanRepo(FakeScanRepo):
            async def find_many_raw(self, *args, **kwargs):
                await asyncio.sleep(0)  # yield to the loop while holding the semaphore
                return await super().find_many_raw(*args, **kwargs)

        class _SuspendingDepRepo(FakeDepRepo):
            async def find_all(self, *args, **kwargs):
                await asyncio.sleep(0)
                return await super().find_all(*args, **kwargs)

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
        # Fresh loop. With a module-global semaphore bound to the first loop, the
        # projects that must wait on it raise RuntimeError here; gather swallows
        # them (return_exceptions=True), so the summaries silently drop below
        # n_projects. The per-call semaphore keeps all projects intact.
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
    """One history read twice. Both paths must settle on the same branch, hence the same numbers."""

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
        return await compute_update_frequency(
            project_id=self._PROJECT,
            project_name="Diff",
            scan_repo=ScanRepository(db),
            dep_repo=DependencyRepository(db),
            analysis_repo=AnalysisResultRepository(db),
            window_days=self._WINDOW,
        )

    async def _rollup(self, db: FakeDatabase) -> UpdateFrequencyMetrics:
        """The ledger read the way the comparison endpoint assembles it."""
        since = window_cutoff(self._WINDOW)
        assert since is not None
        activity = await window_scans_by_branch(ScanRepository(db), [self._PROJECT], since)
        branch = select_primary_branch({b: seen for (_pid, b), seen in activity.items()}, None, [])
        assert branch is not None
        deltas = await ScanUpdateDeltaRepository(db).find_project_window(self._PROJECT, branch, since, 1000)
        window = select_window(deltas)
        baselines = await ScanOutdatedSetRepository(db).names_by_scan([window[0]["_id"]])
        folded = fold_window(window, baselines.get(window[0]["_id"]), self._WINDOW)
        return folded.to_metrics(self._PROJECT, "Diff", branch=branch)

    @pytest.mark.asyncio
    async def test_a_busy_branch_beats_a_fresher_one_on_both_paths(self):
        # Measured in production: the branch of the newest scan is not the branch
        # the project lives on. Whichever branch each path picks decides every
        # field it reports, down to first_scan_date.
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


class TestTheLiveWalkIsAlwaysFullyCovered:
    """The walk reads the scans coverage is measured against, so it never reports partial."""

    @staticmethod
    def _retry_storm_project(pid: str) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
        """Ten in-window scans of which eight are CI retries of one commit."""
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

    @staticmethod
    async def _compare(projects, scans, deps):
        return await compute_update_frequency_comparison(
            projects=projects,
            scan_repo=FakeScanRepo(scans),
            dep_repo=FakeDepRepo(deps),
            analysis_repo=FakeAnalysisRepo([]),
        )

    @pytest.mark.asyncio
    async def test_a_retry_storm_leaves_a_project_fully_covered(self):
        # Eight of ten scans are CI retries of one commit. Both read paths give a run
        # one bar, so counting the retries as missing coverage would take a healthy
        # project out of the ranking for scanning too often.
        scans, deps = self._retry_storm_project("proj-retry")

        result = await self._compare([{"_id": "proj-retry", "name": "Retry"}], scans, deps)

        row = result.projects[0]
        assert row.data_status == "ready"
        assert (row.scan_count, row.total_updates) == (3, 1)
        assert result.partial_projects == 0

    @pytest.mark.asyncio
    async def test_scans_older_than_the_window_do_not_make_a_project_look_partial(self):
        # Coverage is measured against the window the numbers describe, not the
        # project's whole history, which no window could ever cover.
        scans, deps = self._steady_project("proj-ready")
        scans += [_scan_days_ago(f"ancient-{i}", 200 + i, project_id="proj-ready") for i in range(100)]

        result = await self._compare([{"_id": "proj-ready", "name": "Ready"}], scans, deps)

        assert [p.data_status for p in result.projects] == ["ready"]

    @pytest.mark.asyncio
    async def test_scans_the_walk_cannot_date_leave_coverage_alone(self):
        # An archive restore can insert a scan date as text. A range match on a date
        # does not select those, so they leave the window on both sides at once --
        # the walk cannot place them on a timeline and coverage does not expect them.
        scans, deps = self._steady_project("proj-thin")
        scans += [
            _scan_days_ago(f"undated-{i}", 20 + i, project_id="proj-thin") | {"created_at": "not a date"}
            for i in range(8)
        ]

        result = await self._compare([{"_id": "proj-thin", "name": "Thin"}], scans, deps)

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
