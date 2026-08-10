"""Tests for update frequency analysis (version classification, trend, aggregates, streaming orchestrator)."""

import asyncio
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.schemas.analytics import ScanTimelineEntry
from app.services.release_history import ReleaseHistory, ReleaseInfo
from app.services.update_frequency import (
    _COMPARISON_CONCURRENCY,
    _aggregate_metrics,
    _compute_trend,
    _dominant_ecosystem,
    _empty_metrics,
    classify_version_change,
    compute_update_frequency,
    compute_update_frequency_comparison,
)


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
        direction, _ = _compute_trend([])
        assert direction == "unknown"

    def test_four_scans_returns_unknown(self):
        # Baseline + 3 real entries is still too little signal.
        timeline = [_baseline_entry()] + [_make_timeline_entry(i + 1, updates=2) for i in range(3)]
        direction, detail = _compute_trend(timeline)
        assert direction == "unknown"
        assert "enough" in detail.lower()

    def test_consistent_rate_returns_stable(self):
        timeline = [_baseline_entry()] + [_make_timeline_entry(i + 1, updates=2, outdated=5) for i in range(4)]
        direction, _ = _compute_trend(timeline)
        assert direction == "stable"

    def test_constant_rate_never_improving_regardless_of_length(self):
        # The structural zero of the baseline entry must not fabricate acceleration.
        for n in (4, 6, 9, 19):
            timeline = [_baseline_entry()] + [_make_timeline_entry(i + 1, updates=3, outdated=7) for i in range(n)]
            direction, _ = _compute_trend(timeline)
            assert direction == "stable", f"length {n} classified {direction}"

    def test_improving_trend(self):
        timeline = (
            [_baseline_entry()]
            + [_make_timeline_entry(i + 1, updates=1, outdated=10) for i in range(3)]
            + [_make_timeline_entry(i + 4, updates=10, outdated=10) for i in range(3)]
        )
        direction, _ = _compute_trend(timeline)
        assert direction == "improving"

    def test_conflicting_signals_return_stable(self):
        # Updates accelerate while the outdated backlog grows: not "improving".
        timeline = (
            [_baseline_entry()]
            + [_make_timeline_entry(i + 1, updates=1, outdated=2) for i in range(3)]
            + [_make_timeline_entry(i + 4, updates=10, outdated=30) for i in range(3)]
        )
        direction, detail = _compute_trend(timeline)
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
        scans = [
            {"_id": "s1", "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc)},
            {"_id": "s2", "created_at": datetime(2026, 1, 31, tzinfo=timezone.utc)},
        ]
        timeline = [_make_timeline_entry(0), _make_timeline_entry(1)]
        m = _aggregate_metrics(
            type_counter=Counter(),
            recent_events=[],
            completed_scans=scans,
            ever_outdated=set(),
            ever_resolved=set(),
            scan_timeline=timeline,
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
        scans = [
            {"_id": "s1", "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc)},
            {"_id": "s2", "created_at": datetime(2026, 1, 31, tzinfo=timezone.utc)},
        ]
        timeline = [_make_timeline_entry(0), _make_timeline_entry(1)]
        m = _aggregate_metrics(
            type_counter=Counter(),
            recent_events=[],
            completed_scans=scans,
            ever_outdated={"pkg-a", "pkg-b"},
            ever_resolved={"pkg-a"},
            scan_timeline=timeline,
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


class _FakeScanObj:
    """Mirrors the attribute access (.id/.created_at/...) of the real Scan model."""

    def __init__(self, doc: dict[str, Any]):
        self.id = doc["_id"]
        self.created_at = doc["created_at"]
        self.status = doc.get("status", "completed")
        self.branch = doc.get("branch", "main")
        self.commit_hash = doc.get("commit_hash")


def _matches_scan_query(scan: dict[str, Any], query: dict[str, Any]) -> bool:
    for field, cond in query.items():
        value = scan.get(field)
        if isinstance(cond, dict):
            if "$ne" in cond and value == cond["$ne"]:
                return False
            if "$nin" in cond and value in cond["$nin"]:
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
                matched.sort(key=lambda s: s[field], reverse=(order == -1))
        return matched

    async def find_one(self, query: dict[str, Any], sort: list[tuple[str, int]] | None = None) -> dict[str, Any] | None:
        matched = self._filtered(query, sort)
        return matched[0] if matched else None

    async def find_many(
        self,
        query: dict[str, Any],
        sort: list[tuple[str, int]] | None = None,
        skip: int = 0,
        limit: int | None = None,
        projection: dict[str, int] | None = None,
    ) -> list[_FakeScanObj]:
        # Mirrors ScanRepository.find_many: filter by the query (incl. status),
        # sort, then apply the limit — status is filtered BEFORE the limit.
        matched = self._filtered(query, sort)
        if limit is not None:
            matched = matched[skip : skip + limit]
        else:
            matched = matched[skip:]
        return [_FakeScanObj(s) for s in matched]


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
        return list(self._deps_by_scan.get(scan_id, []))


class _AnalysisResultStub:
    def __init__(self, scan_id: str, analyzer_name: str, result: dict[str, Any]):
        self.scan_id = scan_id
        self.analyzer_name = analyzer_name
        self.result = result


class FakeAnalysisRepo:
    def __init__(self, results: list[_AnalysisResultStub]):
        self._results = results
        self.find_many_calls: list[dict[str, Any]] = []

    async def find_many(self, query: dict[str, Any], limit: int = 1000) -> list[_AnalysisResultStub]:
        self.find_many_calls.append(query)
        scan_filter = query.get("scan_id")
        analyzer = query.get("analyzer_name")
        out = []
        for r in self._results:
            if isinstance(scan_filter, dict):
                ids = scan_filter.get("$in", [])
                if r.scan_id not in ids:
                    continue
            elif scan_filter is not None and r.scan_id != scan_filter:
                continue
            if analyzer is not None and r.analyzer_name != analyzer:
                continue
            out.append(r)
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


def _make_dep(scan_id: str, name: str, version: str, ptype: str = "pypi") -> dict[str, Any]:
    return {
        "scan_id": scan_id,
        "name": name,
        "version": version,
        "type": ptype,
        "purl": f"pkg:{ptype}/{name}@{version}",
    }


def _outdated_result(scan_id: str, entries: list[dict[str, str]]) -> _AnalysisResultStub:
    return _AnalysisResultStub(
        scan_id=scan_id,
        analyzer_name="outdated_packages",
        result={"outdated_dependencies": entries},
    )


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
        # Motor returns naive UTC datetimes; a tz-aware `since` cutoff and the
        # downstream date math must both survive that.
        naive = _BASE_SCAN_DATE.replace(tzinfo=None)
        scans = [
            {**_make_scan("s1", 0), "created_at": naive},
            {**_make_scan("s2", 30), "created_at": naive + timedelta(days=30)},
        ]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.1")],
        }
        m = await self._compute(scans, deps, since=_BASE_SCAN_DATE - timedelta(days=1))
        assert m.scan_count == 2
        assert m.first_scan_date.endswith("+00:00")
        assert m.last_scan_date.endswith("+00:00")

    @pytest.mark.asyncio
    async def test_same_commit_scan_storm_collapses(self):
        # 5 CI runs of one commit within a day, then a real new commit.
        scans = [
            _make_scan("s0", 0, commit_hash="aaa"),
            *[_make_scan(f"s{i}", 0, commit_hash="bbb") for i in range(1, 6)],
            _make_scan("s6", 1, commit_hash="ccc"),
        ]
        # Same commit -> identical dep sets.
        deps = {"s0": [_make_dep("s0", "pkg-a", "1.0.0")]}
        for i in range(1, 6):
            deps[f"s{i}"] = [_make_dep(f"s{i}", "pkg-a", "1.0.1")]
        deps["s6"] = [_make_dep("s6", "pkg-a", "1.1.0")]
        m = await self._compute(scans, deps)
        assert m.scan_count == 3
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
        old_core = self._raw_dep("s1", "jackson-core", "2.21.4", "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.21.4")
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
        ]
        m = await self._compute(deps, results)
        assert m.outdated_resolved == 0
        assert m.update_coverage_pct == 0.0


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
        assert m.updates_per_month == 0.0
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
        assert m.updates_per_month == pytest.approx(1 / (1.5 / 30.44), abs=0.01)

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
    async def test_since_parameter_filters_scans(self):
        scans = [_make_scan(f"s{i}", i) for i in range(20)]
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")] for i in range(20)}
        scan_repo = FakeScanRepo(scans)
        dep_repo = FakeDepRepo(deps)
        analysis_repo = FakeAnalysisRepo([])

        # Restrict to scans on or after day 14 -> s14..s19 (6 scans)
        cutoff = _BASE_SCAN_DATE + timedelta(days=14)
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=scan_repo,
            dep_repo=dep_repo,
            analysis_repo=analysis_repo,
            since=cutoff,
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
    async def test_since_overrides_max_scans_when_window_holds_more(self):
        # 30 daily scans, max_scans=5, since=very-old: the entire since window must be honored (hard_limit-bounded load).
        scans = [_make_scan(f"s{i}", i) for i in range(30)]
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")] for i in range(30)}
        scan_repo = FakeScanRepo(scans)
        dep_repo = FakeDepRepo(deps)
        analysis_repo = FakeAnalysisRepo([])

        cutoff = _BASE_SCAN_DATE - timedelta(days=1)  # before everything
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=scan_repo,
            dep_repo=dep_repo,
            analysis_repo=analysis_repo,
            max_scans=5,
            since=cutoff,
        )
        assert m.scan_count == 30, "since cutoff should trump max_scans when the window contains more scans"

    @pytest.mark.asyncio
    async def test_hard_limit_caps_runaway_queries(self):
        # 5000 scans + since=epoch -> the hard_limit safety cap must keep
        # us from loading the whole collection.
        scans = [_make_scan(f"s{i}", i) for i in range(2500)]
        deps = {f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")] for i in range(2500)}
        scan_repo = FakeScanRepo(scans)
        dep_repo = FakeDepRepo(deps)
        analysis_repo = FakeAnalysisRepo([])

        cutoff = _BASE_SCAN_DATE - timedelta(days=1)
        m = await compute_update_frequency(
            project_id="proj-1",
            project_name="Project",
            scan_repo=scan_repo,
            dep_repo=dep_repo,
            analysis_repo=analysis_repo,
            max_scans=5,
            since=cutoff,
            hard_limit=100,
        )
        # Only the newest 100 scans should be analysed under the safety cap.
        assert m.scan_count == 100

    @pytest.mark.asyncio
    async def test_summary_carries_dominant_ecosystem(self):
        # All deps are pypi -> dominant_ecosystem on the comparison summary
        # must reflect that, so the UI/caller can group fairly.
        scans = [_make_scan("s1", 0), _make_scan("s2", 30)]
        deps = {
            "s1": [_make_dep("s1", "pkg-a", "1.0.0", "pypi")],
            "s2": [_make_dep("s2", "pkg-a", "1.0.1", "pypi")],
        }
        scan_repo = FakeScanRepo(scans)
        dep_repo = FakeDepRepo(deps)
        analysis_repo = FakeAnalysisRepo([])

        result = await compute_update_frequency_comparison(
            projects=[{"_id": "proj-1", "name": "Project One"}],
            scan_repo=scan_repo,
            dep_repo=dep_repo,
            analysis_repo=analysis_repo,
        )

        assert len(result.projects) == 1
        assert result.projects[0].dominant_ecosystem == "pypi"

    @pytest.mark.asyncio
    async def test_comparison_emits_per_ecosystem_winners(self):
        # Two projects in different ecosystems; the global best_project
        # is still set, but the per-ecosystem maps let UIs avoid claiming
        # an npm project "beat" a maven project on raw updates_per_month.
        scans_a = [
            {**_make_scan("a1", 0, project_id="proj-py"), "project_id": "proj-py"},
            {**_make_scan("a2", 30, project_id="proj-py"), "project_id": "proj-py"},
        ]
        scans_b = [
            {**_make_scan("b1", 0, project_id="proj-js"), "project_id": "proj-js"},
            {**_make_scan("b2", 30, project_id="proj-js"), "project_id": "proj-js"},
        ]
        deps = {
            "a1": [_make_dep("a1", "pkg-py", "1.0.0", "pypi")],
            "a2": [_make_dep("a2", "pkg-py", "1.0.1", "pypi")],
            "b1": [_make_dep("b1", "pkg-js", "1.0.0", "npm")],
            "b2": [_make_dep("b2", "pkg-js", "1.0.1", "npm")],
        }
        scan_repo = FakeScanRepo(scans_a + scans_b)
        dep_repo = FakeDepRepo(deps)
        analysis_repo = FakeAnalysisRepo([])

        result = await compute_update_frequency_comparison(
            projects=[
                {"_id": "proj-py", "name": "Python Project"},
                {"_id": "proj-js", "name": "JS Project"},
            ],
            scan_repo=scan_repo,
            dep_repo=dep_repo,
            analysis_repo=analysis_repo,
        )

        assert "pypi" in result.best_per_ecosystem
        assert "npm" in result.best_per_ecosystem
        assert result.best_per_ecosystem["pypi"] == "Python Project"
        assert result.best_per_ecosystem["npm"] == "JS Project"

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
        for q in analysis_repo.find_many_calls:
            scan_filter = q.get("scan_id")
            assert not isinstance(scan_filter, dict), (
                f"analysis_repo.find_many called with bulk scan filter {scan_filter}; expected per-scan loading"
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
            async def find_many(self, *args, **kwargs):
                await asyncio.sleep(0)  # yield to the loop while holding the semaphore
                return await super().find_many(*args, **kwargs)

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
            all_scans.append(_make_scan(s1, 0, project_id=pid))
            all_scans.append(_make_scan(s2, 30, project_id=pid))
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
