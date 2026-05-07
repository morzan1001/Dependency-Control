"""Tests for update frequency analysis — version classification, trend, aggregates,
and the streaming orchestrator."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest

from app.schemas.analytics import ScanTimelineEntry
from app.services.update_frequency import (
    _aggregate_metrics,
    _compute_trend,
    _empty_metrics,
    classify_version_change,
    compute_update_frequency,
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

    # A2: identical versions must NOT be classified as "patch"
    def test_identical_versions_returns_none(self):
        assert classify_version_change("1.0.0", "1.0.0") == "none"

    def test_identical_with_v_prefix_returns_none(self):
        assert classify_version_change("v1.0.0", "1.0.0") == "none"

    # A3: pre-release identifiers must be respected
    def test_stable_to_prerelease_is_not_no_change(self):
        # 1.0.0 -> 1.0.0-beta1 is a real change (downgrade), must not be "none"
        result = classify_version_change("1.0.0", "1.0.0-beta1")
        assert result != "none"
        assert result in ("patch", "prerelease")

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


class TestComputeTrend:
    # A4: trend is "unknown" when there isn't enough data, not "stable"
    def test_empty_timeline_returns_unknown(self):
        direction, _ = _compute_trend([])
        assert direction == "unknown"

    def test_three_scans_returns_unknown(self):
        timeline = [_make_timeline_entry(i, updates=2) for i in range(3)]
        direction, detail = _compute_trend(timeline)
        assert direction == "unknown"
        assert "4" in detail or "enough" in detail.lower()

    def test_four_scans_consistent_returns_stable(self):
        timeline = [_make_timeline_entry(i, updates=2, outdated=5) for i in range(4)]
        direction, _ = _compute_trend(timeline)
        assert direction == "stable"

    def test_improving_trend(self):
        timeline = (
            [_make_timeline_entry(i, updates=1, outdated=10) for i in range(3)]
            + [_make_timeline_entry(i + 3, updates=10, outdated=10) for i in range(3)]
        )
        direction, _ = _compute_trend(timeline)
        assert direction == "improving"


class TestEmptyMetrics:
    # A4: empty metrics use "unknown" trend, not "stable"
    def test_empty_metrics_trend_is_unknown(self):
        m = _empty_metrics("p1", "Project One", 0, "")
        assert m.trend_direction == "unknown"

    # A6: empty metrics have null coverage (no outdated history yet)
    def test_empty_metrics_coverage_is_none(self):
        m = _empty_metrics("p1", "Project One", 0, "")
        assert m.update_coverage_pct is None


class TestAggregateMetricsCoverage:
    # A6: coverage is None when nothing has ever been outdated
    def test_coverage_none_when_no_outdated(self):
        scans = [
            {"_id": "s1", "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc)},
            {"_id": "s2", "created_at": datetime(2026, 1, 31, tzinfo=timezone.utc)},
        ]
        timeline = [_make_timeline_entry(0), _make_timeline_entry(1)]
        m = _aggregate_metrics(
            all_events=[],
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
            all_events=[],
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


class FakeScanRepo:
    def __init__(self, scans: List[Dict[str, Any]]):
        # scans must include _id, created_at, status, project_id
        self._scans = scans

    async def find_by_project(
        self,
        project_id: str,
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "created_at",
        sort_order: int = -1,
        projection: Optional[Dict[str, int]] = None,
    ) -> List[Dict[str, Any]]:
        matched = [s for s in self._scans if s["project_id"] == project_id]
        matched.sort(key=lambda s: s["created_at"], reverse=(sort_order == -1))
        return matched[skip : skip + limit]


class FakeDepRepo:
    def __init__(self, deps_by_scan: Dict[str, List[Dict[str, Any]]]):
        self._deps_by_scan = deps_by_scan
        self.calls: List[str] = []  # tracks every find_all query for assertions

    async def find_all(
        self,
        query: Dict[str, Any],
        projection: Optional[Dict[str, int]] = None,
    ) -> List[Dict[str, Any]]:
        scan_id = query.get("scan_id")
        self.calls.append(scan_id)
        return list(self._deps_by_scan.get(scan_id, []))


class _AnalysisResultStub:
    def __init__(self, scan_id: str, analyzer_name: str, result: Dict[str, Any]):
        self.scan_id = scan_id
        self.analyzer_name = analyzer_name
        self.result = result


class FakeAnalysisRepo:
    def __init__(self, results: List[_AnalysisResultStub]):
        self._results = results
        self.find_many_calls: List[Dict[str, Any]] = []

    async def find_many(self, query: Dict[str, Any], limit: int = 1000) -> List[_AnalysisResultStub]:
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


def _make_scan(scan_id: str, day_offset: int, project_id: str = "proj-1") -> Dict[str, Any]:
    return {
        "_id": scan_id,
        "created_at": _BASE_SCAN_DATE + timedelta(days=day_offset),
        "status": "completed",
        "project_id": project_id,
    }


def _make_dep(scan_id: str, name: str, version: str, ptype: str = "pypi") -> Dict[str, Any]:
    return {"scan_id": scan_id, "name": name, "version": version, "type": ptype, "purl": ""}


def _outdated_result(scan_id: str, entries: List[Dict[str, str]]) -> _AnalysisResultStub:
    return _AnalysisResultStub(
        scan_id=scan_id,
        analyzer_name="outdated_packages",
        result={"outdated_dependencies": entries},
    )


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
        deps = {
            f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")]
            for i in range(50)
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
        deps = {
            f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")]
            for i in range(30)
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
            max_scans=5,
        )

        assert m.scan_count == 5
        # If the orchestrator used the oldest 5 (legacy bug), recent_updates would
        # show versions like 1.0.1..1.0.4. The new behavior must show 1.0.26..1.0.29.
        latest_versions = {e.new_version for e in m.recent_updates}
        assert "1.0.29" in latest_versions
        assert "1.0.0" not in latest_versions

    @pytest.mark.asyncio
    async def test_since_parameter_filters_scans(self):
        scans = [_make_scan(f"s{i}", i) for i in range(20)]
        deps = {
            f"s{i}": [_make_dep(f"s{i}", "pkg-a", f"1.0.{i}")]
            for i in range(20)
        }
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
    async def test_outdated_loaded_per_pair_not_upfront(self):
        # The streaming refactor must NOT issue a single bulk find_many across all scan_ids.
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
                f"analysis_repo.find_many called with bulk scan filter {scan_filter}; "
                "expected per-scan loading"
            )
