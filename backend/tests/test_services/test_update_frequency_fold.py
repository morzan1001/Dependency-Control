"""Tests for the pure update-frequency fold over per-scan delta documents."""

from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.schemas.analytics import ScanTimelineEntry
from app.services.release_history import UpstreamCadenceMetrics
from app.services.update_frequency import DAYS_PER_MONTH, compute_trend
from app.services.update_frequency_fold import (
    FoldedWindow,
    accounted_commits,
    fold_window,
    select_window,
)

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _at(days: float) -> datetime:
    return BASE + timedelta(days=days)


def _sample(name: str, kind: str = "patch", old: str = "1.0.0", new: str = "1.0.1") -> dict[str, Any]:
    return {"n": name, "t": "npm", "p": f"pkg:npm/{name}@{new}", "ov": old, "nv": new, "k": kind, "wo": True}


def _delta(
    scan_id: str,
    day: float,
    *,
    patch: int = 0,
    minor: int = 0,
    major: int = 0,
    unknown: int = 0,
    downgrade: int = 0,
    outdated_count: int | None = 0,
    added: Sequence[str] = (),
    resolved: Sequence[str] = (),
    dep_count: int = 100,
    commit_hash: str | None = None,
    eco: dict[str, int] | None = None,
    samples: Sequence[dict[str, Any]] = (),
    error: str | None = None,
    naive: bool = False,
    project_id: str = "p1",
    branch: str = "main",
) -> dict[str, Any]:
    """A scan_update_deltas document with every field the writer stores.

    Predecessor links are left unset; ``_chain`` fills them the way the writer does.
    """
    created = _at(day)
    if naive:
        created = created.replace(tzinfo=None)
    return {
        "_id": scan_id,
        "project_id": project_id,
        "branch": branch,
        "scan_created_at": created,
        "commit_hash": commit_hash if commit_hash is not None else f"c-{scan_id}",
        "prev_scan_id": None,
        "prev_created_at": None,
        "is_baseline": True,
        "dep_count": dep_count,
        "updates": {
            "patch": patch,
            "minor": minor,
            "major": major,
            "unknown": unknown,
            "downgrade": downgrade,
        },
        "total_updates": patch + minor + major + unknown,
        "outdated_count": outdated_count,
        "outdated_added": list(added),
        "outdated_resolved": list(resolved),
        "eco": eco if eco is not None else {"npm": dep_count},
        "updates_sample": list(samples),
        "error": error,
        "schema_version": 1,
        "computed_at": BASE,
    }


def _chain(deltas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Link each delta to its predecessor the way the writer does: skipping unusable scans."""
    prev: dict[str, Any] | None = None
    for delta in deltas:
        delta["prev_scan_id"] = prev["_id"] if prev else None
        delta["prev_created_at"] = prev["scan_created_at"] if prev else None
        delta["is_baseline"] = prev is None
        if delta["dep_count"] > 0 and not delta["error"]:
            prev = delta
    return deltas


def _fold(
    deltas: list[dict[str, Any]],
    baseline_outdated: set[str] | None = None,
    window_days: int | None = 90,
) -> FoldedWindow:
    return fold_window(select_window(deltas), baseline_outdated, window_days)


# Five scans, ten days apart, in a 90-day window. Hand-computed in TestGoldenWindow.
def _golden_deltas() -> list[dict[str, Any]]:
    return _chain(
        [
            # The anchor's own counts compare against a scan outside the window and must be dropped.
            _delta("s0", 0, patch=99, outdated_count=4, dep_count=100),
            _delta("s1", 10, patch=3, minor=1, downgrade=1, outdated_count=4, added=["e"], resolved=["a"]),
            _delta("s2", 20, patch=2, major=1, outdated_count=3, resolved=["b"]),
            _delta("s3", 30, minor=2, unknown=1, outdated_count=5, added=["f", "g"]),
            _delta("s4", 40, patch=1, outdated_count=4, resolved=["e", "f"]),
        ]
    )


GOLDEN_BASELINE_OUTDATED = {"a", "b", "c", "d"}


def _fold_golden(window_days: int | None = 90) -> FoldedWindow:
    return _fold(_golden_deltas(), GOLDEN_BASELINE_OUTDATED, window_days)


class TestGoldenWindow:
    """patch 6, minor 3, major 1, unknown 1, downgrade 1 -> 11 updates over 4 intervals."""

    @pytest.mark.parametrize(
        ("field", "expected"),
        [
            ("scan_count", 5),
            ("total_updates", 11),
            ("patch_updates", 6),
            ("minor_updates", 3),
            ("major_updates", 1),
            ("unknown_updates", 1),
            ("downgrade_updates", 1),
            # 11 / 4 intervals
            ("updates_per_scan", 2.75),
            # 11 / (90 / 30.44)
            ("updates_per_month", 3.72),
            ("time_range_days", 40.0),
            # 40 days / 4 intervals
            ("avg_days_between_scans", 10.0),
            # {a,b,c,d} + {e} + {f,g}
            ("total_outdated_detected", 7),
            # {a} + {b} + {e,f}
            ("outdated_resolved", 4),
            # 4 / 7
            ("update_coverage_pct", 57.1),
            ("trend_direction", "deteriorating"),
            ("dominant_ecosystem", "npm"),
        ],
    )
    def test_scalar_fields(self, field: str, expected: Any) -> None:
        assert getattr(_fold_golden(), field) == expected

    def test_granularity_ratio(self) -> None:
        assert _fold_golden().granularity_ratio == {"patch": 0.55, "minor": 0.27, "major": 0.09, "unknown": 0.09}

    def test_window_boundary_dates(self) -> None:
        folded = _fold_golden()
        assert folded.first_scan_date == _at(0).isoformat()
        assert folded.last_scan_date == _at(40).isoformat()

    def test_trend_detail_compares_halves_of_the_non_baseline_timeline(self) -> None:
        # older [s1, s2] = 4, 3 updates / 4, 3 outdated; newer [s3, s4] = 3, 1 / 5, 4
        assert _fold_golden().trend_detail == "Updates/scan: 3.5 → 2.0. Outdated: 3.5 → 4.5"

    def test_timeline(self) -> None:
        timeline = _fold_golden().scan_timeline
        assert [(e.scan_id, e.updates_count, e.downgrades, e.outdated_count) for e in timeline] == [
            ("s0", 0, 0, 4),
            ("s1", 4, 1, 4),
            ("s2", 3, 0, 3),
            ("s3", 3, 0, 5),
            ("s4", 1, 0, 4),
        ]

    def test_timeline_carries_the_per_kind_split(self) -> None:
        entry = _fold_golden().scan_timeline[3]
        assert (entry.patch, entry.minor, entry.major, entry.unknown) == (0, 2, 0, 1)


class TestUpdatesPerMonth:
    def test_window_denominator_is_the_selected_window(self) -> None:
        # Same 11 updates, a 30.44-day window -> exactly the raw count.
        assert _fold(_golden_deltas(), GOLDEN_BASELINE_OUTDATED, 30).updates_per_month == round(
            11 / (30 / DAYS_PER_MONTH), 2
        )

    def test_window_denominator_ignores_the_observed_span(self) -> None:
        # The scans span 40 days; the 90-day window is what counts.
        assert _fold_golden().updates_per_month == 3.72

    def test_without_a_window_no_rate_is_reported(self) -> None:
        assert _fold_golden(window_days=None).updates_per_month is None

    def test_ci_cadence_cannot_change_the_rate(self) -> None:
        # Same 3 updates in the same 90-day window: minutes apart or months apart.
        burst = _chain([_delta("b0", 0.0), _delta("b1", 10 / 1440, patch=3)])
        spread = _chain([_delta("l0", 0.0), _delta("l1", 60.88, patch=3)])
        assert _fold(burst).updates_per_month == _fold(spread).updates_per_month == round(3 / (90 / DAYS_PER_MONTH), 2)


class TestCadence:
    def test_avg_interval_uses_the_real_span_not_the_display_floor(self) -> None:
        deltas = _chain([_delta("s0", 0), _delta("s1", 0.3, patch=1), _delta("s2", 0.6, patch=1)])
        folded = _fold(deltas)
        assert folded.avg_days_between_scans == 0.3
        assert folded.time_range_days == 1.0


class TestInputContract:
    def test_newest_first_input_is_rejected(self) -> None:
        deltas = _chain([_delta("s0", 0), _delta("s1", 10, patch=1)])
        with pytest.raises(ValueError, match="oldest first"):
            select_window(list(reversed(deltas)))

    def test_mixed_branches_are_rejected(self) -> None:
        deltas = _chain([_delta("s0", 0), _delta("s1", 10, patch=1, branch="feature/x")])
        with pytest.raises(ValueError, match="one project/branch"):
            select_window(deltas)

    def test_mixed_projects_are_rejected(self) -> None:
        deltas = _chain([_delta("s0", 0), _delta("s1", 10, patch=1, project_id="p2")])
        with pytest.raises(ValueError, match="one project/branch"):
            select_window(deltas)

    def test_equal_timestamps_are_accepted(self) -> None:
        deltas = _chain([_delta("s0", 5), _delta("s1", 5, patch=1)])
        assert [d["_id"] for d in select_window(deltas)] == ["s0", "s1"]


class TestChainContinuity:
    def test_a_broken_link_truncates_the_window_to_the_newest_run(self) -> None:
        deltas = _chain([_delta(f"s{i}", i * 10, patch=1) for i in range(5)])
        # s2 was never re-diffed against s1: its counts still cover the s0->s2 interval.
        deltas[2]["prev_scan_id"] = "s0"
        folded = _fold(deltas)
        assert [e.scan_id for e in folded.scan_timeline] == ["s2", "s3", "s4"]
        assert folded.total_updates == 2

    def test_an_intact_chain_keeps_every_scan(self) -> None:
        deltas = _chain([_delta(f"s{i}", i * 10, patch=1) for i in range(5)])
        assert [d["_id"] for d in select_window(deltas)] == ["s0", "s1", "s2", "s3", "s4"]

    def test_a_chain_restart_inside_the_window_becomes_the_anchor(self) -> None:
        deltas = _chain([_delta(f"s{i}", i * 10, patch=1) for i in range(4)])
        # The branch history before s2 was pruned, so s2 is a baseline of its own.
        deltas[2]["prev_scan_id"] = None
        assert [d["_id"] for d in select_window(deltas)] == ["s2", "s3"]


class TestSameCommitRuns:
    def test_ci_retries_of_one_commit_collapse_into_their_first_scan(self) -> None:
        real = _chain([_delta("s0", 0, commit_hash="c1"), _delta("s1", 10, patch=8, commit_hash="c2")])
        with_retries = _chain(
            [
                _delta("s0", 0, commit_hash="c1"),
                _delta("s1", 10, patch=8, commit_hash="c2"),
                *[_delta(f"r{i}", 10 + (i + 1) / 24, commit_hash="c2") for i in range(6)],
            ]
        )
        folded_real = _fold(real)
        folded_retries = _fold(with_retries)
        assert folded_retries.scan_count == folded_real.scan_count == 2
        assert folded_retries.updates_per_scan == folded_real.updates_per_scan == 8.0
        assert folded_retries.avg_days_between_scans == folded_real.avg_days_between_scans == 10.0
        assert folded_retries.trend_direction == folded_real.trend_direction == "unknown"

    def test_updates_of_the_first_scan_of_a_run_survive(self) -> None:
        deltas = _chain(
            [
                _delta("s0", 0, commit_hash="c1"),
                _delta("s1", 10, patch=3, commit_hash="c2"),
                _delta("s2", 11, commit_hash="c2"),
                _delta("s3", 20, patch=4, commit_hash="c3"),
            ]
        )
        folded = _fold(deltas)
        assert [e.scan_id for e in folded.scan_timeline] == ["s0", "s1", "s3"]
        assert folded.total_updates == 7

    def test_non_consecutive_reuse_of_a_commit_is_kept(self) -> None:
        # A revert back to an earlier commit is real movement, not a retry.
        deltas = _chain(
            [
                _delta("s0", 0, commit_hash="c1"),
                _delta("s1", 10, patch=2, commit_hash="c2"),
                _delta("s2", 20, downgrade=2, commit_hash="c1"),
            ]
        )
        assert [d["_id"] for d in select_window(deltas)] == ["s0", "s1", "s2"]


class TestShortWindows:
    def test_empty_window(self) -> None:
        folded = _fold([], {"a"})
        assert folded.scan_count == 0
        assert folded.first_scan_date == ""
        assert folded.last_scan_date == ""
        assert folded.scan_timeline == []
        assert folded.recent_updates == []
        assert folded.updates_per_month is None
        assert folded.update_coverage_pct is None
        assert folded.trend_direction == "unknown"
        assert folded.trend_detail == "Not enough scans to analyze (need at least 2)"

    def test_baseline_only(self) -> None:
        folded = _fold([_delta("s0", 3, outdated_count=4)], {"a", "b", "c", "d"})
        assert folded.scan_count == 1
        assert folded.first_scan_date == folded.last_scan_date == _at(3).isoformat()
        assert folded.total_updates == 0
        assert folded.time_range_days == 0.0
        assert folded.avg_days_between_scans == 0.0
        # A single scan measures no resolution, so coverage stays unmeasured.
        assert folded.total_outdated_detected == 0
        assert folded.update_coverage_pct is None
        assert folded.scan_timeline == []

    def test_window_that_collapses_to_one_usable_scan(self) -> None:
        deltas = _chain([_delta("s0", 0), _delta("s1", 1, dep_count=0), _delta("s2", 2, error="boom")])
        assert _fold(deltas).scan_count == 1


class TestUnusableScans:
    def test_sbom_less_scan_is_dropped(self) -> None:
        deltas = _chain(
            [
                _delta("s0", 0, outdated_count=2),
                _delta("s1", 10, patch=2, outdated_count=2),
                _delta("s2", 20, dep_count=0, outdated_count=0),
                _delta("s3", 30, patch=1, outdated_count=2),
            ]
        )
        folded = _fold(deltas, {"a", "b"})
        assert [e.scan_id for e in folded.scan_timeline] == ["s0", "s1", "s3"]
        assert folded.scan_count == 3
        assert folded.total_updates == 3

    def test_writer_failure_is_dropped(self) -> None:
        deltas = _chain(
            [
                _delta("s0", 0),
                _delta("s1", 10, patch=2),
                _delta("s2", 20, error="dependency read failed"),
                _delta("s3", 30, patch=1),
            ]
        )
        assert [e.scan_id for e in _fold(deltas).scan_timeline] == ["s0", "s1", "s3"]

    def test_the_anchor_is_the_oldest_usable_scan(self) -> None:
        deltas = _chain(
            [
                _delta("s0", 0, dep_count=0, error="boom", outdated_count=None),
                _delta("s1", 10, outdated_count=40),
                _delta("s2", 20, patch=2, outdated_count=40, added=["z"]),
            ]
        )
        window = select_window(deltas)
        assert [d["_id"] for d in window] == ["s1", "s2"]
        folded = fold_window(window, {f"p{i}" for i in range(40)}, 90)
        assert folded.first_scan_date == _at(10).isoformat()
        assert folded.total_outdated_detected == 41
        assert folded.update_coverage_pct == 0.0

    def test_dropped_scans_do_not_dilute_updates_per_scan(self) -> None:
        usable = _chain([_delta("s0", 0), _delta("s1", 10, patch=4)])
        with_empties = _chain([_delta("s0", 0), _delta("s1", 10, patch=4), _delta("s2", 20, dep_count=0)])
        assert _fold(usable).updates_per_scan == 4.0
        assert _fold(with_empties).updates_per_scan == 4.0


class TestAccountedCommits:
    """What the ledger reached over the stretch the fold covered, in commits."""

    @staticmethod
    def _over(deltas: list[dict[str, Any]]) -> int:
        return accounted_commits(deltas, select_window(deltas))

    def test_the_scans_the_fold_drops_on_purpose_leave_no_hole(self) -> None:
        # Same-commit retries and SBOM-less scans are dropped by design; counting the
        # folded documents instead would read this healthy branch as half measured.
        deltas = _chain(
            [
                _delta("s0", 0, commit_hash="c1"),
                _delta("s1", 10, patch=1, commit_hash="c2"),
                _delta("s2", 11, commit_hash="c2"),
                _delta("s3", 12, commit_hash="c2"),
                _delta("s4", 20, dep_count=0, commit_hash="c3"),
                _delta("s5", 30, patch=1, commit_hash="c4"),
            ]
        )
        assert len(select_window(deltas)) == 3
        assert self._over(deltas) == 4

    def test_a_scan_naming_no_commit_stands_for_itself(self) -> None:
        deltas = _chain([_delta("s0", 0, commit_hash=""), _delta("s1", 10, patch=1, commit_hash="")])
        assert self._over(deltas) == 2

    def test_everything_before_the_anchor_is_a_hole_the_fold_could_not_reach(self) -> None:
        deltas = _chain([_delta(f"s{i}", i * 10, patch=1) for i in range(5)])
        # The branch history before s3 was pruned, so the fold anchors there.
        deltas[3]["prev_scan_id"] = None
        assert [d["_id"] for d in select_window(deltas)] == ["s3", "s4"]
        assert self._over(deltas) == 2

    def test_a_delta_the_writer_failed_on_is_a_real_hole(self) -> None:
        intact = _chain([_delta(f"s{i}", i * 10, patch=1) for i in range(4)])
        broken = _chain(
            [
                _delta("s0", 0, patch=1),
                _delta("s1", 10, patch=1),
                _delta("s2", 20, error="dependency read failed"),
                _delta("s3", 30, patch=1),
            ]
        )
        assert self._over(intact) == 4
        assert self._over(broken) == 3


class TestCoverage:
    def test_never_outdated_is_none_not_zero(self) -> None:
        deltas = _chain([_delta("s0", 0), _delta("s1", 10, patch=1)])
        folded = _fold(deltas)
        assert folded.total_outdated_detected == 0
        assert folded.update_coverage_pct is None

    def test_outdated_but_nothing_resolved_is_zero_not_none(self) -> None:
        deltas = _chain([_delta("s0", 0, outdated_count=2), _delta("s1", 10, patch=1, outdated_count=2)])
        assert _fold(deltas, {"a", "b"}).update_coverage_pct == 0.0

    def test_full_coverage(self) -> None:
        deltas = _chain([_delta("s0", 0, outdated_count=2), _delta("s1", 10, resolved=["a", "b"], outdated_count=0)])
        assert _fold(deltas, {"a", "b"}).update_coverage_pct == 100.0

    def test_baseline_set_seeds_the_denominator(self) -> None:
        # outdated_added on the anchor is a diff against a pre-window scan; only
        # the full set passed in can size the denominator.
        deltas = _chain(
            [_delta("s0", 0, added=["a"], outdated_count=3), _delta("s1", 10, resolved=["a"], outdated_count=2)]
        )
        folded = _fold(deltas, {"a", "b", "c"})
        assert folded.total_outdated_detected == 3
        assert folded.update_coverage_pct == round(1 / 3 * 100, 1)


class TestMissingOutdatedAnalysis:
    """The writer reports the whole outdated set again once it has no measured
    predecessor to subtract, which is what keeps the denominator complete here."""

    def _backlog(self) -> set[str]:
        return {f"pkg-{i}" for i in range(40)}

    def test_a_gap_in_the_analysis_does_not_resolve_the_backlog(self) -> None:
        backlog = self._backlog()
        deltas = _chain(
            [
                _delta("s0", 0, outdated_count=40),
                _delta("s1", 10, patch=1, outdated_count=None),
                _delta("s2", 20, patch=1, outdated_count=40, added=sorted(backlog)),
            ]
        )
        folded = _fold(deltas, backlog)
        assert folded.total_outdated_detected == 40
        assert folded.outdated_resolved == 0
        assert folded.update_coverage_pct == 0.0

    def test_packages_that_go_outdated_across_a_gap_still_size_the_denominator(self) -> None:
        backlog = self._backlog()
        deltas = _chain(
            [
                _delta("s0", 0, outdated_count=40),
                _delta("s1", 10, patch=1, outdated_count=None),
                _delta("s2", 20, patch=1, outdated_count=41, added=sorted(backlog | {"late"})),
                _delta("s3", 30, patch=1, outdated_count=1, resolved=sorted(backlog)),
            ]
        )
        folded = _fold(deltas, backlog)
        assert folded.total_outdated_detected == 41
        assert folded.outdated_resolved == 40
        # Reading the gap as "nothing new went outdated" would report 100%.
        assert folded.update_coverage_pct == round(40 / 41 * 100, 1)

    def test_an_unmeasured_anchor_lets_the_next_scan_seed_the_backlog(self) -> None:
        deltas = _chain(
            [
                _delta("s0", 0, outdated_count=None),
                _delta("s1", 10, outdated_count=2, added=["a", "b"]),
                _delta("s2", 20, outdated_count=1, resolved=["a"]),
            ]
        )
        folded = _fold(deltas, None)
        assert folded.total_outdated_detected == 2
        assert folded.update_coverage_pct == 50.0

    def test_a_window_without_any_measurement_reports_no_coverage(self) -> None:
        deltas = _chain([_delta("s0", 0, outdated_count=None), _delta("s1", 10, patch=1, outdated_count=None)])
        folded = _fold(deltas, None)
        assert folded.total_outdated_detected == 0
        assert folded.update_coverage_pct is None

    def test_the_timeline_marks_an_unmeasured_scan(self) -> None:
        deltas = _chain(
            [
                _delta("s0", 0, outdated_count=5),
                _delta("s1", 10, patch=1, outdated_count=None),
                _delta("s2", 20, patch=1, outdated_count=5),
            ]
        )
        assert [e.outdated_count for e in _fold(deltas).scan_timeline] == [5, None, 5]

    def test_an_unmeasured_half_drops_the_backlog_signal_from_the_trend(self) -> None:
        counts = [None, None, 4, 4]
        deltas = _chain(
            [_delta("s0", 0, outdated_count=9)]
            + [_delta(f"s{i + 1}", (i + 1) * 10, patch=2, outdated_count=counts[i]) for i in range(4)]
        )
        direction, detail = _fold(deltas).trend_direction, _fold(deltas).trend_detail
        assert direction == "stable"
        assert "Outdated" not in detail


class TestDowngrades:
    def test_downgrades_are_counted_but_are_not_updates(self) -> None:
        deltas = _chain([_delta("s0", 0), _delta("s1", 10, downgrade=5), _delta("s2", 20, downgrade=5)])
        folded = _fold(deltas)
        assert folded.downgrade_updates == 10
        assert folded.total_updates == 0
        assert folded.updates_per_scan == 0.0
        assert folded.updates_per_month == 0.0
        assert folded.granularity_ratio == {"patch": 0.0, "minor": 0.0, "major": 0.0, "unknown": 0.0}
        assert [(e.updates_count, e.downgrades) for e in folded.scan_timeline] == [(0, 0), (0, 5), (0, 5)]


class TestRecentUpdates:
    def test_newest_first_across_scans(self) -> None:
        deltas = _chain(
            [
                _delta("s0", 0, samples=[_sample("anchor-pkg")]),
                _delta("s1", 10, patch=2, samples=[_sample("b"), _sample("a")]),
                _delta("s2", 20, patch=2, samples=[_sample("d"), _sample("c")]),
            ]
        )
        assert [e.package_name for e in _fold(deltas).recent_updates] == ["d", "c", "b", "a"]

    def test_event_fields_come_from_the_sample_and_the_scan_pair(self) -> None:
        deltas = _chain(
            [
                _delta("s0", 0),
                _delta("s1", 7, major=1, samples=[_sample("left-pad", kind="major", old="1.2.3", new="2.0.0")]),
            ]
        )
        event = _fold(deltas).recent_updates[0]
        assert event.package_name == "left-pad"
        assert event.package_type == "npm"
        assert event.purl == "pkg:npm/left-pad@2.0.0"
        assert event.old_version == "1.2.3"
        assert event.new_version == "2.0.0"
        assert event.update_type == "major"
        assert event.was_outdated is True
        assert event.scan_date == _at(7).isoformat()
        assert event.previous_scan_date == _at(0).isoformat()
        assert event.days_between_scans == 7

    def test_days_between_scans_is_floored_at_one(self) -> None:
        deltas = _chain([_delta("s0", 0), _delta("s1", 0.25, patch=1, samples=[_sample("a")])])
        assert _fold(deltas).recent_updates[0].days_between_scans == 1

    def test_capped_at_thirty(self) -> None:
        deltas = _chain(
            [_delta("s0", 0)]
            + [
                _delta(f"s{i}", i * 10, patch=20, samples=[_sample(f"p{i}-{j}") for j in range(20)])
                for i in range(1, 4)
            ]
        )
        recent = _fold(deltas).recent_updates
        assert len(recent) == 30
        # Newest scan first: its whole sample, then the next scan's.
        assert recent[0].package_name == "p3-0"
        assert recent[20].package_name == "p2-0"

    def test_anchor_samples_are_dropped(self) -> None:
        deltas = _chain(
            [
                _delta("s0", 0, samples=[_sample("anchor-pkg")]),
                _delta("s1", 10, patch=1, samples=[_sample("a")]),
            ]
        )
        assert [e.package_name for e in _fold(deltas).recent_updates] == ["a"]


class TestDominantEcosystem:
    @pytest.mark.parametrize(
        ("eco", "expected"),
        [
            ({"npm": 7, "pypi": 3}, "npm"),
            ({"npm": 6, "pypi": 4}, "mixed"),
            ({"npm": 5, "pypi": 5}, "mixed"),
            ({"golang": 10}, "golang"),
            ({}, None),
            ({"unknown": 10}, None),
            # Missing-PURL noise must not tilt the result.
            ({"npm": 7, "unknown": 100}, "npm"),
            ({"npm": 0, "pypi": 0}, None),
        ],
    )
    def test_from_the_newest_scan(self, eco: dict[str, int], expected: str | None) -> None:
        deltas = _chain([_delta("s0", 0, eco={"maven": 999}), _delta("s1", 10, eco=eco)])
        assert _fold(deltas).dominant_ecosystem == expected


class TestNaiveDatetimes:
    def test_mongo_naive_datetimes_are_read_as_utc(self) -> None:
        deltas = _chain([_delta("s0", 0, naive=True), _delta("s1", 10, patch=1, samples=[_sample("a")], naive=True)])
        folded = _fold(deltas)
        assert folded.first_scan_date == _at(0).isoformat()
        assert folded.recent_updates[0].previous_scan_date == _at(0).isoformat()
        assert folded.avg_days_between_scans == 10.0

    def test_mixed_naive_and_aware_datetimes(self) -> None:
        deltas = _chain([_delta("s0", 0, naive=True), _delta("s1", 10, patch=1)])
        assert _fold(deltas).time_range_days == 10.0


def _timeline(updates: Sequence[int], outdated: Sequence[int | None]) -> list[ScanTimelineEntry]:
    """Timeline with a leading baseline entry, as the fold builds it."""
    entries = [_entry("anchor", 0, 0, 0)]
    entries.extend(_entry(f"s{i}", i + 1, u, o) for i, (u, o) in enumerate(zip(updates, outdated, strict=True)))
    return entries


def _entry(scan_id: str, day: int, updates: int, outdated: int | None) -> ScanTimelineEntry:
    return ScanTimelineEntry(
        scan_id=scan_id,
        date=_at(day).isoformat(),
        updates_count=updates,
        outdated_count=outdated,
        patch=updates,
        minor=0,
        major=0,
    )


class TestTrend:
    @pytest.mark.parametrize(
        ("case", "updates", "outdated", "direction"),
        [
            # older avg 10 vs newer avg 11 == exactly 1.1x: the comparison is strict.
            ("updates at the 1.1 threshold", (10, 10, 11, 11), (0, 0, 0, 0), "stable"),
            ("updates just over 1.1", (10, 10, 12, 12), (0, 0, 0, 0), "improving"),
            # older avg 10 vs newer avg 9 == exactly 0.9x.
            ("updates at the 0.9 threshold", (10, 10, 9, 9), (0, 0, 0, 0), "stable"),
            ("updates just under 0.9", (10, 10, 8, 9), (0, 0, 0, 0), "deteriorating"),
            ("outdated at the 0.9 threshold", (5, 5, 5, 5), (10, 10, 9, 9), "stable"),
            ("outdated just under 0.9", (5, 5, 5, 5), (10, 10, 8, 9), "improving"),
            ("outdated at the 1.1 threshold", (5, 5, 5, 5), (10, 10, 11, 11), "stable"),
            ("outdated just over 1.1", (5, 5, 5, 5), (10, 10, 12, 12), "deteriorating"),
            ("more updates and more outdated", (10, 10, 20, 20), (10, 10, 20, 20), "stable"),
            ("three non-baseline entries", (10, 10, 1), (0, 0, 0), "unknown"),
            ("a shrinking backlog measured only in the newer half", (5, 5, 5, 5), (None, None, 1, 1), "stable"),
        ],
    )
    def test_thresholds(
        self, case: str, updates: tuple[int, ...], outdated: tuple[int | None, ...], direction: str
    ) -> None:
        assert compute_trend(_timeline(updates, outdated))[0] == direction, case

    def test_both_signals_improving_reports_improving(self) -> None:
        assert compute_trend(_timeline((10, 10, 20, 20), (10, 10, 5, 5)))[0] == "improving"

    def test_mixed_signals_report_stable_with_both_halves(self) -> None:
        direction, detail = compute_trend(_timeline((10, 10, 1, 1), (10, 10, 1, 1)))
        assert direction == "stable"
        assert detail == "Mixed signals. Outdated: 10.0 → 1.0. Updates/scan: 10.0 → 1.0"

    def test_odd_timeline_splits_two_against_three(self) -> None:
        direction, detail = compute_trend(_timeline((4, 4, 1, 1, 1), (0, 0, 0, 0, 0)))
        assert direction == "deteriorating"
        assert detail == "Updates/scan: 4.0 → 1.0"

    def test_fewer_than_four_non_baseline_entries_is_unknown(self) -> None:
        direction, detail = compute_trend(_timeline((1, 2, 3), (1, 2, 3)))
        assert direction == "unknown"
        assert detail == "Not enough scans to determine trend (need at least 5)"

    def test_a_fully_unmeasured_backlog_is_left_out_of_the_detail(self) -> None:
        direction, detail = compute_trend(_timeline((5, 5, 5, 5), (None, None, None, None)))
        assert direction == "stable"
        assert detail == "Consistent (~5.0 updates/scan)"

    def test_a_partly_measured_half_averages_what_was_measured(self) -> None:
        direction, detail = compute_trend(_timeline((5, 5, 5, 5), (10, None, 4, None)))
        assert direction == "improving"
        assert detail == "Outdated: 10.0 → 4.0"


class TestModelConstruction:
    def test_to_metrics_carries_every_folded_number(self) -> None:
        folded = _fold_golden()
        metrics = folded.to_metrics("p1", "Project One", branch="main")
        assert metrics.project_id == "p1"
        assert metrics.project_name == "Project One"
        assert metrics.branch == "main"
        assert metrics.scan_count == 5
        assert metrics.total_updates == 11
        assert metrics.updates_per_scan == 2.75
        assert metrics.updates_per_month == 3.72
        assert metrics.patch_updates == 6
        assert metrics.minor_updates == 3
        assert metrics.major_updates == 1
        assert metrics.unknown_updates == 1
        assert metrics.downgrade_updates == 1
        assert metrics.granularity_ratio == folded.granularity_ratio
        assert metrics.avg_days_between_scans == 10.0
        assert metrics.time_range_days == 40.0
        assert metrics.first_scan_date == folded.first_scan_date
        assert metrics.last_scan_date == folded.last_scan_date
        assert metrics.total_outdated_detected == 7
        assert metrics.outdated_resolved == 4
        assert metrics.update_coverage_pct == 57.1
        assert metrics.trend_direction == "deteriorating"
        assert metrics.trend_detail == folded.trend_detail
        assert metrics.dominant_ecosystem == "npm"
        assert metrics.scan_timeline == folded.scan_timeline
        assert metrics.recent_updates == folded.recent_updates
        assert metrics.slowest_packages == []

    def test_to_metrics_without_upstream_leaves_the_cadence_fields_unset(self) -> None:
        metrics = _fold_golden().to_metrics("p1", "Project One")
        assert metrics.upstream_releases_last_12m_median is None
        assert metrics.upstream_days_between_releases_median is None
        assert metrics.upstream_days_since_latest_release_median is None
        assert metrics.adoption_latency_days_median is None

    def test_to_metrics_maps_upstream_cadence(self) -> None:
        upstream = UpstreamCadenceMetrics(
            upstream_releases_last_12m_median=12.0,
            upstream_days_between_releases_median=30.0,
            upstream_days_since_latest_release_median=5.0,
            adoption_latency_days_median=2.5,
        )
        metrics = _fold_golden().to_metrics("p1", "Project One", upstream=upstream)
        assert metrics.upstream_releases_last_12m_median == 12.0
        assert metrics.upstream_days_between_releases_median == 30.0
        assert metrics.upstream_days_since_latest_release_median == 5.0
        assert metrics.adoption_latency_days_median == 2.5

    def test_to_summary(self) -> None:
        summary = _fold_golden().to_summary("p1", "Project One", team_name="Platform", branch="main", window_days=90)
        assert summary.project_id == "p1"
        assert summary.project_name == "Project One"
        assert summary.team_name == "Platform"
        assert summary.data_status == "ready"
        assert summary.branch == "main"
        assert summary.window_days == 90
        assert summary.total_updates == 11
        assert summary.scan_count == 5
        assert summary.updates_per_month == 3.72
        assert summary.update_coverage_pct == 57.1
        assert summary.patch_ratio == 0.55
        assert summary.trend_direction == "deteriorating"
        assert summary.total_outdated == 7
        assert summary.last_scan_date == _at(40).isoformat()

    def test_summary_keeps_unmeasured_coverage_none(self) -> None:
        deltas = _chain([_delta("s0", 0), _delta("s1", 10, patch=1)])
        summary = _fold(deltas).to_summary("p1", "Project One", window_days=90)
        assert summary.update_coverage_pct is None
        assert summary.team_name is None

    def test_a_partial_row_carries_the_folded_numbers_under_the_caveat(self) -> None:
        # The fold sums what it was given; only the caller knows the window held more.
        folded = _fold_golden()
        summary = folded.to_summary("p1", "Project One", window_days=90, data_status="partial")
        assert summary.data_status == "partial"
        assert (summary.scan_count, summary.total_updates) == (folded.scan_count, folded.total_updates)
        assert summary.updates_per_month == folded.updates_per_month
