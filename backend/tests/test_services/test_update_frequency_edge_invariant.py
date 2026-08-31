"""Both read paths sum every consecutive pair of window scans, and bar them the same way.

A same-commit run merges its scans into one timeline bar; it never removes a pair
from a sum. These tests run one seeded history through the live walk and through
the real writer plus fold, and compare them on the very field list the parity gate
uses, with the gate's own exceptions.
"""

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch

import pytest

from app.api.v1.endpoints.analytics import update_frequency as endpoint
from app.api.v1.endpoints.analytics.update_frequency import _fold_branch, _rollup_project_metrics
from app.repositories import AnalysisResultRepository, DependencyRepository, ScanRepository
from app.repositories.update_frequency import BranchWindowActivity
from app.schemas.analytics import ScanTimelineEntry, UpdateFrequencyMetrics
from app.services.update_frequency import (
    compute_update_frequency,
    fold_runs_into_bars,
    same_commit_runs,
)
from app.services.update_frequency_fold import accounted_commits, fold_window, select_window, window_bars
from app.services.update_frequency_rollup import record_scan_update_delta
from scripts.verify_update_frequency_parity import KnownCauses, compare_metrics
from tests.mocks.fake_mongo import FakeDatabase

PROJECT = "proj-1"
BRANCH = "main"
WINDOW_DAYS = 90
NOW = datetime.now(tz=timezone.utc)

# The gate excuses these three by name; nothing here may hide behind them.
_NO_KNOWN_CAUSES = KnownCauses(capped_sample_scans=0, live_updates_saturated=False, slowest_packages_capped=False)


def _days_ago(days: float) -> datetime:
    return NOW - timedelta(days=days)


async def _seed_scan(
    db: FakeDatabase,
    scan_id: str,
    created_at: datetime,
    packages: dict[str, str],
    outdated: tuple[str, ...] | None = (),
    *,
    commit_hash: str | None = None,
    branch: str = BRANCH,
) -> None:
    """``outdated=None`` seeds no outdated analysis; ``()`` seeds one that found nothing."""
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": PROJECT,
            "branch": branch,
            "created_at": created_at,
            "commit_hash": commit_hash or f"commit-{scan_id}",
            "status": "completed",
            "is_rescan": False,
        }
    )
    for name, version in packages.items():
        await db.dependencies.insert_one(
            {
                "_id": f"{scan_id}:{name}",
                "scan_id": scan_id,
                "project_id": PROJECT,
                "name": name,
                "version": version,
                "type": "library",
                "purl": f"pkg:pypi/{name}@{version}",
            }
        )
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


async def _live(db: FakeDatabase) -> UpdateFrequencyMetrics:
    return await compute_update_frequency(
        project_id=PROJECT,
        project_name="Project One",
        scan_repo=ScanRepository(db),
        dep_repo=DependencyRepository(db),
        analysis_repo=AnalysisResultRepository(db),
        window_days=WINDOW_DAYS,
    )


async def _rollup(db: FakeDatabase) -> UpdateFrequencyMetrics | None:
    return await _rollup_project_metrics(
        db, {"_id": PROJECT, "name": "Project One", "default_branch": None, "deleted_branches": []}, WINDOW_DAYS
    )


async def _both(db: FakeDatabase) -> tuple[UpdateFrequencyMetrics, UpdateFrequencyMetrics]:
    live = await _live(db)
    rolled = await _rollup(db)
    assert rolled is not None, "the ledger declined a history it was seeded for"
    return live, rolled


def _differences(live: UpdateFrequencyMetrics, rolled: UpdateFrequencyMetrics) -> dict[str, tuple[Any, Any]]:
    """Every gate field the two paths disagree on, minus the deviations the gate names."""
    return {d.field: (d.live, d.rollup) for d in compare_metrics(live, rolled, _NO_KNOWN_CAUSES) if d.reason is None}


def _timeline_ids(metrics: UpdateFrequencyMetrics) -> list[str]:
    return [entry.scan_id for entry in metrics.scan_timeline]


def _assert_bars_tile_the_pairs(metrics: UpdateFrequencyMetrics) -> None:
    """The bars partition the window's pairs, so both totals reconstruct from the timeline."""
    assert sum(entry.updates_count for entry in metrics.scan_timeline) == metrics.total_updates
    assert metrics.updates_per_scan == round(metrics.total_updates / (metrics.scan_count - 1), 2)


async def _assert_identical(db: FakeDatabase) -> UpdateFrequencyMetrics:
    live, rolled = await _both(db)
    assert _differences(live, rolled) == {}
    _assert_bars_tile_the_pairs(live)
    _assert_bars_tile_the_pairs(rolled)
    return live


class TestMovementInsideARun:
    """The two histories that first showed the collapse and the delta chain disagreeing."""

    @pytest.mark.asyncio
    async def test_a_backlog_resolved_inside_a_retry_run_is_counted_on_both_paths(self):
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {"requests": "2.0.0", "flask": "3.0.0"}, ("flask",), commit_hash="cA")
        await _seed_scan(db, "a2", _days_ago(59), {"requests": "2.0.0", "flask": "3.0.0"}, (), commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(50), {"requests": "2.0.1", "flask": "3.0.0"}, (), commit_hash="cB")
        await _build_ledger(db)

        live = await _assert_identical(db)

        assert (live.total_outdated_detected, live.outdated_resolved) == (1, 1)
        assert live.update_coverage_pct == 100.0

    @pytest.mark.asyncio
    async def test_an_sbom_that_moves_inside_a_retry_run_is_an_update_on_both_paths(self):
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {"requests": "2.0.0"}, commit_hash="cA")
        await _seed_scan(db, "a2", _days_ago(59), {"requests": "2.1.0"}, commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(50), {"requests": "2.1.0"}, commit_hash="cB")
        await _build_ledger(db)

        live = await _assert_identical(db)

        assert live.total_updates == 1
        assert _timeline_ids(live) == ["a2", "b1"]

    @pytest.mark.asyncio
    async def test_the_anchor_bar_carries_the_movement_of_its_own_run(self):
        """[a1 a2 a3][b1 b2][c1]: five pairs, three bars, and every pair summed once."""
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {"p": "1.0.0"}, ("p",), commit_hash="cA")
        await _seed_scan(db, "a2", _days_ago(59), {"p": "1.0.1"}, ("p",), commit_hash="cA")
        await _seed_scan(db, "a3", _days_ago(58), {"p": "1.0.2"}, ("p",), commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(50), {"p": "1.1.0"}, (), commit_hash="cB")
        await _seed_scan(db, "b2", _days_ago(49), {"p": "1.2.0"}, (), commit_hash="cB")
        await _seed_scan(db, "c1", _days_ago(40), {"p": "1.3.0"}, (), commit_hash="cC")
        await _build_ledger(db)

        live = await _assert_identical(db)

        assert _timeline_ids(live) == ["a3", "b2", "c1"]
        assert [entry.updates_count for entry in live.scan_timeline] == [2, 2, 1]
        assert live.total_updates == 5
        assert live.scan_count == 3


class TestRunPlacement:
    @pytest.mark.asyncio
    async def test_a_run_at_the_window_start(self):
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {"p": "1.0.0"}, ("p",), commit_hash="cA")
        await _seed_scan(db, "a2", _days_ago(59), {"p": "1.1.0"}, ("p",), commit_hash="cA")
        await _seed_scan(db, "a3", _days_ago(58), {"p": "1.2.0"}, (), commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(50), {"p": "1.3.0"}, (), commit_hash="cB")
        await _seed_scan(db, "c1", _days_ago(40), {"p": "1.4.0"}, (), commit_hash="cC")
        await _build_ledger(db)

        live = await _assert_identical(db)

        assert _timeline_ids(live) == ["a3", "b1", "c1"]
        assert live.first_scan_date == _days_ago(58).isoformat()

    @pytest.mark.asyncio
    async def test_a_run_at_the_window_end(self):
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {"p": "1.0.0"}, commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(50), {"p": "1.1.0"}, commit_hash="cB")
        await _seed_scan(db, "c1", _days_ago(40), {"p": "1.2.0"}, commit_hash="cC")
        await _seed_scan(db, "c2", _days_ago(39), {"p": "1.3.0"}, commit_hash="cC")
        await _seed_scan(db, "c3", _days_ago(38), {"p": "1.4.0"}, commit_hash="cC")
        await _build_ledger(db)

        live = await _assert_identical(db)

        assert _timeline_ids(live) == ["a1", "b1", "c3"]
        # The newest bar is dated by the newest scan of its run, not by the commit's first try.
        assert live.last_scan_date == _days_ago(38).isoformat()
        assert live.scan_timeline[-1].updates_count == 3

    @pytest.mark.asyncio
    async def test_a_history_that_is_one_single_run_supports_no_comparison(self):
        db = FakeDatabase()
        # The SBOM moves inside the run, so a guard counting scans instead of bars would
        # report five updates against one bar rather than declining the comparison.
        for index in range(5):
            await _seed_scan(db, f"r{index}", _days_ago(60 - index), {"p": f"1.{index}.0"}, commit_hash="cA")
        await _build_ledger(db)

        live = await _live(db)

        assert live.scan_count == 1
        assert live.total_updates == 0
        # A single bar cannot be divided by its intervals; the ledger declines rather than fold it.
        assert await _rollup(db) is None
        assert _fold_branch(BRANCH, await _deltas(db), _activity(5)).status == "insufficient_data"

    @pytest.mark.asyncio
    async def test_runs_alternating_with_single_scans(self):
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {"p": "1.0.0"}, ("p",), commit_hash="cA")
        await _seed_scan(db, "a2", _days_ago(59), {"p": "1.0.0"}, ("p",), commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(55), {"p": "1.1.0"}, (), commit_hash="cB")
        await _seed_scan(db, "c1", _days_ago(50), {"p": "1.2.0"}, ("p",), commit_hash="cC")
        await _seed_scan(db, "c2", _days_ago(49), {"p": "1.2.0"}, ("p",), commit_hash="cC")
        await _seed_scan(db, "c3", _days_ago(48), {"p": "1.3.0"}, (), commit_hash="cC")
        await _seed_scan(db, "d1", _days_ago(40), {"p": "1.4.0"}, (), commit_hash="cD")
        await _build_ledger(db)

        live = await _assert_identical(db)

        assert _timeline_ids(live) == ["a2", "b1", "c3", "d1"]
        assert live.total_updates == 4

    @pytest.mark.asyncio
    async def test_a_run_whose_first_member_carries_no_sbom(self):
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {}, commit_hash="cA")
        await _seed_scan(db, "a2", _days_ago(59), {"p": "1.0.0"}, commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(50), {"p": "1.1.0"}, commit_hash="cB")
        await _seed_scan(db, "b2", _days_ago(49), {"p": "1.2.0"}, commit_hash="cB")
        await _build_ledger(db)

        live = await _assert_identical(db)

        # The SBOM-less scan measured nothing, so neither path keeps it or its run membership.
        assert _timeline_ids(live) == ["a2", "b2"]
        assert live.total_updates == 2

    @pytest.mark.asyncio
    async def test_a_version_that_returns_to_itself_inside_a_run(self):
        """a->b->a across one commit: two classified changes, one of them a downgrade."""
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {"p": "1.0.0"}, commit_hash="cA")
        await _seed_scan(db, "a2", _days_ago(59), {"p": "1.1.0"}, commit_hash="cA")
        await _seed_scan(db, "a3", _days_ago(58), {"p": "1.0.0"}, commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(50), {"p": "1.0.0"}, commit_hash="cB")
        await _build_ledger(db)

        live = await _assert_identical(db)

        assert (live.total_updates, live.downgrade_updates) == (1, 1)
        assert _timeline_ids(live) == ["a3", "b1"]
        assert live.scan_timeline[0].downgrades == 1


class TestBarRepresentatives:
    @pytest.mark.asyncio
    async def test_the_backlog_of_a_run_is_read_from_its_last_member(self):
        """The run's newest scan cleared its backlog, so the bar it names is clear too."""
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {"p": "1.0.0"}, ("p",), commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(50), {"p": "1.1.0"}, ("p",), commit_hash="cB")
        await _seed_scan(db, "b2", _days_ago(49), {"p": "1.1.0"}, (), commit_hash="cB")
        await _build_ledger(db)

        live = await _assert_identical(db)

        assert [entry.outdated_count for entry in live.scan_timeline] == [1, 0]
        # p was outdated at a1 and again at b1, but only a1 named a bar of its own.
        assert live.slowest_packages == []

    @pytest.mark.asyncio
    async def test_a_run_whose_last_member_carries_no_outdated_analysis(self):
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {"p": "1.0.0"}, ("p",), commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(50), {"p": "1.1.0"}, ("p",), commit_hash="cB")
        await _seed_scan(db, "b2", _days_ago(49), {"p": "1.1.0"}, None, commit_hash="cB")
        await _build_ledger(db)

        live = await _assert_identical(db)

        assert [entry.outdated_count for entry in live.scan_timeline] == [1, None]
        # The newest bar measured nothing, so the backlog still stands where it was last seen.
        assert [(p.name, p.scans_outdated) for p in live.slowest_packages] == [("p", 1)]

    @pytest.mark.asyncio
    async def test_a_package_outdated_across_a_whole_run_counts_once(self):
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {"p": "1.0.0"}, ("p",), commit_hash="cA")
        await _seed_scan(db, "a2", _days_ago(59), {"p": "1.0.0"}, ("p",), commit_hash="cA")
        await _seed_scan(db, "a3", _days_ago(58), {"p": "1.0.0"}, ("p",), commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(50), {"p": "1.0.0"}, ("p",), commit_hash="cB")
        await _build_ledger(db)

        live = await _assert_identical(db)

        assert [(p.name, p.scans_outdated) for p in live.slowest_packages] == [("p", 2)]
        assert live.slowest_packages[0].scans_outdated <= live.scan_count


class TestDataStatusIsUnmoved:
    @pytest.mark.asyncio
    async def test_a_retry_storm_still_accounts_for_every_commit(self):
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {"p": "1.0.0"}, commit_hash="cA")
        await _seed_scan(db, "a2", _days_ago(59), {"p": "1.0.0"}, commit_hash="cA")
        await _seed_scan(db, "a3", _days_ago(58), {"p": "1.0.0"}, commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(50), {"p": "1.1.0"}, commit_hash="cB")
        await _seed_scan(db, "c1", _days_ago(40), {"p": "1.2.0"}, commit_hash="cC")
        await _build_ledger(db)

        resolved = _fold_branch(BRANCH, await _deltas(db), _activity(3))

        assert resolved.status == "ready"
        assert len(resolved.window) == 5
        assert [bar[-1]["_id"] for bar in window_bars(resolved.window)] == ["a3", "b1", "c1"]

    @pytest.mark.asyncio
    async def test_the_anchor_still_sits_on_the_first_scan_of_its_run(self):
        """Coverage counts commit tokens from the anchor on, and a run contributes one."""
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {}, commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(50), {"p": "1.0.0"}, commit_hash="cB")
        await _seed_scan(db, "b2", _days_ago(49), {"p": "1.1.0"}, commit_hash="cB")
        await _seed_scan(db, "c1", _days_ago(40), {"p": "1.2.0"}, commit_hash="cC")
        await _build_ledger(db)
        deltas = await _deltas(db)

        window = select_window(deltas)

        # The SBOM-less a1 is what the fold cannot reach, and cA is what it does not account for.
        assert window[0]["_id"] == "b1"
        assert accounted_commits(deltas, window) == 2
        assert _fold_branch(BRANCH, deltas, _activity(3)).status == "partial"
        assert _fold_branch(BRANCH, deltas, _activity(2)).status == "ready"


class TestCappedRate:
    @pytest.mark.asyncio
    async def test_the_measured_span_is_the_stretch_the_bars_report(self):
        """A capped branch divides by what it read, so the span must run bar to bar."""
        db = FakeDatabase()
        await _seed_scan(db, "a1", _days_ago(60), {"p": "1.0.0"}, commit_hash="cA")
        await _seed_scan(db, "a2", _days_ago(55), {"p": "1.1.0"}, commit_hash="cA")
        await _seed_scan(db, "b1", _days_ago(20), {"p": "1.2.0"}, commit_hash="cB")
        await _seed_scan(db, "b2", _days_ago(10), {"p": "1.3.0"}, commit_hash="cB")
        await _build_ledger(db)
        deltas = await _deltas(db)

        with patch.object(endpoint, "WINDOW_HARD_LIMIT", len(deltas)):
            resolved = _fold_branch(BRANCH, deltas, _activity(2))
        folded = fold_window(resolved.window, None, resolved.measured_days)

        # a2 to b2 is 45 days; the runs' first members span only 40.
        assert resolved.measured_days == 45
        assert round(folded.time_range_days) == resolved.measured_days


class TestWindowCapCutsMidRun:
    @pytest.mark.asyncio
    async def test_both_paths_derive_the_same_bars_from_the_same_newest_documents(self):
        """A cap landing inside a run must not leave the two paths on different bars."""
        db = FakeDatabase()
        hard_limit = 8
        for index in range(12):
            await _seed_scan(
                db,
                f"s{index:02d}",
                _days_ago(60 - index),
                {"p": f"1.{index}.0"},
                commit_hash=f"c{index // 3}",
            )
        await _build_ledger(db)

        live = await compute_update_frequency(
            project_id=PROJECT,
            project_name="Project One",
            scan_repo=ScanRepository(db),
            dep_repo=DependencyRepository(db),
            analysis_repo=AnalysisResultRepository(db),
            window_days=WINDOW_DAYS,
            hard_limit=hard_limit,
        )
        window = select_window((await _deltas(db))[-hard_limit:])

        assert [bar[-1]["_id"] for bar in window_bars(window)] == _timeline_ids(live)


class TestSameCommitRunsRule:
    @pytest.mark.parametrize(
        ("commits", "expected"),
        [
            ([], []),
            (["a"], [["a"]]),
            (["a", "a", "a"], [["a", "a", "a"]]),
            (["a", "a", "b"], [["a", "a"], ["b"]]),
            (["a", "b", "b"], [["a"], ["b", "b"]]),
            (["a", "b", "a"], [["a"], ["b"], ["a"]]),
            ([None, None], [[None], [None]]),
            (["", ""], [[""], [""]]),
            (["a", None, "a"], [["a"], [None], ["a"]]),
        ],
        ids=[
            "empty",
            "single",
            "whole-window-one-run",
            "run-at-the-start",
            "run-at-the-end",
            "non-consecutive-reuse-is-two-runs",
            "a-missing-commit-stands-for-itself",
            "an-empty-commit-stands-for-itself",
            "a-missing-commit-splits-a-run",
        ],
    )
    def test_runs_are_maximal_stretches_of_one_named_commit(self, commits, expected):
        assert same_commit_runs(commits, commit_of=lambda commit: commit) == expected

    def test_a_bar_is_its_runs_last_scan_carrying_every_members_counts(self):
        entries = [
            _entry("s1", updates=1, patch=1, outdated=5),
            _entry("s2", updates=2, minor=2, outdated=4),
            _entry("s3", updates=1, major=1, outdated=3),
        ]

        bars = fold_runs_into_bars(entries, ["cA", "cA", "cB"])

        assert [bar.scan_id for bar in bars] == ["s2", "s3"]
        assert (bars[0].updates_count, bars[0].patch, bars[0].minor) == (3, 1, 2)
        assert bars[0].outdated_count == 4
        assert sum(bar.updates_count for bar in bars) == sum(entry.updates_count for entry in entries)

    def test_bars_and_commits_must_describe_the_same_scans(self):
        with pytest.raises(ValueError):
            fold_runs_into_bars([_entry("s1")], ["cA", "cB"])


def _entry(
    scan_id: str,
    *,
    updates: int = 0,
    patch: int = 0,
    minor: int = 0,
    major: int = 0,
    outdated: int | None = None,
) -> ScanTimelineEntry:
    return ScanTimelineEntry(
        scan_id=scan_id,
        date=_days_ago(10).isoformat(),
        updates_count=updates,
        outdated_count=outdated,
        patch=patch,
        minor=minor,
        major=major,
        unknown=0,
        downgrades=0,
    )


async def _deltas(db: FakeDatabase) -> list[dict[str, Any]]:
    docs = await db.scan_update_deltas.find({"project_id": PROJECT, "branch": BRANCH}).to_list(None)
    return sorted(docs, key=lambda doc: (doc["scan_created_at"], doc["_id"]))


def _activity(commit_count: int) -> BranchWindowActivity:
    return BranchWindowActivity(commit_count=commit_count, last_scan_at=NOW)


# ---------------------------------------------------------------------------
# Generated histories
# ---------------------------------------------------------------------------

_PACKAGES = ("requests", "flask", "urllib3", "click")
_GENERATED_SEEDS = tuple(range(40))


@dataclass(frozen=True)
class _GeneratedScan:
    scan_id: str
    created_at: datetime
    commit: str
    packages: dict[str, str]
    outdated: tuple[str, ...] | None
    branch: str


def _generate_history(seed: int) -> list[_GeneratedScan]:
    """A branch history mixing run lengths, missing measurements, downgrades and removals."""
    rng = random.Random(seed)
    versions = {name: [1, 0, 0] for name in _PACKAGES}
    present = set(_PACKAGES)
    scans: list[_GeneratedScan] = []
    day = 85.0

    for commit_index in range(rng.randint(3, 7)):
        for _ in range(rng.randint(1, 6)):
            day -= rng.choice((0.25, 0.5, 1.0, 3.0))
            if rng.random() < 0.35:
                name = rng.choice(_PACKAGES)
                tier = rng.randint(0, 2)
                step = -1 if rng.random() < 0.15 and versions[name][tier] > 0 else 1
                versions[name][tier] += step
                for lower in range(tier + 1, 3):
                    versions[name][lower] = 0
            if rng.random() < 0.12:
                name = rng.choice(_PACKAGES)
                present.symmetric_difference_update({name})
            packages = {name: ".".join(map(str, versions[name])) for name in sorted(present)}
            if rng.random() < 0.08:
                packages = {}
            outdated: tuple[str, ...] | None = None
            if rng.random() >= 0.15:
                outdated = tuple(name for name in sorted(packages) if rng.random() < 0.4)
            scans.append(
                _GeneratedScan(
                    scan_id=f"s{len(scans):03d}",
                    created_at=_days_ago(day),
                    commit=f"c{commit_index}",
                    packages=packages,
                    outdated=outdated,
                    branch=BRANCH,
                )
            )

    # A quieter second branch: the primary-branch pick must not drift to it.
    for index in range(2):
        scans.append(
            _GeneratedScan(
                scan_id=f"f{index}",
                created_at=_days_ago(day - 0.5 - index),
                commit=f"fc{index}",
                packages={"requests": f"9.{index}.0"},
                outdated=(),
                branch="feature",
            )
        )
    return scans


async def _seed_generated(db: FakeDatabase, scans: list[_GeneratedScan]) -> None:
    for scan in sorted(scans, key=lambda s: s.created_at):
        await _seed_scan(
            db,
            scan.scan_id,
            scan.created_at,
            scan.packages,
            scan.outdated,
            commit_hash=scan.commit,
            branch=scan.branch,
        )
    await _build_ledger(db)


class TestGeneratedHistories:
    @pytest.mark.parametrize("seed", _GENERATED_SEEDS)
    @pytest.mark.asyncio
    async def test_the_two_paths_agree_on_every_gate_field(self, seed):
        db = FakeDatabase()
        scans = _generate_history(seed)
        await _seed_generated(db, scans)

        live = await _live(db)
        rolled = await _rollup(db)

        assert rolled is not None, f"seed {seed}: the ledger declined a complete history"
        assert _differences(live, rolled) == {}, f"seed {seed}"
        _assert_bars_tile_the_pairs(live)
        _assert_bars_tile_the_pairs(rolled)
        assert live.branch == BRANCH

    def test_the_generated_histories_really_contain_runs(self):
        """Guard the fuzz against going vacuous: without runs it would prove nothing."""
        shapes = {
            len(run)
            for seed in _GENERATED_SEEDS
            for run in same_commit_runs(
                [scan for scan in _generate_history(seed) if scan.branch == BRANCH],
                commit_of=lambda scan: scan.commit,
            )
        }
        assert shapes >= {1, 2, 3, 4, 5, 6}

    def test_the_generated_histories_really_drop_measurements(self):
        scans = [scan for seed in _GENERATED_SEEDS for scan in _generate_history(seed)]
        assert any(not scan.packages for scan in scans)
        assert any(scan.outdated is None for scan in scans)


class TestGeneratedHistoriesWithALedgerHole:
    """A delta the writer never wrote truncates the fold; the walk is unaffected."""

    @pytest.mark.parametrize("seed", _GENERATED_SEEDS[:10])
    @pytest.mark.asyncio
    async def test_the_ledger_folds_a_suffix_of_the_bars_the_walk_sees(self, seed):
        db = FakeDatabase()
        scans = _generate_history(seed)
        await _seed_generated(db, scans)
        deltas = await _deltas(db)
        hole = deltas[len(deltas) // 2]["_id"]
        await db.scan_update_deltas.delete_one({"_id": hole})

        live = await _live(db)
        resolved = _fold_branch(BRANCH, await _deltas(db), _activity(len(scans)))

        if resolved.status in ("ready", "partial"):
            folded = [bar[-1]["_id"] for bar in window_bars(resolved.window)]
            walked = _timeline_ids(live)
            assert folded == walked[len(walked) - len(folded) :], f"seed {seed}"
