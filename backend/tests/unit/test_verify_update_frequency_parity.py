"""The parity check decides whether UPDATE_FREQUENCY_USE_ROLLUP may be flipped.

So the tests hold it to what that decision needs: it must compare the comparison endpoint the
flag switches — rows, their order and the counters — and not only the per-project metrics; a
row that reads ``ready`` on one path and ``partial`` on the other must fail it; and every scan
only one path folded must be named as the ledger gap it is.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.schemas.analytics import ProjectUpdateSummary
from app.services.update_frequency import rank_summaries
from scripts import verify_update_frequency_parity as parity
from scripts.verify_update_frequency_parity import (
    compare_comparisons,
    run,
    select_projects,
    verify_comparison,
    verify_project,
)
from tests.mocks.fake_mongo import FakeDatabase

PROJECT = "proj-1"
BRANCH = "main"
WINDOW_DAYS = 90
NOW = datetime.now(tz=timezone.utc)


def _days_ago(days: float) -> datetime:
    return NOW - timedelta(days=days)


async def _seed_scan(
    db: FakeDatabase,
    scan_id: str,
    created_at: datetime,
    packages: dict[str, str],
    outdated: tuple[str, ...] | None = None,
    *,
    project_id: str = PROJECT,
    branch: str = BRANCH,
) -> None:
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": project_id,
            "branch": branch,
            "created_at": created_at,
            "commit_hash": f"commit-{scan_id}",
            "status": "completed",
            "is_rescan": False,
        }
    )
    for name, version in packages.items():
        await db.dependencies.insert_one(
            {
                "_id": f"{scan_id}:{name}",
                "scan_id": scan_id,
                "project_id": project_id,
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


async def _seed_project(db: FakeDatabase, project_id: str = PROJECT, name: str = "Project One") -> dict[str, Any]:
    project = {"_id": project_id, "name": name, "default_branch": None, "deleted_branches": []}
    await db.projects.insert_one(dict(project))
    return project


async def _build_ledger(db: FakeDatabase) -> None:
    """Run the ingest writer over every seeded scan, oldest first, as the backfill does."""
    from app.services.update_frequency_rollup import record_scan_update_delta

    scans = await db.scans.find({}).to_list(None)
    for scan in sorted(scans, key=lambda s: (s["created_at"], s["_id"])):
        await record_scan_update_delta(db, scan["_id"])


async def _seed_agreeing_history(db: FakeDatabase) -> dict[str, Any]:
    await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0", "flask": "3.0.0"}, ("flask",))
    await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.0.1", "flask": "3.0.0"}, ("flask",))
    await _seed_scan(db, "s3", _days_ago(40), {"requests": "2.1.0", "flask": "4.0.0"}, ())
    await _build_ledger(db)
    return await _seed_project(db)


async def _seed_linear_history(db: FakeDatabase, count: int = 5) -> dict[str, Any]:
    """``count`` scans ten days apart, each a patch bump, all recorded in the ledger.

    Long enough that losing one scan from the ledger still leaves the window fully covered,
    so the two paths compare instead of the rollup declining the project outright.
    """
    for index in range(count):
        await _seed_scan(db, f"s{index + 1}", _days_ago(60 - index * 10), {"requests": f"2.0.{index}"}, ())
    await _build_ledger(db)
    return await _seed_project(db)


async def _compare(db: FakeDatabase, *project_ids: str) -> list[Any]:
    """The comparison-endpoint check, wired the way ``run`` wires it."""
    return await verify_comparison(db, list(project_ids), WINDOW_DAYS)


def _by_field(deviations: list[Any]) -> dict[tuple[str | None, str], Any]:
    return {d.key: d for d in deviations}


class TestAgreement:
    @pytest.mark.asyncio
    async def test_a_history_both_paths_agree_on_reports_nothing(self):
        db = FakeDatabase()
        project = await _seed_agreeing_history(db)

        report = await verify_project(db, project, WINDOW_DAYS)

        assert report.deviations == ()
        assert report.declined is None
        assert report.branch == BRANCH

    @pytest.mark.asyncio
    async def test_the_comparison_endpoint_agrees_on_every_row_field_order_and_counter(self):
        db = FakeDatabase()
        await _seed_agreeing_history(db)

        assert await _compare(db, PROJECT) == []


class TestUnexplainedDrift:
    @pytest.mark.asyncio
    async def test_a_tampered_delta_is_reported_with_both_values(self):
        db = FakeDatabase()
        project = await _seed_agreeing_history(db)
        await db.scan_update_deltas.update_one({"_id": "s3"}, {"$set": {"updates.patch": 7}})

        report = await verify_project(db, project, WINDOW_DAYS)

        drift = {d.field: (d.live, d.rollup) for d in report.unexplained}
        assert drift["total_updates"] == (3, 10)
        assert drift["patch_updates"] == (1, 8)

    @pytest.mark.asyncio
    async def test_a_tampered_delta_reaches_the_comparison_rows_and_counters(self):
        db = FakeDatabase()
        await _seed_agreeing_history(db)
        await db.scan_update_deltas.update_one({"_id": "s3"}, {"$set": {"updates.patch": 7}})

        deviations = _by_field(await _compare(db, PROJECT))

        assert deviations[PROJECT, "total_updates"].live == 3
        assert deviations[PROJECT, "total_updates"].rollup == 10
        assert deviations[None, "team_avg_updates_per_month"].reason is None


class TestLedgerGaps:
    """Every scan only one path folded is a gap to close, named with what the ledger holds."""

    @pytest.mark.asyncio
    async def test_an_unwritten_delta_is_diagnosed_and_excuses_nothing(self):
        db = FakeDatabase()
        project = await _seed_linear_history(db)
        await db.scan_update_deltas.delete_one({"_id": "s1"})

        report = await verify_project(db, project, WINDOW_DAYS)

        assert report.scan_diff.live_only == (("s1", "no delta written yet"),)
        assert {d.field for d in report.unexplained} >= {"scan_count", "first_scan_date"}
        assert report.unexplained == report.deviations

    @pytest.mark.asyncio
    async def test_a_delta_holding_a_writer_failure_excuses_nothing(self):
        db = FakeDatabase()
        project = await _seed_linear_history(db)
        await db.scan_update_deltas.update_one({"_id": "s1"}, {"$set": {"error": "RuntimeError: boom"}})

        report = await verify_project(db, project, WINDOW_DAYS)

        assert report.scan_diff.live_only == (("s1", "its delta records a writer failure"),)
        assert report.unexplained == report.deviations

    @pytest.mark.asyncio
    async def test_a_delta_the_fold_left_out_excuses_nothing(self):
        # A broken predecessor link truncates the ledger's window, so the live path folds a
        # scan whose delta exists and is sound.
        db = FakeDatabase()
        project = await _seed_linear_history(db)
        await db.scan_update_deltas.update_one({"_id": "s2"}, {"$set": {"prev_scan_id": "ghost"}})

        report = await verify_project(db, project, WINDOW_DAYS)

        assert report.scan_diff.live_only == (("s1", "its delta was left out of the folded window"),)
        assert report.unexplained == report.deviations

    @pytest.mark.asyncio
    async def test_a_scan_only_the_ledger_folds_excuses_nothing(self):
        # A scan that lost its usable status keeps its delta until the writer runs again; the
        # live path already ignores it, so hiding scans cannot reconcile the two.
        db = FakeDatabase()
        project = await _seed_linear_history(db)
        await db.scans.update_one({"_id": "s2"}, {"$set": {"status": "failed"}})

        report = await verify_project(db, project, WINDOW_DAYS)

        assert report.scan_diff.rollup_only == ("s2",)
        assert report.unexplained == report.deviations


class TestSbomLessScans:
    """Both paths drop a scan that produced no SBOM, so it is no difference at all."""

    @staticmethod
    async def _seed(db: FakeDatabase, total: int, sbom_less: str) -> dict[str, Any]:
        for index in range(total):
            scan_id = f"s{index + 1}"
            packages = {} if scan_id == sbom_less else {"requests": f"2.{index}.0"}
            await _seed_scan(db, scan_id, _days_ago(60 - index * 10), packages, ())
        await _build_ledger(db)
        return await _seed_project(db)

    @pytest.mark.asyncio
    async def test_neither_path_folds_it_so_nothing_is_reported(self):
        db = FakeDatabase()
        project = await self._seed(db, total=3, sbom_less="s2")

        report = await verify_project(db, project, WINDOW_DAYS)

        assert report.scan_diff.live_only == ()
        assert report.scan_diff.rollup_only == ()
        assert report.deviations == ()

    @pytest.mark.asyncio
    async def test_the_comparison_rows_and_counters_agree_across_it(self):
        db = FakeDatabase()
        await self._seed(db, total=5, sbom_less="s3")

        assert await _compare(db, PROJECT) == []

    @pytest.mark.asyncio
    async def test_drift_beside_it_is_still_reported(self):
        db = FakeDatabase()
        project = await self._seed(db, total=5, sbom_less="s3")
        await db.scan_update_deltas.update_one({"_id": "s4"}, {"$set": {"updates.major": 5}})

        report = await verify_project(db, project, WINDOW_DAYS)

        assert {d.field for d in report.unexplained} >= {"major_updates", "total_updates"}
        assert _by_field(await _compare(db, PROJECT))[PROJECT, "total_updates"].reason is None


class TestStatusDifference:
    """A row that changes status enters or leaves the ranking, so it is always a mismatch."""

    @staticmethod
    def _payload(status: str, scan_count: int) -> dict[str, Any]:
        return rank_summaries(
            [
                ProjectUpdateSummary(
                    project_id=PROJECT,
                    project_name="Project One",
                    data_status=status,
                    branch=BRANCH,
                    window_days=WINDOW_DAYS,
                    scan_count=scan_count,
                    updates_per_month=1.0,
                    update_coverage_pct=50.0,
                    patch_ratio=1.0,
                    trend_direction="stable",
                    total_updates=3,
                    total_outdated=2,
                    last_scan_date="2026-08-01T00:00:00+00:00",
                )
            ]
        ).model_dump()

    def test_the_status_difference_carries_both_verdicts(self):
        deviations = _by_field(compare_comparisons(self._payload("ready", 4), self._payload("partial", 3)))

        status = deviations[PROJECT, "data_status"]
        assert (status.live, status.rollup) == ("ready", "partial")
        assert deviations[None, "partial_projects"].rollup == 1


class TestKnownDeviations:
    @pytest.mark.asyncio
    async def test_a_scan_above_the_sample_cap_only_excuses_recent_updates(self):
        db = FakeDatabase()
        before = {f"pkg{i:02d}": "1.0.0" for i in range(25)}
        after = {f"pkg{i:02d}": "1.0.1" for i in range(25)}
        await _seed_scan(db, "s1", _days_ago(60), before, ())
        await _seed_scan(db, "s2", _days_ago(50), after, ())
        await _build_ledger(db)
        project = await _seed_project(db)

        report = await verify_project(db, project, WINDOW_DAYS)

        assert [d.field for d in report.deviations] == ["recent_updates"]
        assert report.unexplained == ()
        assert "at most 20 samples per scan" in report.deviations[0].reason
        assert len(report.deviations[0].live) == 25
        assert len(report.deviations[0].rollup) == 20

    @pytest.mark.asyncio
    async def test_a_mixed_ecosystem_project_only_excuses_the_dominant_ecosystem(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        await _build_ledger(db)
        # Only the newest scan's composition reaches the ledger, so a type the older scan
        # alone carried moves the live verdict but not the rolled-up one.
        await db.dependencies.insert_one(
            {
                "_id": "s1:left",
                "scan_id": "s1",
                "project_id": PROJECT,
                "name": "left-pad",
                "version": "1.0.0",
                "type": "library",
                "purl": "pkg:npm/left-pad@1.0.0",
            }
        )
        project = await _seed_project(db)

        report = await verify_project(db, project, WINDOW_DAYS)

        assert [d.field for d in report.deviations] == ["dominant_ecosystem"]
        assert report.unexplained == ()
        assert (report.deviations[0].live, report.deviations[0].rollup) == ("mixed", "pypi")


class TestDeclined:
    @pytest.mark.asyncio
    async def test_a_project_without_deltas_is_reported_as_declined(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        project = await _seed_project(db)

        report = await verify_project(db, project, WINDOW_DAYS)

        assert report.declined == "0 delta(s) in the window, 0 foldable, 0 holding a writer failure"
        assert report.deviations == ()

    @pytest.mark.asyncio
    async def test_a_decline_names_what_the_ledger_does_hold(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        await _build_ledger(db)
        await db.scan_update_deltas.update_one({"_id": "s2"}, {"$set": {"error": "RuntimeError: boom"}})
        project = await _seed_project(db)

        report = await verify_project(db, project, WINDOW_DAYS)

        assert report.declined == "2 delta(s) in the window, 1 foldable, 1 holding a writer failure"

    @pytest.mark.asyncio
    async def test_an_unbackfilled_project_reorders_the_comparison_and_flips_its_status(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ("requests",))
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ("requests",))
        await _build_ledger(db)
        await _seed_project(db)
        # Never fed to the writer, so the ledger has nothing for it while the live path ranks it.
        await _seed_scan(db, "t1", _days_ago(60), {"flask": "3.0.0"}, ("flask",), project_id="proj-2")
        await _seed_scan(db, "t2", _days_ago(50), {"flask": "4.0.0"}, (), project_id="proj-2")
        await _seed_project(db, "proj-2", "Project Two")

        deviations = _by_field(await _compare(db, PROJECT, "proj-2"))

        status = deviations["proj-2", "data_status"]
        assert (status.live, status.rollup) == ("ready", "pending")
        assert deviations[None, "row order"].live == ["proj-2", PROJECT]
        assert deviations[None, "row order"].rollup == [PROJECT, "proj-2"]
        assert deviations[None, "pending_projects"].rollup == 1


class TestSampling:
    @pytest.mark.asyncio
    async def test_only_projects_with_something_to_compare_are_sampled(self):
        db = FakeDatabase()
        await _seed_scan(db, "s1", _days_ago(60), {"requests": "2.0.0"}, ())
        await _seed_scan(db, "s2", _days_ago(50), {"requests": "2.1.0"}, ())
        await _seed_scan(db, "lonely", _days_ago(40), {"requests": "2.0.0"}, (), project_id="proj-2")
        await _seed_scan(db, "stale", _days_ago(200), {"requests": "2.0.0"}, (), project_id="proj-3")
        await _seed_scan(db, "stale2", _days_ago(190), {"requests": "2.1.0"}, (), project_id="proj-3")
        for project_id in (PROJECT, "proj-2", "proj-3"):
            await _seed_project(db, project_id, project_id)

        selected = await select_projects(db, sample=10, project_id=None, since=_days_ago(WINDOW_DAYS))

        assert [p["_id"] for p in selected] == [PROJECT]

    @pytest.mark.asyncio
    async def test_the_sample_takes_the_busiest_projects_first(self):
        db = FakeDatabase()
        for index, (project_id, scans) in enumerate((("quiet", 2), ("busy", 4), ("middling", 3))):
            for scan in range(scans):
                await _seed_scan(
                    db,
                    f"{project_id}-{scan}",
                    _days_ago(60 - scan - index * 10),
                    {"requests": f"2.0.{scan}"},
                    (),
                    project_id=project_id,
                )
            await _seed_project(db, project_id, project_id)

        selected = await select_projects(db, sample=2, project_id=None, since=_days_ago(WINDOW_DAYS))

        assert [p["_id"] for p in selected] == ["busy", "middling"]

    @pytest.mark.asyncio
    async def test_project_id_bypasses_the_ranking(self):
        db = FakeDatabase()
        await _seed_project(db, "proj-9", "Nine")

        selected = await select_projects(db, sample=10, project_id="proj-9", since=_days_ago(WINDOW_DAYS))

        assert [p["_id"] for p in selected] == ["proj-9"]

    @pytest.mark.asyncio
    async def test_an_unknown_project_id_selects_nothing(self):
        db = FakeDatabase()

        assert await select_projects(db, sample=10, project_id="nope", since=_days_ago(WINDOW_DAYS)) == []


class _FakeClient:
    def __init__(self, db: FakeDatabase):
        self._db = db

    def __getitem__(self, _name: str) -> FakeDatabase:
        return self._db

    def close(self) -> None:
        return None


def _args(**overrides: Any):
    import argparse

    return argparse.Namespace(**({"sample": 20, "project_id": None, "window_days": WINDOW_DAYS} | overrides))


class TestExitCodes:
    @pytest.mark.asyncio
    async def test_agreement_exits_zero(self, monkeypatch, capsys):
        db = FakeDatabase()
        await _seed_agreeing_history(db)
        monkeypatch.setattr(parity, "AsyncIOMotorClient", lambda _url: _FakeClient(db))

        assert await run(_args()) == 0
        out = capsys.readouterr().out
        assert "every row field, the row order and every counter agree" in out
        assert "identical on every field" in out

    @pytest.mark.asyncio
    async def test_an_unexplained_deviation_exits_two(self, monkeypatch, capsys):
        db = FakeDatabase()
        await _seed_agreeing_history(db)
        await db.scan_update_deltas.update_one({"_id": "s3"}, {"$set": {"updates.patch": 7}})
        monkeypatch.setattr(parity, "AsyncIOMotorClient", lambda _url: _FakeClient(db))

        assert await run(_args()) == 2
        out = capsys.readouterr().out
        assert "MISMATCH total_updates" in out
        assert "unexplained deviations:    1" in out

    @pytest.mark.asyncio
    async def test_a_status_flip_on_the_comparison_alone_exits_two(self, monkeypatch, capsys):
        # The per-project check has nothing to say about a project the ledger declines, so
        # only the comparison sees this one; before the comparison check it exited 0.
        db = FakeDatabase()
        await _seed_agreeing_history(db)
        await _seed_scan(db, "t1", _days_ago(60), {"flask": "3.0.0"}, (), project_id="proj-2")
        await _seed_scan(db, "t2", _days_ago(50), {"flask": "4.0.0"}, (), project_id="proj-2")
        await _seed_project(db, "proj-2", "Project Two")
        monkeypatch.setattr(parity, "AsyncIOMotorClient", lambda _url: _FakeClient(db))

        assert await run(_args()) == 2
        out = capsys.readouterr().out
        assert "MISMATCH data_status" in out
        assert "unexplained deviations:    0" in out

    @pytest.mark.asyncio
    async def test_a_deviation_with_a_named_cause_exits_zero_but_is_printed(self, monkeypatch, capsys):
        db = FakeDatabase()
        before = {f"pkg{i:02d}": "1.0.0" for i in range(25)}
        after = {f"pkg{i:02d}": "1.0.1" for i in range(25)}
        await _seed_scan(db, "s1", _days_ago(60), before, ())
        await _seed_scan(db, "s2", _days_ago(50), after, ())
        await _build_ledger(db)
        await _seed_project(db)
        monkeypatch.setattr(parity, "AsyncIOMotorClient", lambda _url: _FakeClient(db))

        assert await run(_args()) == 0
        out = capsys.readouterr().out
        assert "known    recent_updates" in out
        assert "only known deviations:     1" in out

    @pytest.mark.asyncio
    async def test_an_empty_sample_exits_three(self, monkeypatch, capsys):
        db = FakeDatabase()
        monkeypatch.setattr(parity, "AsyncIOMotorClient", lambda _url: _FakeClient(db))

        assert await run(_args()) == 3
        assert "nothing compared" in capsys.readouterr().err

    @pytest.mark.asyncio
    async def test_a_failing_query_exits_one(self, monkeypatch, capsys):
        db = FakeDatabase()
        monkeypatch.setattr(parity, "AsyncIOMotorClient", lambda _url: _FakeClient(db))

        async def _explode(*_args: Any, **_kwargs: Any):
            raise RuntimeError("no route to mongod")

        monkeypatch.setattr(parity, "select_projects", _explode)

        assert await run(_args()) == 1
        assert "no route to mongod" in capsys.readouterr().err
