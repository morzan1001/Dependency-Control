"""Tests for the one head resolver on ScanRepository and its delegators.

Head is the newest usable build on the project's default branch, falling back to any branch the
VCS still has; a rescan ranks behind the build it re-analysed, and ``latest_scan_id`` is that
answer cached and trusted only while it names a readable scan on the head branch.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import SCAN_STATUS_FAILED
from app.models.stats import Stats
from app.repositories.scans import ScanRepository
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
_HEAD = "head"


def _project(project_id: str, **overrides) -> dict:
    """The projection shape analytics passes in: id, pointer, and the two branch fields."""
    doc = {"_id": project_id, "deleted_branches": [], "latest_scan_id": None, "default_branch": None}
    doc.update(overrides)
    return doc


def _scan(scan_id: str, project_id: str, branch: str, hours_old: int, **overrides) -> dict:
    doc = {
        "_id": scan_id,
        "project_id": project_id,
        "branch": branch,
        "status": "completed",
        "created_at": _NOW - timedelta(hours=hours_old),
    }
    doc.update(overrides)
    return doc


async def _seeded(scans: list[dict]) -> FakeDatabase:
    db = FakeDatabase()
    for scan in scans:
        await db.scans.insert_one(scan)
    return db


class _CountingScans:
    """Counts the reads head resolution makes, so its cost stays a stated property."""

    def __init__(self, collection):
        self._collection = collection
        self.finds = 0
        self.aggregates = 0

    def find(self, *args, **kwargs):
        self.finds += 1
        return self._collection.find(*args, **kwargs)

    def aggregate(self, *args, **kwargs):
        self.aggregates += 1
        return self._collection.aggregate(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._collection, name)


async def _resolve(scans: list[dict], projects: list[dict]) -> tuple[dict[str, str], _CountingScans]:
    db = await _seeded(scans)
    counting = _CountingScans(db.scans)
    repo = ScanRepository(db)
    repo.collection = counting
    return await repo.get_latest_active_scan_ids(projects), counting


class SimpleProject:
    """A model-shaped project: head resolution reads its fields with getattr."""

    def __init__(self, project_id: str, deleted_branches: list[str]):
        self.id = project_id
        self.deleted_branches = deleted_branches
        self.default_branch = None
        self.latest_scan_id = None


class TestGetLatestActiveScan:
    """The single-project entry point answers with the same head as the bulk one."""

    def test_head_is_the_default_branch_tip_not_the_newest_scan_anywhere(self):
        async def run():
            db = await _seeded([_scan("main-tip", "p1", "main", 6), _scan("feature-tip", "p1", "feature/spike", 0)])
            return await ScanRepository(db).get_latest_active_scan(_project("p1", default_branch="main"))

        scan = asyncio.run(run())

        assert scan is not None and scan.id == "main-tip"

    def test_a_rescan_does_not_take_head_from_the_build_it_re_analysed(self):
        """The recommendations tab resolved head here and reported a 200-day-old release's findings
        because the rescanner had just re-analysed it."""

        async def run():
            db = await _seeded(
                [
                    _scan("build", "p1", "main", 4800),
                    _scan("rescan", "p1", "main", 0, is_rescan=True, original_scan_id="build"),
                    _scan("tip", "p1", "main", 48),
                ]
            )
            return await ScanRepository(db).get_latest_active_scan(_project("p1", default_branch="main"))

        scan = asyncio.run(run())

        assert scan is not None and scan.id == "tip"

    def test_the_two_entry_points_agree(self):
        async def run():
            scans = [
                _scan("main-tip", "p1", "main", 6),
                _scan("rescan", "p1", "main", 0, is_rescan=True, original_scan_id="main-tip"),
                _scan("feature-tip", "p1", "feature/spike", 1),
            ]
            project = _project("p1", default_branch="main", latest_scan_id="feature-tip")
            db = await _seeded(scans)
            repo = ScanRepository(db)
            single = await repo.get_latest_active_scan(project)
            bulk = await repo.get_latest_active_scan_ids([project])
            return single, bulk

        single, bulk = asyncio.run(run())

        assert single is not None and bulk == {"p1": single.id}

    def test_deleted_branches_argument_overrides_the_projects_own_set(self):
        """Housekeeping passes the freshly-computed set before it is persisted."""

        async def run():
            db = await _seeded([_scan("on-fresh", "p1", "fresh-a", 0), _scan("on-stale", "p1", "stale", 1)])
            return await ScanRepository(db).get_latest_active_scan(
                _project("p1", deleted_branches=["stale"]),
                deleted_branches=["fresh-a"],
            )

        scan = asyncio.run(run())

        assert scan is not None and scan.id == "on-stale"

    def test_accepts_a_project_model_like_object(self):
        async def run():
            db = await _seeded([_scan("on-live", "proj-42", "main", 0), _scan("on-gone", "proj-42", "gone", 1)])
            project = SimpleProject(project_id="proj-42", deleted_branches=["gone"])
            return await ScanRepository(db).get_latest_active_scan(project)

        scan = asyncio.run(run())

        assert scan is not None and scan.id == "on-live"

    def test_returns_none_when_no_scan_is_usable(self):
        async def run():
            db = await _seeded([_scan("failed", "p1", "main", 0, status="failed")])
            return await ScanRepository(db).get_latest_active_scan(_project("p1"))

        assert asyncio.run(run()) is None

    def test_returns_none_for_a_project_without_an_id(self):
        async def run():
            db = await _seeded([_scan("orphan", "", "main", 0)])
            return await ScanRepository(db).get_latest_active_scan(_project(""))

        assert asyncio.run(run()) is None


class TestGetLatestActiveScanIds:
    def test_uses_latest_scan_id_when_it_still_names_a_head_scan(self):
        result, reads = asyncio.run(
            _resolve(
                [_scan("scan-latest", "p1", "main", 1)],
                [_project("p1", latest_scan_id="scan-latest")],
            )
        )

        assert result == {"p1": "scan-latest"}
        # A usable pointer answers the whole scope with one read and no aggregation.
        assert (reads.finds, reads.aggregates) == (1, 0)

    def test_keeps_the_pointer_when_the_deleted_branch_is_not_its_own(self):
        """deleted_branches is the steady state of any VCS-integrated project, and an unrelated
        entry must not throw away the tip and hand head mode a rescan of an old release."""
        result, reads = asyncio.run(
            _resolve(
                [
                    _scan("tip", "p2", "main", 2),
                    _scan("rescan-of-release", "p2", "main", 0, is_rescan=True, original_scan_id="old-release"),
                ],
                [_project("p2", latest_scan_id="tip", deleted_branches=["feature-old"], default_branch="main")],
            )
        )

        assert result == {"p2": "tip"}
        # The pointer is still the cached answer here, so nothing has to be re-derived.
        assert reads.aggregates == 0

    def test_aggregates_when_the_pointer_is_on_a_deleted_branch(self):
        result, reads = asyncio.run(
            _resolve(
                [_scan("scan-on-dead-branch", "p2", "dead", 1), _scan("scan-active", "p2", "main", 5)],
                [_project("p2", latest_scan_id="scan-on-dead-branch", deleted_branches=["dead"])],
            )
        )

        assert result == {"p2": "scan-active"}
        assert reads.aggregates == 1

    def test_resolves_projects_without_latest_scan_id_by_query(self):
        result, _ = asyncio.run(
            _resolve([_scan("found-by-query", "p3", "develop", 1)], [_project("p3")]),
        )

        assert result == {"p3": "found-by-query"}

    def test_omits_a_project_with_neither_pointer_nor_usable_scan(self):
        result, _ = asyncio.run(
            _resolve([_scan("failed", "p4", "main", 1, status="failed")], [_project("p4")]),
        )

        assert result == {}

    def test_collapses_multiple_pointer_less_projects_into_one_query(self):
        result, reads = asyncio.run(
            _resolve(
                [_scan("scan-a", "p5", "main", 1), _scan("scan-b", "p6", "main", 1)],
                [_project("p5"), _project("p6")],
            )
        )

        assert result == {"p5": "scan-a", "p6": "scan-b"}
        assert reads.aggregates == 1

    def test_resolves_pointer_less_project_with_deleted_branches_separately(self):
        result, _ = asyncio.run(
            _resolve(
                [_scan("on-dead", "p7", "dead", 0), _scan("active-scan", "p7", "main", 3)],
                [_project("p7", deleted_branches=["dead"])],
            )
        )

        assert result == {"p7": "active-scan"}

    def test_falls_back_when_the_pointer_names_an_unreadable_scan(self):
        """Retention removes the scan document and leaves latest_scan_id behind, so a project whose
        head was deleted must resolve to the older scan retention exempted, not to the dead id."""
        result, _ = asyncio.run(
            _resolve(
                [_scan("exempted-release", "p8", "main", 200)],
                [_project("p8", latest_scan_id="retention-deleted")],
            )
        )

        assert result == {"p8": "exempted-release"}

    def test_falls_back_when_the_pointer_names_a_scan_back_in_pending(self):
        result, _ = asyncio.run(
            _resolve(
                [_scan("reingesting", "p8", "main", 0, status="pending"), _scan("previous", "p8", "main", 6)],
                [_project("p8", latest_scan_id="reingesting")],
            )
        )

        assert result == {"p8": "previous"}

    def test_validates_every_pointer_in_one_read(self):
        result, reads = asyncio.run(
            _resolve(
                [_scan("live-a", "pa", "main", 1), _scan("live-b", "pb", "main", 1)],
                [_project("pa", latest_scan_id="live-a"), _project("pb", latest_scan_id="live-b")],
            )
        )

        assert result == {"pa": "live-a", "pb": "live-b"}
        assert (reads.finds, reads.aggregates) == (1, 0)

    def test_reads_nothing_when_no_project_carries_a_pointer(self):
        result, reads = asyncio.run(
            _resolve([_scan("found-by-query", "p9", "main", 1)], [_project("p9")]),
        )

        assert result == {"p9": "found-by-query"}
        assert reads.finds == 0

    def test_skips_projects_with_falsy_id(self):
        result, reads = asyncio.run(_resolve([], [_project("")]))

        assert result == {}
        assert reads.aggregates == 0

    def test_mixed_projects(self):
        result, _ = asyncio.run(
            _resolve(
                [
                    _scan("clean-scan", "p_clean", "main", 1),
                    _scan("on-deleted", "p_deleted", "x", 0),
                    _scan("active-scan", "p_deleted", "main", 4),
                ],
                [
                    _project("p_clean", latest_scan_id="clean-scan"),
                    _project("p_deleted", latest_scan_id="on-deleted", deleted_branches=["x"]),
                ],
            )
        )

        assert result == {"p_clean": "clean-scan", "p_deleted": "active-scan"}


class TestHeadIsTheDefaultBranch:
    def test_a_newer_feature_branch_scan_is_not_the_head(self):
        result, _ = asyncio.run(
            _resolve(
                [_scan("main-tip", "p1", "main", 6), _scan("feature-tip", "p1", "feature/spike", 0)],
                [_project("p1", default_branch="main")],
            )
        )

        assert result == {"p1": "main-tip"}

    def test_a_pointer_left_on_another_branch_is_re_derived(self):
        result, _ = asyncio.run(
            _resolve(
                [_scan("main-tip", "p1", "main", 6), _scan("feature-tip", "p1", "feature/spike", 0)],
                [_project("p1", default_branch="main", latest_scan_id="feature-tip")],
            )
        )

        assert result == {"p1": "main-tip"}

    def test_a_default_branch_this_instance_never_scanned_still_resolves(self):
        result, _ = asyncio.run(
            _resolve([_scan("develop-tip", "p1", "develop", 1)], [_project("p1", default_branch="main")]),
        )

        assert result == {"p1": "develop-tip"}

    def test_a_rescan_does_not_take_the_tip_from_the_build_it_re_analysed(self):
        result, _ = asyncio.run(
            _resolve(
                [
                    _scan("build", "p1", "main", 5),
                    _scan("rescan", "p1", "main", 0, is_rescan=True, original_scan_id="build"),
                ],
                [_project("p1", default_branch="main")],
            )
        )

        assert result == {"p1": "build"}

    def test_a_branch_left_with_only_a_rescan_still_resolves_to_it(self):
        result, _ = asyncio.run(
            _resolve(
                [_scan("rescan", "p1", "main", 0, is_rescan=True, original_scan_id="gone")],
                [_project("p1", default_branch="main")],
            )
        )

        assert result == {"p1": "rescan"}

    def test_a_default_branch_the_vcs_deleted_falls_back_to_a_live_branch(self):
        result, _ = asyncio.run(
            _resolve(
                [_scan("old-main", "p1", "main", 1), _scan("develop-tip", "p1", "develop", 4)],
                [_project("p1", default_branch="main", deleted_branches=["main"])],
            )
        )

        assert result == {"p1": "develop-tip"}


class TestGetPrecedingScan:
    """The build a scan succeeded, which is what "what changed since the last build" compares against."""

    @staticmethod
    async def _preceding_id(scans: list[dict], scan_id: str = _HEAD) -> str | None:
        db = await _seeded(scans)
        preceding = await ScanRepository(db).get_preceding_scan(scan_id)
        return preceding.id if preceding else None

    def test_the_newest_earlier_build_on_the_same_branch(self):
        result = asyncio.run(
            self._preceding_id(
                [
                    _scan(_HEAD, "p1", "main", 0),
                    _scan("previous", "p1", "main", 5),
                    _scan("ancient", "p1", "main", 50),
                ]
            )
        )

        assert result == "previous"

    def test_a_build_on_another_branch_is_not_what_this_one_succeeded(self):
        result = asyncio.run(
            self._preceding_id([_scan(_HEAD, "p1", "main", 0), _scan("feature-build", "p1", "feature/spike", 1)])
        )

        assert result is None

    def test_an_unusable_scan_is_not_a_build(self):
        """A failed run holds no findings, so a delta against it invents a fix for everything."""
        result = asyncio.run(
            self._preceding_id(
                [
                    _scan(_HEAD, "p1", "main", 0),
                    _scan("failed", "p1", "main", 1, status=SCAN_STATUS_FAILED),
                    _scan("previous", "p1", "main", 5),
                ]
            )
        )

        assert result == "previous"

    def test_a_rescan_is_not_the_build_the_next_one_followed(self):
        result = asyncio.run(
            self._preceding_id(
                [
                    _scan(_HEAD, "p1", "main", 0),
                    _scan("rescan", "p1", "main", 1, is_rescan=True, original_scan_id="previous"),
                    _scan("previous", "p1", "main", 5),
                ]
            )
        )

        assert result == "previous"

    def test_a_build_that_never_carried_the_rescan_flag_is_eligible(self):
        """``is_rescan`` is tri-state: absent and False both mean a real build."""
        result = asyncio.run(
            self._preceding_id(
                [
                    _scan(_HEAD, "p1", "main", 0),
                    _scan("flag-absent", "p1", "main", 5),
                    _scan("flag-false", "p1", "main", 9, is_rescan=False),
                ]
            )
        )

        assert result == "flag-absent"

    def test_the_first_build_on_a_branch_has_no_predecessor(self):
        result = asyncio.run(self._preceding_id([_scan(_HEAD, "p1", "main", 0)]))

        assert result is None

    def test_a_scan_that_does_not_exist_has_no_predecessor(self):
        result = asyncio.run(self._preceding_id([_scan("previous", "p1", "main", 5)]))

        assert result is None


def _vulnerability(finding_id: str, scan_id: str, severity: str) -> dict:
    return {
        "_id": f"{scan_id}:{finding_id}",
        "id": finding_id,
        "finding_id": finding_id,
        "scan_id": scan_id,
        "project_id": "p1",
        "type": "vulnerability",
        "severity": severity,
        "component": "pkg",
        "version": "1.0.0",
        "description": "",
        "scanners": ["trivy"],
        "details": {},
        "waived": False,
    }


class TestStatsRecalculationReadsHead:
    @pytest.mark.asyncio
    async def test_a_pointer_on_a_feature_branch_does_not_decide_the_projects_stats(self):
        from app.services.stats import recalculate_project_stats

        db = FakeDatabase()
        await db.projects.insert_one(_project("p1", name="proj", default_branch="main", latest_scan_id="feature-scan"))
        await db.scans.insert_one(_scan("main-tip", "p1", "main", 5))
        await db.scans.insert_one(_scan("feature-scan", "p1", "feature/x", 0))
        await db.findings.insert_one(_vulnerability("f-main", "main-tip", "CRITICAL"))
        await db.findings.insert_one(_vulnerability("f-feature", "feature-scan", "LOW"))

        stats = await recalculate_project_stats("p1", db)

        assert stats is not None
        assert (stats.critical, stats.low) == (1, 0)


class TestHousekeepingDelegation:
    """housekeeping._resolve_latest_scan_after_branch_deletion keeps its update-dict shape while
    the replacement it writes into the pointer is head."""

    @pytest.mark.asyncio
    async def test_updates_to_the_branch_tip_rather_than_the_newest_rescan(self):
        from app.core import housekeeping

        db = FakeDatabase()
        await db.scans.insert_one(_scan("scan-old", "p1", "feature", 10))
        await db.scans.insert_one(_scan("main-tip", "p1", "main", 5, stats=Stats().model_dump()))
        await db.scans.insert_one(_scan("rescan", "p1", "main", 0, is_rescan=True, original_scan_id="main-tip"))
        project_data = {"_id": "p1", "latest_scan_id": "scan-old", "default_branch": "main"}

        updates = await housekeeping._resolve_latest_scan_after_branch_deletion(project_data, ["feature"], db, "proj")

        assert updates["latest_scan_id"] == "main-tip"
        assert updates["last_scan_at"] is not None
        # stats round-trips back to the stored (model_dump) shape.
        assert updates["stats"] == Stats().model_dump()

    @pytest.mark.asyncio
    async def test_clears_when_no_active_scan(self):
        from app.core import housekeeping

        db = FakeDatabase()
        await db.scans.insert_one(_scan("scan-old", "p1", "feature", 10))
        project_data = {"_id": "p1", "latest_scan_id": "scan-old", "default_branch": "main"}

        updates = await housekeeping._resolve_latest_scan_after_branch_deletion(project_data, ["feature"], db, "proj")

        assert updates == {"latest_scan_id": None, "stats": None}

    @pytest.mark.asyncio
    async def test_noop_when_current_scan_not_on_deleted_branch(self):
        from app.core import housekeeping

        db = FakeDatabase()
        await db.scans.insert_one(_scan("scan-old", "p1", "main", 10))
        project_data = {"_id": "p1", "latest_scan_id": "scan-old", "default_branch": "main"}

        updates = await housekeeping._resolve_latest_scan_after_branch_deletion(project_data, ["feature"], db, "proj")

        assert updates == {}
