"""Tests for the one head resolver on ScanRepository and its delegators.

The rule these assert is stated once, in ``app/repositories/scans.py``: head is the freshest
readable analysis of the tip commit of the project's head branch. Two steps — the newest build
picks the commit, its rescan lineage picks the analysis — so a rescan reaches head with its
enrichment without moving head onto the commit it re-analysed. ``latest_scan_id`` is that answer
cached, trusted only while it names a readable scan that may head the project, and it goes through
the lineage step like any other candidate.
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
# One read validates every pointer in the scope. A tip is already in hand when its lineage is
# walked, so only a tip carrying a rescan link costs one more read, again per scope.
_POINTER_READS = 1
_NO_READS = 0
_SBOM_REFS = [{"type": "gridfs_reference", "gridfs_id": "g1"}]


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
        "sbom_refs": _SBOM_REFS,
    }
    doc.update(overrides)
    return doc


async def _seeded(scans: list[dict]) -> FakeDatabase:
    db = FakeDatabase()
    for scan in scans:
        await db.scans.insert_one(scan)
    # Both rescan creators stamp the forward link on the source as they insert the rescan, so a
    # fixture carrying only original_scan_id is a lineage no writer in this codebase produces.
    for scan in scans:
        if scan.get("original_scan_id"):
            await db.scans.update_one({"_id": scan["original_scan_id"]}, {"$set": {"latest_rescan_id": scan["_id"]}})
    return db


class _CountingScans:
    """Counts the reads head resolution makes, so its cost stays a stated property."""

    def __init__(self, collection):
        self._collection = collection
        self.finds = 0
        self.seeks = 0
        self.aggregates = 0

    def find(self, *args, **kwargs):
        self.finds += 1
        return self._collection.find(*args, **kwargs)

    async def find_one(self, *args, **kwargs):
        self.seeks += 1
        return await self._collection.find_one(*args, **kwargs)

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

        assert single is not None and single.id == "rescan"
        assert bulk == {"p1": single.id}

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
        # A usable pointer answers the whole scope without re-deriving the tip.
        assert (reads.finds, reads.seeks, reads.aggregates) == (_POINTER_READS, _NO_READS, _NO_READS)

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
        assert reads.seeks == _NO_READS

    def test_re_derives_with_one_index_seek_when_the_pointer_is_on_a_deleted_branch(self):
        result, reads = asyncio.run(
            _resolve(
                [_scan("scan-on-dead-branch", "p2", "dead", 1), _scan("scan-active", "p2", "main", 5)],
                [_project("p2", latest_scan_id="scan-on-dead-branch", deleted_branches=["dead"])],
            )
        )

        assert result == {"p2": "scan-active"}
        assert (reads.seeks, reads.aggregates) == (1, _NO_READS)

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

    def test_a_pointer_less_project_costs_one_index_seek_rather_than_a_sort_of_its_history(self):
        """The rank-first aggregation fetched and sorted every usable scan the project ever held."""
        history = [_scan(f"old-{index}", "p5", "main", index + 2) for index in range(20)]
        result, reads = asyncio.run(
            _resolve(
                [_scan("scan-a", "p5", "main", 1), *history, _scan("scan-b", "p6", "main", 1)],
                [_project("p5"), _project("p6")],
            )
        )

        assert result == {"p5": "scan-a", "p6": "scan-b"}
        assert (reads.seeks, reads.aggregates) == (2, _NO_READS)

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
        assert (reads.finds, reads.aggregates) == (_POINTER_READS, _NO_READS)

    def test_skips_the_pointer_read_when_no_project_carries_a_pointer(self):
        result, reads = asyncio.run(
            _resolve([_scan("found-by-query", "p9", "main", 1)], [_project("p9")]),
        )

        assert result == {"p9": "found-by-query"}
        assert reads.finds == _NO_READS

    def test_skips_projects_with_falsy_id(self):
        result, reads = asyncio.run(_resolve([], [_project("")]))

        assert result == {}
        assert (reads.finds, reads.seeks, reads.aggregates) == (_NO_READS, _NO_READS, _NO_READS)

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

    def test_a_pointer_is_read_once_on_its_way_through_the_lineage(self):
        """The pointer read already carries the chain fields, so the walk starts at the rescan link."""
        result, reads = asyncio.run(
            _resolve(
                [
                    _scan("build", "p1", "main", 5),
                    _scan("rescan", "p1", "main", 0, is_rescan=True, original_scan_id="build"),
                ],
                [_project("p1", default_branch="main", latest_scan_id="build")],
            )
        )

        assert result == {"p1": "rescan"}
        assert reads.finds == _POINTER_READS + 1


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

    def test_head_is_the_rescan_of_the_tip_build_rather_than_the_analysis_it_replaced(self):
        """Second step of the rule: the build picked the commit, so the rescan of that same commit
        is what head reports — otherwise the rescanner's fresh enrichment never reaches a reader."""
        result, _ = asyncio.run(
            _resolve(
                [
                    _scan("build", "p1", "main", 5),
                    _scan("rescan", "p1", "main", 0, is_rescan=True, original_scan_id="build"),
                ],
                [_project("p1", default_branch="main")],
            )
        )

        assert result == {"p1": "rescan"}

    def test_every_pointer_over_one_rescanned_build_resolves_to_the_same_scan(self):
        """The two doors into the identical two-scan branch — pointer set, pointer stale, no
        pointer — cannot answer differently, or which rule fired is decided by the pointer."""
        scans = [
            _scan("build", "p1", "main", 5),
            _scan("rescan", "p1", "main", 0, is_rescan=True, original_scan_id="build"),
        ]
        answers = [
            asyncio.run(_resolve(scans, [_project("p1", default_branch="main", latest_scan_id=pointer)]))[0]
            for pointer in ("rescan", "build", None)
        ]

        assert answers == [{"p1": "rescan"}] * len(answers)

    def test_a_branch_left_with_only_a_rescan_still_resolves_to_it(self):
        result, _ = asyncio.run(
            _resolve(
                [_scan("rescan", "p1", "main", 0, is_rescan=True, original_scan_id="gone")],
                [_project("p1", default_branch="main")],
            )
        )

        assert result == {"p1": "rescan"}

    def test_two_builds_stamped_in_the_same_millisecond_resolve_to_one_head(self):
        """BSON dates are milliseconds, so the date alone cannot separate these two; the seeding
        order is the one the server would hand back untied, and head must not be it."""
        result, _ = asyncio.run(
            _resolve(
                [_scan("z-build", "p1", "main", 0), _scan("a-build", "p1", "main", 0)],
                [_project("p1", default_branch="main")],
            )
        )

        assert result == {"p1": "a-build"}

    def test_a_default_branch_the_vcs_deleted_falls_back_to_a_live_branch(self):
        result, _ = asyncio.run(
            _resolve(
                [_scan("old-main", "p1", "main", 1), _scan("develop-tip", "p1", "develop", 4)],
                [_project("p1", default_branch="main", deleted_branches=["main"])],
            )
        )

        assert result == {"p1": "develop-tip"}

    def test_without_a_default_branch_a_tag_build_ranks_behind_every_branch_build(self):
        """A tag pipeline writes its tag into branch, so it names no branch to be the tip of."""
        result, _ = asyncio.run(
            _resolve(
                [_scan("main-build", "p1", "main", 6), _scan("tag-build", "p1", "v2.0.0", 0, commit_tag="v2.0.0")],
                [_project("p1")],
            )
        )

        assert result == {"p1": "main-build"}

    def test_without_a_default_branch_a_pointer_to_a_tag_build_is_re_derived(self):
        result, _ = asyncio.run(
            _resolve(
                [_scan("main-build", "p1", "main", 6), _scan("tag-build", "p1", "v2.0.0", 0, commit_tag="v2.0.0")],
                [_project("p1", latest_scan_id="tag-build")],
            )
        )

        assert result == {"p1": "main-build"}

    @pytest.mark.parametrize("default_branch", [None, "main"])
    def test_a_newer_scan_without_an_sbom_does_not_take_head_from_the_build_that_has_one(self, default_branch):
        """Such a scan carries no dependencies, so heading with it would blank the project's vulnerabilities."""
        result, _ = asyncio.run(
            _resolve(
                [_scan("sbom-build", "p1", "main", 6), _scan("sast-only", "p1", "main", 0, sbom_refs=[])],
                [_project("p1", default_branch=default_branch)],
            )
        )

        assert result == {"p1": "sbom-build"}

    def test_a_project_whose_ci_only_builds_tags_is_headed_by_its_newest_tag_build(self):
        result, _ = asyncio.run(
            _resolve(
                [
                    _scan("v1", "p1", "v1.0.0", 30, commit_tag="v1.0.0"),
                    _scan("v2", "p1", "v2.0.0", 6, commit_tag="v2.0.0"),
                    _scan("v1-rescan", "p1", "v1.0.0", 0, commit_tag="v1.0.0", is_rescan=True, original_scan_id="v1"),
                ],
                [_project("p1")],
            )
        )

        assert result == {"p1": "v2"}


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

    def test_a_rescan_of_the_tip_is_preceded_by_the_build_before_the_tip(self):
        """A rescan re-analyses its build's commit, so comparing it with that build diffs a commit
        against itself."""
        result = asyncio.run(
            self._preceding_id(
                [
                    _scan("tip", "p1", "main", 5),
                    _scan("before-tip", "p1", "main", 10),
                    _scan(_HEAD, "p1", "main", 0, is_rescan=True, original_scan_id="tip"),
                ]
            )
        )

        assert result == "before-tip"

    def test_a_rescan_of_an_old_release_is_preceded_by_the_build_before_that_release(self):
        result = asyncio.run(
            self._preceding_id(
                [
                    _scan("newer-build", "p1", "main", 24),
                    _scan("release", "p1", "main", 100),
                    _scan("before-release", "p1", "main", 200),
                    _scan(_HEAD, "p1", "main", 0, is_rescan=True, original_scan_id="release"),
                ]
            )
        )

        assert result == "before-release"

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


def _waiver_on(finding_id: str) -> dict:
    return {
        "_id": f"w-{finding_id}",
        "project_id": "p1",
        "finding_id": finding_id,
        "scope": "finding",
        "finding_type": "vulnerability",
        "reason": "accepted",
        "created_by": "tester",
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
        project = await db.projects.find_one({"_id": "p1"})
        assert (project["latest_scan_id"], project["stats"]["critical"]) == ("main-tip", 1)

    @pytest.mark.asyncio
    async def test_a_build_finalized_while_the_recalc_waited_for_the_lock_is_the_head_it_stamps(self, monkeypatch):
        from app.repositories.distributed_locks import DistributedLocksRepository
        from app.services.stats import recalculate_project_stats

        db = FakeDatabase()
        await db.projects.insert_one(_project("p1", name="proj", default_branch="main", latest_scan_id="b1"))
        await db.scans.insert_one(_scan("b1", "p1", "main", 5))
        await db.findings.insert_one(_vulnerability("f-old", "b1", "HIGH"))
        acquire = DistributedLocksRepository.acquire_lock

        async def _b2_finalizes_while_another_recalc_holds_the_lock(self, *args):
            monkeypatch.setattr(DistributedLocksRepository, "acquire_lock", acquire)
            await db.scans.insert_one(_scan("b2", "p1", "main", 0))
            await db.findings.insert_one(_vulnerability("f-new", "b2", "CRITICAL"))
            await db.projects.update_one({"_id": "p1"}, {"$set": {"latest_scan_id": "b2"}})
            return False

        monkeypatch.setattr(
            DistributedLocksRepository, "acquire_lock", _b2_finalizes_while_another_recalc_holds_the_lock
        )
        monkeypatch.setattr("app.services.stats._LOCK_RETRY_BASE_DELAY", 0)

        stats = await recalculate_project_stats("p1", db)

        assert (stats.critical, stats.high) == (1, 0)
        project = await db.projects.find_one({"_id": "p1"})
        assert (project["latest_scan_id"], project["stats"]["critical"], project["stats"]["high"]) == ("b2", 1, 0)

    @pytest.mark.asyncio
    async def test_a_build_finalized_during_the_restamp_gets_the_waivers_too(self, monkeypatch):
        """The engine re-stamps a new head only while a waiver is active, so a deleted one's flags would stay."""
        from app.services import stats as stats_service

        db = FakeDatabase()
        await db.projects.insert_one(_project("p1", name="proj", default_branch="main", latest_scan_id="b1"))
        await db.scans.insert_one(_scan("b1", "p1", "main", 5))
        await db.waivers.insert_one(_waiver_on("CVE-W"))
        restamp = stats_service._restamp_scan

        async def _b2_finalizes_meanwhile(scan_id, *args):
            monkeypatch.setattr(stats_service, "_restamp_scan", restamp)
            await db.scans.insert_one(_scan("b2", "p1", "main", 0))
            await db.findings.insert_one(_vulnerability("CVE-W", "b2", "CRITICAL"))
            return await restamp(scan_id, *args)

        monkeypatch.setattr(stats_service, "_restamp_scan", _b2_finalizes_meanwhile)

        stats = await stats_service.recalculate_project_stats("p1", db)

        assert (await db.findings.find_one({"_id": "b2:CVE-W"}))["waived"] is True
        assert stats is not None and stats.critical == 0
        project = await db.projects.find_one({"_id": "p1"})
        assert (project["latest_scan_id"], project["stats"]["critical"]) == ("b2", 0)


class TestSyncProjectHead:
    """The one writer of ``latest_scan_id`` and ``project.stats``: head derived afresh, written over the pointer read."""

    @staticmethod
    async def _synced(db: FakeDatabase, project: dict) -> tuple[str | None, dict]:
        await db.projects.insert_one(project)
        written = await ScanRepository(db).sync_project_head(project["_id"])
        return written, await db.projects.find_one({"_id": project["_id"]})

    @pytest.mark.asyncio
    async def test_caches_the_derived_head_rather_than_the_pointer_it_replaces(self):
        db = await _seeded(
            [_scan("scan-old", "p1", "main", 10), _scan("main-tip", "p1", "main", 5, stats=Stats().model_dump())]
        )

        written, project = await self._synced(db, _project("p1", latest_scan_id="scan-old", default_branch="main"))

        assert written == "main-tip"
        assert (project["latest_scan_id"], project["stats"]) == ("main-tip", Stats().model_dump())

    @pytest.mark.asyncio
    async def test_a_newer_scan_without_an_sbom_is_not_the_head_it_caches(self):
        db = await _seeded(
            [
                _scan("sbom-build", "p1", "main", 5, stats={"critical": 9}),
                _scan("sast-only", "p1", "main", 1, sbom_refs=[], stats={"critical": 0}),
            ]
        )

        written, project = await self._synced(db, _project("p1", latest_scan_id="sast-only"))

        assert written == "sbom-build"
        assert project["stats"] == {"critical": 9}

    @pytest.mark.asyncio
    async def test_clears_both_fields_when_nothing_usable_is_left(self):
        db = await _seeded([_scan("on-gone", "p1", "gone", 1, stats={"critical": 3})])

        written, project = await self._synced(
            db, _project("p1", latest_scan_id="on-gone", deleted_branches=["gone"], stats={"critical": 3})
        )

        assert written is None
        assert (project["latest_scan_id"], project["stats"]) == (None, None)

    @pytest.mark.asyncio
    async def test_a_pointer_moved_since_it_was_read_is_derived_again(self, monkeypatch):
        """A writer that moved the pointer meanwhile saw newer scans, so an older derivation must not land."""
        db = await _seeded([_scan("b1", "p1", "main", 2), _scan("b2", "p1", "main", 0)])
        await db.projects.insert_one(_project("p1", latest_scan_id="b0", default_branch="main"))
        derive = ScanRepository._head_scan_ids

        async def _b2_finalizes_meanwhile(self, scopes):
            monkeypatch.setattr(ScanRepository, "_head_scan_ids", derive)
            await db.projects.update_one({"_id": "p1"}, {"$set": {"latest_scan_id": "b2"}})
            return {"p1": "b1"}

        monkeypatch.setattr(ScanRepository, "_head_scan_ids", _b2_finalizes_meanwhile)

        assert await ScanRepository(db).sync_project_head("p1") == "b2"
        assert (await db.projects.find_one({"_id": "p1"}))["latest_scan_id"] == "b2"

    @pytest.mark.asyncio
    async def test_a_project_that_is_gone_is_left_alone(self):
        db = await _seeded([_scan("main-tip", "p1", "main", 5)])

        assert await ScanRepository(db).sync_project_head("p1") is None
        assert await db.projects.find_one({"_id": "p1"}) is None
