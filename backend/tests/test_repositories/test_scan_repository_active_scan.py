"""Tests for the canonical latest-active-scan selection on ScanRepository and its delegators.

The rule: select the latest completed scan whose branch is not deleted. The selector must
always exclude deleted-branch scans when a project has deleted branches.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from app.models.stats import Stats
from app.repositories.scans import ScanRepository
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.mongodb import create_mock_collection, create_mock_db

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def _completed_scan_doc(scan_id: str = "scan-1", branch: str = "main", with_stats: bool = False) -> dict:
    doc = {
        "_id": scan_id,
        "project_id": "p1",
        "branch": branch,
        "status": "completed",
        "created_at": datetime(2026, 7, 1, tzinfo=timezone.utc),
    }
    if with_stats:
        doc["stats"] = Stats().model_dump()
    return doc


class TestGetLatestActiveScan:
    def test_excludes_deleted_branches_in_query(self):
        coll = create_mock_collection(find_one=_completed_scan_doc("scan-9"))
        repo = ScanRepository(create_mock_db({"scans": coll}))

        result = asyncio.run(repo.get_latest_active_scan({"_id": "p1", "deleted_branches": ["feature-x", "old"]}))

        query = coll.find_one.call_args.args[0]
        assert query["project_id"] == "p1"
        assert query["status"] == {"$in": ["completed", "completed_with_errors"]}
        assert query["branch"] == {"$nin": ["feature-x", "old"]}
        assert coll.find_one.call_args.kwargs["sort"] == [("created_at", -1)]
        assert result is not None and result.id == "scan-9"

    def test_no_branch_filter_when_no_deleted_branches(self):
        coll = create_mock_collection(find_one=_completed_scan_doc())
        repo = ScanRepository(create_mock_db({"scans": coll}))

        asyncio.run(repo.get_latest_active_scan({"_id": "p1", "deleted_branches": []}))

        query = coll.find_one.call_args.args[0]
        assert "branch" not in query
        assert query == {"project_id": "p1", "status": {"$in": ["completed", "completed_with_errors"]}}

    def test_deleted_branches_override(self):
        """An explicit deleted_branches arg takes precedence over the project's stored value."""
        coll = create_mock_collection(find_one=_completed_scan_doc())
        repo = ScanRepository(create_mock_db({"scans": coll}))

        asyncio.run(
            repo.get_latest_active_scan(
                {"_id": "p1", "deleted_branches": ["stale"]},
                deleted_branches=["fresh-a", "fresh-b"],
            )
        )

        query = coll.find_one.call_args.args[0]
        assert query["branch"] == {"$nin": ["fresh-a", "fresh-b"]}

    def test_accepts_project_model_like_object(self):
        coll = create_mock_collection(find_one=_completed_scan_doc())
        repo = ScanRepository(create_mock_db({"scans": coll}))

        project = MagicMock()
        project.id = "proj-42"
        project.deleted_branches = ["gone"]

        asyncio.run(repo.get_latest_active_scan(project))

        query = coll.find_one.call_args.args[0]
        assert query["project_id"] == "proj-42"
        assert query["branch"] == {"$nin": ["gone"]}

    def test_returns_none_when_no_scan(self):
        coll = create_mock_collection(find_one=None)
        repo = ScanRepository(create_mock_db({"scans": coll}))

        assert asyncio.run(repo.get_latest_active_scan({"_id": "p1", "deleted_branches": ["x"]})) is None


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
    db = FakeDatabase()
    for scan in scans:
        await db.scans.insert_one(scan)
    counting = _CountingScans(db.scans)
    repo = ScanRepository(db)
    repo.collection = counting
    return await repo.get_latest_active_scan_ids(projects), counting


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


class TestStatsDelegation:
    """stats._resolve_active_scan_id keeps its short-circuits and delegates the fallback lookup."""

    def test_returns_scan_id_when_no_deleted_branches(self):
        from app.services import stats

        db = create_mock_db({"scans": create_mock_collection()})
        result = asyncio.run(stats._resolve_active_scan_id(db, "p1", "scan-1", []))
        assert result == "scan-1"

    def test_returns_scan_id_when_current_branch_not_deleted(self):
        from app.services import stats

        coll = create_mock_collection(find_one={"_id": "scan-1", "branch": "main"})
        db = create_mock_db({"scans": coll})
        result = asyncio.run(stats._resolve_active_scan_id(db, "p1", "scan-1", ["feature"]))
        assert result == "scan-1"

    def test_resolves_active_scan_when_current_on_deleted_branch(self):
        from app.services import stats

        # First find_one returns the current scan (on a deleted branch); the
        # canonical fallback find_one returns the replacement active scan.
        coll = MagicMock()
        from unittest.mock import AsyncMock

        coll.find_one = AsyncMock(
            side_effect=[
                {"_id": "scan-1", "branch": "feature"},  # current scan lookup
                _completed_scan_doc("scan-active", branch="main"),  # canonical fallback selection
            ]
        )
        db = create_mock_db({"scans": coll})

        result = asyncio.run(stats._resolve_active_scan_id(db, "p1", "scan-1", ["feature"]))

        assert result == "scan-active"
        # The fallback query must exclude the deleted branch.
        fallback_query = coll.find_one.call_args_list[1].args[0]
        assert fallback_query["branch"] == {"$nin": ["feature"]}
        assert fallback_query["status"] == {"$in": ["completed", "completed_with_errors"]}

    def test_returns_none_when_no_active_scan(self):
        from unittest.mock import AsyncMock

        from app.services import stats

        coll = MagicMock()
        coll.find_one = AsyncMock(
            side_effect=[
                {"_id": "scan-1", "branch": "feature"},  # current scan on deleted branch
                None,  # no replacement
            ]
        )
        db = create_mock_db({"scans": coll})

        result = asyncio.run(stats._resolve_active_scan_id(db, "p1", "scan-1", ["feature"]))
        assert result is None


class TestHousekeepingDelegation:
    """housekeeping._resolve_latest_scan_after_branch_deletion keeps its update-dict shape while delegating selection."""

    def test_updates_from_active_scan(self):
        from unittest.mock import AsyncMock

        from app.core import housekeeping

        coll = MagicMock()
        coll.find_one = AsyncMock(
            side_effect=[
                {"_id": "scan-old", "branch": "feature"},  # current scan on deleted branch
                _completed_scan_doc("scan-new", branch="main", with_stats=True),  # replacement
            ]
        )
        db = create_mock_db({"scans": coll})

        project_data = {"_id": "p1", "latest_scan_id": "scan-old"}
        updates = asyncio.run(
            housekeeping._resolve_latest_scan_after_branch_deletion(project_data, ["feature"], db, "proj")
        )

        assert updates["latest_scan_id"] == "scan-new"
        assert updates["last_scan_at"] is not None
        # stats round-trips back to the stored (model_dump) shape.
        assert updates["stats"] == Stats().model_dump()

    def test_clears_when_no_active_scan(self):
        from unittest.mock import AsyncMock

        from app.core import housekeeping

        coll = MagicMock()
        coll.find_one = AsyncMock(
            side_effect=[
                {"_id": "scan-old", "branch": "feature"},
                None,  # no replacement scan on an active branch
            ]
        )
        db = create_mock_db({"scans": coll})

        project_data = {"_id": "p1", "latest_scan_id": "scan-old"}
        updates = asyncio.run(
            housekeeping._resolve_latest_scan_after_branch_deletion(project_data, ["feature"], db, "proj")
        )

        assert updates == {"latest_scan_id": None, "stats": None}

    def test_noop_when_current_scan_not_on_deleted_branch(self):
        from unittest.mock import AsyncMock

        from app.core import housekeeping

        coll = MagicMock()
        coll.find_one = AsyncMock(return_value={"_id": "scan-old", "branch": "main"})
        db = create_mock_db({"scans": coll})

        project_data = {"_id": "p1", "latest_scan_id": "scan-old"}
        updates = asyncio.run(
            housekeeping._resolve_latest_scan_after_branch_deletion(project_data, ["feature"], db, "proj")
        )
        assert updates == {}
