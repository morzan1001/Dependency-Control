"""Tests for the canonical latest-active-scan selection on ScanRepository and its delegators.

The rule: select the latest completed scan whose branch is not deleted. The selector must
always exclude deleted-branch scans when a project has deleted branches.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock

from app.models.stats import Stats
from app.repositories.scans import ScanRepository
from tests.mocks.mongodb import create_mock_collection, create_mock_db


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
        assert query["status"] == "completed"
        assert query["branch"] == {"$nin": ["feature-x", "old"]}
        assert coll.find_one.call_args.kwargs["sort"] == [("created_at", -1)]
        assert result is not None and result.id == "scan-9"

    def test_no_branch_filter_when_no_deleted_branches(self):
        coll = create_mock_collection(find_one=_completed_scan_doc())
        repo = ScanRepository(create_mock_db({"scans": coll}))

        asyncio.run(repo.get_latest_active_scan({"_id": "p1", "deleted_branches": []}))

        query = coll.find_one.call_args.args[0]
        assert "branch" not in query
        assert query == {"project_id": "p1", "status": "completed"}

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


class TestGetLatestActiveScanIds:
    def test_uses_latest_scan_id_when_no_deleted_branches(self):
        coll = create_mock_collection()
        repo = ScanRepository(create_mock_db({"scans": coll}))

        p = MagicMock()
        p.id = "p1"
        p.deleted_branches = []
        p.latest_scan_id = "scan-latest"

        result = asyncio.run(repo.get_latest_active_scan_ids([p]))

        assert result == {"p1": "scan-latest"}
        # No deleted branches -> no aggregation needed.
        coll.aggregate.assert_not_called()

    def test_aggregates_for_projects_with_deleted_branches(self):
        coll = create_mock_collection(aggregate=[{"_id": "p2", "scan_id": "scan-active"}])
        repo = ScanRepository(create_mock_db({"scans": coll}))

        p = MagicMock()
        p.id = "p2"
        p.deleted_branches = ["dead"]
        p.latest_scan_id = "scan-on-dead-branch"

        result = asyncio.run(repo.get_latest_active_scan_ids([p]))

        assert result == {"p2": "scan-active"}
        pipeline = coll.aggregate.call_args.args[0]
        match = pipeline[0]["$match"]["$or"][0]
        assert match == {"project_id": "p2", "branch": {"$nin": ["dead"]}, "status": "completed"}
        assert pipeline[1]["$sort"] == {"created_at": -1}
        assert pipeline[2]["$group"] == {"_id": "$project_id", "scan_id": {"$first": "$_id"}}

    def test_skips_projects_without_latest_scan_id(self):
        coll = create_mock_collection()
        repo = ScanRepository(create_mock_db({"scans": coll}))

        p = MagicMock()
        p.id = "p3"
        p.deleted_branches = []
        p.latest_scan_id = None

        assert asyncio.run(repo.get_latest_active_scan_ids([p])) == {}

    def test_mixed_projects(self):
        coll = create_mock_collection(aggregate=[{"_id": "p_deleted", "scan_id": "active-scan"}])
        repo = ScanRepository(create_mock_db({"scans": coll}))

        clean = MagicMock(id="p_clean", deleted_branches=[], latest_scan_id="clean-scan")
        deleted = MagicMock(id="p_deleted", deleted_branches=["x"], latest_scan_id="on-deleted")

        result = asyncio.run(repo.get_latest_active_scan_ids([clean, deleted]))

        assert result == {"p_clean": "clean-scan", "p_deleted": "active-scan"}


class TestAnalyticsDelegation:
    """analytics helper delegates to the canonical repo method."""

    def test_resolve_active_scan_ids_delegates(self):
        from app.api.v1.helpers import analytics

        coll = create_mock_collection(aggregate=[{"_id": "p2", "scan_id": "active"}])
        db = create_mock_db({"scans": coll})

        clean = MagicMock(id="p1", deleted_branches=[], latest_scan_id="scan-1")
        deleted = MagicMock(id="p2", deleted_branches=["dead"], latest_scan_id="scan-dead")

        result = asyncio.run(analytics._resolve_active_scan_ids([clean, deleted], db))

        assert result == {"p1": "scan-1", "p2": "active"}


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
        assert fallback_query["status"] == "completed"

    def test_returns_none_when_no_active_scan(self):
        from app.services import stats
        from unittest.mock import AsyncMock

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
        from app.core import housekeeping
        from unittest.mock import AsyncMock

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
        from app.core import housekeeping
        from unittest.mock import AsyncMock

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
        from app.core import housekeeping
        from unittest.mock import AsyncMock

        coll = MagicMock()
        coll.find_one = AsyncMock(return_value={"_id": "scan-old", "branch": "main"})
        db = create_mock_db({"scans": coll})

        project_data = {"_id": "p1", "latest_scan_id": "scan-old"}
        updates = asyncio.run(
            housekeeping._resolve_latest_scan_after_branch_deletion(project_data, ["feature"], db, "proj")
        )
        assert updates == {}
