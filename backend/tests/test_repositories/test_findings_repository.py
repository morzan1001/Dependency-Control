"""Tests for FindingRepository analytics methods."""

import asyncio
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

from app.repositories.findings import FindingRepository
from tests.mocks.mongodb import create_mock_collection


def _make_mock_db(collection):
    db = MagicMock()
    db.__getitem__ = MagicMock(return_value=collection)
    return db


def _capture_pipeline(collection) -> List[Dict[str, Any]]:
    """Return the pipeline passed to collection.aggregate()."""
    call_args = collection.aggregate.call_args
    assert call_args is not None, "collection.aggregate was never called"
    return call_args[0][0]


class TestGetVulnCountsByComponentsScanScope:
    """get_vuln_counts_by_components must restrict results to the supplied scan_ids."""

    def _run(self, scan_ids, project_ids, component_names, agg_results=None):
        collection = create_mock_collection()
        # base.aggregate() calls collection.aggregate(pipeline).to_list(limit).
        agg_cursor = MagicMock()
        agg_cursor.to_list = AsyncMock(return_value=agg_results or [])
        collection.aggregate = MagicMock(return_value=agg_cursor)

        db = _make_mock_db(collection)
        repo = FindingRepository(db)

        result = asyncio.run(repo.get_vuln_counts_by_components(scan_ids, project_ids, component_names))
        return result, collection

    def test_scan_id_in_pipeline_match(self):
        scan_ids = ["scan-latest"]
        _, collection = self._run(scan_ids, ["proj-1"], ["requests"])

        pipeline = _capture_pipeline(collection)
        match_stage = pipeline[0]["$match"]
        assert "scan_id" in match_stage, "$match must contain scan_id"
        assert match_stage["scan_id"] == {"$in": scan_ids}

    def test_latest_scan_finding_is_counted(self):
        agg_results = [{"_id": "requests", "count": 3}]
        result, _ = self._run(
            scan_ids=["scan-latest"],
            project_ids=["proj-1"],
            component_names=["requests"],
            agg_results=agg_results,
        )
        assert result["requests"] == 3

    def test_project_id_still_in_pipeline_match(self):
        project_ids = ["proj-1", "proj-2"]
        _, collection = self._run(["scan-1"], project_ids, ["pkg"])

        pipeline = _capture_pipeline(collection)
        match_stage = pipeline[0]["$match"]
        assert "project_id" in match_stage
        assert match_stage["project_id"] == {"$in": project_ids}

    def test_waived_excluded_from_count(self):
        _, collection = self._run(["scan-1"], ["proj-1"], ["pkg"])

        pipeline = _capture_pipeline(collection)
        match_stage = pipeline[0]["$match"]
        assert match_stage.get("waived") == {"$ne": True}


class TestGetSeverityDistributionScanScope:
    """get_severity_distribution scopes its $match by scan_id."""

    def _run(self, scan_ids, agg_results=None):
        collection = create_mock_collection()
        agg_cursor = MagicMock()
        agg_cursor.to_list = AsyncMock(return_value=agg_results or [])
        collection.aggregate = MagicMock(return_value=agg_cursor)
        db = _make_mock_db(collection)
        repo = FindingRepository(db)
        result = asyncio.run(repo.get_severity_distribution(scan_ids))
        return result, collection

    def test_scan_id_in_severity_match(self):
        scan_ids = ["scan-x", "scan-y"]
        _, collection = self._run(scan_ids)

        pipeline = _capture_pipeline(collection)
        match_stage = pipeline[0]["$match"]
        assert match_stage["scan_id"] == {"$in": scan_ids}
