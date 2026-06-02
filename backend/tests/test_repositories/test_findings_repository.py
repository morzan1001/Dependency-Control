"""Tests for FindingRepository analytics methods.

Verifies that get_vuln_counts_by_components scopes its $match to the provided
scan_ids so that findings from historical scans do not bleed into counts for
the current active scans.
"""

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


# ---------------------------------------------------------------------------
# get_vuln_counts_by_components — pipeline must include scan_id restriction
# ---------------------------------------------------------------------------


class TestGetVulnCountsByComponentsScanScope:
    """get_vuln_counts_by_components must restrict results to the supplied scan_ids.

    A component that had a vulnerability in an OLD scan but is fixed (absent
    from findings) in the latest scan MUST NOT be counted.
    """

    def _run(self, scan_ids, project_ids, component_names, agg_results=None):
        collection = create_mock_collection()
        # Provide a to_list-capable cursor so that base.aggregate() works.
        # base.aggregate() does: self.collection.aggregate(pipeline).to_list(limit)
        agg_cursor = MagicMock()
        agg_cursor.to_list = AsyncMock(return_value=agg_results or [])
        collection.aggregate = MagicMock(return_value=agg_cursor)

        db = _make_mock_db(collection)
        repo = FindingRepository(db)

        result = asyncio.run(repo.get_vuln_counts_by_components(scan_ids, project_ids, component_names))
        return result, collection

    def test_scan_id_in_pipeline_match(self):
        """The $match stage MUST include scan_id: {$in: scan_ids}."""
        scan_ids = ["scan-latest"]
        _, collection = self._run(scan_ids, ["proj-1"], ["requests"])

        pipeline = _capture_pipeline(collection)
        match_stage = pipeline[0]["$match"]
        assert "scan_id" in match_stage, "$match must contain scan_id"
        assert match_stage["scan_id"] == {"$in": scan_ids}

    def test_historical_scan_findings_not_counted(self):
        """Component with vuln only in OLD scan → count must be 0 for latest scan.

        The repository returns counts from whatever the aggregation returns;
        the scan_id filter ensures only latest-scan docs are aggregated.
        Simulate the DB returning zero results (because the filter excludes
        old-scan rows), and assert the count is 0 for the component.
        """
        # Aggregation returns nothing → old-scan finding was filtered out
        result, _ = self._run(
            scan_ids=["scan-latest"],
            project_ids=["proj-1"],
            component_names=["lodash"],
            agg_results=[],
        )
        assert result.get("lodash", 0) == 0

    def test_latest_scan_finding_is_counted(self):
        """Component with vuln in the latest scan IS counted."""
        agg_results = [{"_id": "requests", "count": 3}]
        result, _ = self._run(
            scan_ids=["scan-latest"],
            project_ids=["proj-1"],
            component_names=["requests"],
            agg_results=agg_results,
        )
        assert result["requests"] == 3

    def test_project_id_still_in_pipeline_match(self):
        """project_id filter must still be present alongside scan_id."""
        project_ids = ["proj-1", "proj-2"]
        _, collection = self._run(["scan-1"], project_ids, ["pkg"])

        pipeline = _capture_pipeline(collection)
        match_stage = pipeline[0]["$match"]
        assert "project_id" in match_stage
        assert match_stage["project_id"] == {"$in": project_ids}

    def test_waived_excluded_from_count(self):
        """waived findings must be excluded (waived: {$ne: true}) in the $match."""
        _, collection = self._run(["scan-1"], ["proj-1"], ["pkg"])

        pipeline = _capture_pipeline(collection)
        match_stage = pipeline[0]["$match"]
        assert match_stage.get("waived") == {"$ne": True}


# ---------------------------------------------------------------------------
# get_severity_distribution — existing scan_id scope must remain intact
# ---------------------------------------------------------------------------


class TestGetSeverityDistributionScanScope:
    """Regression: get_severity_distribution already scopes by scan_id; verify
    the signature and match stage are still correct."""

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
