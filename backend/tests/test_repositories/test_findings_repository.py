"""Tests for FindingRepository analytics methods."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from app.repositories.findings import FindingRepository
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.mongodb import create_mock_collection


def _make_mock_db(collection):
    db = MagicMock()
    db.__getitem__ = MagicMock(return_value=collection)
    return db


def _capture_pipeline(collection) -> list[dict[str, Any]]:
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


class TestApplyVulnerabilityWaiverAliasMatch:
    """A waiver keyed to a GHSA id must reach the entry now surfaced under its CVE id."""

    _GHSA = "GHSA-3pjw-73gf-8qr5"

    def _capture_update(self):
        collection = create_mock_collection()
        db = _make_mock_db(collection)
        repo = FindingRepository(db)
        asyncio.run(repo.apply_vulnerability_waiver("scan-1", self._GHSA, waived=True, waiver_reason="accepted"))
        return collection.update_many.call_args

    def test_query_matches_id_aliases_and_resolved_cve(self):
        args, _ = self._capture_update()
        query = args[0]
        assert query["scan_id"] == "scan-1"
        assert query["type"] == "vulnerability"
        assert query["$or"] == [
            {"details.vulnerabilities.id": self._GHSA},
            {"details.vulnerabilities.aliases": self._GHSA},
            {"details.vulnerabilities.resolved_cve": self._GHSA},
        ]

    def test_array_filter_targets_entry_by_any_known_id(self):
        # Verified against a real mongod: $or in an array filter is valid when all
        # paths share the identifier, and it waives exactly the aliased entry.
        _, kwargs = self._capture_update()
        assert kwargs["array_filters"] == [
            {
                "$or": [
                    {"vuln.id": self._GHSA},
                    {"vuln.aliases": self._GHSA},
                    {"vuln.resolved_cve": self._GHSA},
                ]
            }
        ]

    def test_ghsa_keyed_waiver_reaches_doc_with_cve_keyed_entry(self):
        db = FakeDatabase()
        asyncio.run(
            db.findings.insert_one(
                {
                    "_id": "f1",
                    "scan_id": "scan-1",
                    "type": "vulnerability",
                    "details": {
                        "vulnerabilities": [
                            {
                                "id": "CVE-2026-59888",
                                "aliases": [self._GHSA],
                                "resolved_cve": "CVE-2026-59888",
                            }
                        ]
                    },
                }
            )
        )
        repo = FindingRepository(db)

        modified = asyncio.run(repo.apply_vulnerability_waiver("scan-1", self._GHSA, waived=True))

        assert modified == 1


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
