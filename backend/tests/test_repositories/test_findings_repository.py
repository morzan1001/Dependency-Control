"""Tests for FindingRepository analytics methods."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from app.repositories.findings import FindingRepository
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.mongodb import create_mock_collection, create_mock_db


def _capture_pipeline(collection) -> list[dict[str, Any]]:
    """Return the pipeline passed to collection.aggregate()."""
    call_args = collection.aggregate.call_args
    assert call_args is not None, "collection.aggregate was never called"
    return call_args[0][0]


class TestGetSeverityDistributionScanScope:
    """get_severity_distribution scopes its $match by scan_id."""

    def _run(self, scan_ids, agg_results=None):
        collection = create_mock_collection()
        agg_cursor = MagicMock()
        agg_cursor.to_list = AsyncMock(return_value=agg_results or [])
        collection.aggregate = MagicMock(return_value=agg_cursor)
        db = create_mock_db({"findings": collection})
        repo = FindingRepository(db)
        result = asyncio.run(repo.get_severity_distribution(scan_ids))
        return result, collection

    def test_scan_id_in_severity_match(self):
        scan_ids = ["scan-x", "scan-y"]
        _, collection = self._run(scan_ids)

        pipeline = _capture_pipeline(collection)
        match_stage = pipeline[0]["$match"]
        assert match_stage["scan_id"] == {"$in": scan_ids}


class TestGetSeverityDistributionSkipsWaived:
    """A waived finding is accepted risk, so the severity breakdown the dashboards read must not
    show it while the counts beside it, computed the same way, do not."""

    @staticmethod
    def _finding(finding_id: str, severity: str, **overrides) -> dict[str, Any]:
        doc = {
            "_id": finding_id,
            "finding_id": finding_id,
            "scan_id": "scan-1",
            "project_id": "p1",
            "type": "vulnerability",
            "severity": severity,
            "component": "pkg",
        }
        doc.update(overrides)
        return doc

    def _distribution(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        async def run():
            db = FakeDatabase()
            for doc in findings:
                await db.findings.insert_one(doc)
            return await FindingRepository(db).get_severity_distribution(["scan-1"])

        return asyncio.run(run())

    def test_a_waived_finding_is_left_out_of_the_distribution(self):
        distribution = self._distribution(
            [
                self._finding("f-open", "HIGH"),
                self._finding("f-waived", "HIGH", waived=True),
                self._finding("f-low", "LOW"),
            ]
        )

        assert distribution == {"HIGH": 1, "LOW": 1}

    def test_a_finding_that_never_carried_the_flag_still_counts(self):
        """``waived`` is tri-state: absent and False both mean open."""
        distribution = self._distribution(
            [self._finding("f-absent", "CRITICAL"), self._finding("f-false", "CRITICAL", waived=False)]
        )

        assert distribution == {"CRITICAL": 2}


def test_location_findings_carry_details_only_where_no_signature_is_stored():
    asyncio.run(_location_findings_carry_details_only_where_no_signature_is_stored())


async def _location_findings_carry_details_only_where_no_signature_is_stored():
    db = FakeDatabase()
    await db.findings.insert_many(
        [
            {
                "_id": "signed",
                "scan_id": "s",
                "type": "sast",
                "component": "a.py",
                "match": {"rule_key": "r"},
                "details": {"big": 1},
            },
            {
                "_id": "unsigned",
                "scan_id": "s",
                "type": "iac",
                "component": "b.tf",
                "match": None,
                "details": {"rule_id": "q"},
            },
            {"_id": "vuln", "scan_id": "s", "type": "vulnerability", "component": "pkg", "details": {}},
        ]
    )

    docs = {d["_id"]: d for d in await FindingRepository(db).find_location_findings("s")}

    assert set(docs) == {"signed", "unsigned"}
    assert "details" not in docs["signed"]
    assert docs["unsigned"]["details"] == {"rule_id": "q"}
