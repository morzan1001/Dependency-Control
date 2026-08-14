"""Legacy-path waivers must record what they matched, like the signature path does.

Without an outcome an operator cannot tell that a waiver suppresses nothing any more —
prod has 81 waivers on this path with ``last_match_count: None``. Fixtures use the real
stored waiver shape (package_name always set, scope 'finding'/'file', status a risk label).
"""

import asyncio

import pytest

from app.models.waiver import Waiver
from app.repositories.findings import FindingRepository
from app.repositories.waivers import WaiverRepository
from app.services.stats import _apply_waivers
from tests.mocks.fake_mongo import FakeDatabase

SCAN_ID = "scan-k21"


def _finding(_id: str, finding_type: str, finding_id: str, component: str, version: str | None = None) -> dict:
    return {
        "_id": _id,
        "finding_id": finding_id,
        "scan_id": SCAN_ID,
        "project_id": "p",
        "type": finding_type,
        "severity": "MEDIUM",
        "component": component,
        "version": version,
        "waived": False,
    }


@pytest.fixture
def db():
    database = FakeDatabase()
    for doc in (
        _finding("f1", "license", "LIC-GPL-2.0-only", "spring-core", "6.1.0"),
        _finding("f2", "license", "LIC-GPL-2.0-only", "jackson-databind", "2.20.2"),
        _finding("f3", "quality", "MAINT-left-pad", "left-pad", "1.3.0"),
    ):
        asyncio.run(database.findings.insert_one(doc))
    return database


def _apply(db, waivers):
    repo = WaiverRepository(db)
    for waiver in waivers:
        asyncio.run(repo.create(waiver))
    asyncio.run(_apply_waivers(FindingRepository(db), SCAN_ID, waivers, repo))
    return {w.id: asyncio.run(db.waivers.find_one({"_id": w.id})) for w in waivers}


class TestLegacyWaiverRecordsItsOutcome:
    def test_matching_waiver_records_the_count_and_scan(self, db):
        waiver = Waiver(
            reason="approved",
            created_by="u",
            finding_type="quality",
            finding_id="MAINT-left-pad",
            package_name="left-pad",
            package_version="1.3.0",
        )

        stored = _apply(db, [waiver])[waiver.id]

        assert stored["last_match_count"] == 1
        assert stored["last_eval_scan_id"] == SCAN_ID

    def test_orphaned_waiver_records_zero_instead_of_staying_unknown(self, db):
        waiver = Waiver(
            reason="approved",
            created_by="u",
            finding_type="quality",
            finding_id="MAINT-renamed-package",
            package_name="renamed-package",
        )

        stored = _apply(db, [waiver])[waiver.id]

        assert stored["last_match_count"] == 0
        assert stored["last_eval_scan_id"] == SCAN_ID

    def test_unscoped_license_waiver_reports_how_many_components_it_suppresses(self, db, caplog):
        """finding_id is not unique per scan for license findings; the breadth must be visible."""
        waiver = Waiver(
            reason="approved",
            created_by="u",
            finding_type="license",
            finding_id="LIC-GPL-2.0-only",
        )

        stored = _apply(db, [waiver])[waiver.id]

        assert stored["last_match_count"] == 2
        assert any("suppresses 2 findings" in record.message for record in caplog.records)

    def test_vulnerability_id_waiver_records_its_outcome_too(self, db):
        asyncio.run(
            db.findings.insert_one(
                {
                    "_id": "f4",
                    "finding_id": "express:4.18.2",
                    "scan_id": SCAN_ID,
                    "project_id": "p",
                    "type": "vulnerability",
                    "severity": "MEDIUM",
                    "component": "express",
                    "version": "4.18.2",
                    "waived": False,
                    "details": {"vulnerabilities": [{"id": "CVE-2024-29041", "severity": "MEDIUM", "aliases": []}]},
                }
            )
        )
        waiver = Waiver(
            reason="approved",
            created_by="u",
            finding_type="vulnerability",
            vulnerability_id="CVE-2024-29041",
            package_name="express",
        )

        stored = _apply(db, [waiver])[waiver.id]

        assert stored["last_match_count"] == 1
        assert stored["last_eval_scan_id"] == SCAN_ID
