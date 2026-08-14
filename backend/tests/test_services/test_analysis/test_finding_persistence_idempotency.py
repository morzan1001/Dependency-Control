"""W30: finding persistence must be idempotent — a raced double-persist must not double the finding set."""

import pytest

from app.models.finding import Finding, FindingType, Severity
from app.repositories.findings import FindingRepository
from app.services.analysis.engine import _prepare_finding_records
from tests.mocks.fake_mongo import FakeDatabase

_SCAN_ID = "ed8fa8da-205c-5bac-852b-9fafd4a33bb8"


@pytest.fixture
def db():
    return FakeDatabase()


def _finding(fid: str, component: str = "hamcrest-core", version: str = "3.0") -> Finding:
    return Finding(
        id=fid,
        type=FindingType.QUALITY,
        severity=Severity.MEDIUM,
        component=component,
        version=version,
        description="quality issue",
        scanners=["deps_dev"],
    )


class TestDeterministicIds:
    def test_same_finding_gets_same_id_across_runs(self):
        records_a, _ = _prepare_finding_records([_finding("QUALITY:hamcrest-core:3.0")], _SCAN_ID, "proj-1", None)
        records_b, _ = _prepare_finding_records([_finding("QUALITY:hamcrest-core:3.0")], _SCAN_ID, "proj-1", None)
        assert records_a[0]["_id"] == records_b[0]["_id"]

    def test_different_scans_get_different_ids(self):
        records_a, _ = _prepare_finding_records([_finding("QUALITY:hamcrest-core:3.0")], _SCAN_ID, "proj-1", None)
        records_b, _ = _prepare_finding_records([_finding("QUALITY:hamcrest-core:3.0")], "other-scan", "proj-1", None)
        assert records_a[0]["_id"] != records_b[0]["_id"]

    def test_duplicate_identities_within_one_batch_stay_distinct(self):
        findings = [_finding("QUALITY:hamcrest-core:3.0"), _finding("QUALITY:hamcrest-core:3.0")]
        records, _ = _prepare_finding_records(findings, _SCAN_ID, "proj-1", None)
        assert records[0]["_id"] != records[1]["_id"]


@pytest.mark.asyncio
async def test_double_persist_of_same_records_does_not_double_findings(db):
    """Simulates the race path: both workers' deletes land before both inserts."""
    repo = FindingRepository(db)
    findings = [_finding(f"QUALITY:pkg-{i}:1.0", component=f"pkg-{i}", version="1.0") for i in range(3)]
    records, _ = _prepare_finding_records(findings, _SCAN_ID, "proj-1", None)

    first = await repo.create_many_raw([dict(r) for r in records])
    second = await repo.create_many_raw([dict(r) for r in records])

    assert first == 3
    assert second == 0, "re-inserting the same records must be a no-op, not a second copy"
    stored = await db.findings.count_documents({"scan_id": _SCAN_ID})
    assert stored == 3, f"raced double-persist must leave exactly one copy, got {stored}"
