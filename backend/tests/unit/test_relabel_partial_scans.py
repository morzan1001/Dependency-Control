"""relabel_partial_scans and dedupe_duplicated_scan_findings must key scans on `_id`.

The scans collection has no `scan_id` field — the id lives in `_id`, while findings and
dependencies carry a `scan_id` reference. Keying the scan lookup on `scan_id` matches nothing
and both migrations report a clean no-op run.
"""

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_COMPLETED_WITH_ERRORS
from scripts.dedupe_duplicated_scan_findings import dedupe
from scripts.relabel_partial_scans import relabel
from tests.mocks.fake_mongo import FakeDatabase

SCAN_ID = "c55d2890-def3-5b5d-bff5-c7d2d0011573"


def _scan(status=SCAN_STATUS_COMPLETED, findings_count=2):
    return {
        "_id": SCAN_ID,
        "status": status,
        "findings_count": findings_count,
        "retry_count": 1,
        "latest_run": {"scan_id": SCAN_ID, "status": status, "findings_count": findings_count},
    }


def _finding(_id, finding_id, component="pkg", type_="vulnerability"):
    return {
        "_id": _id,
        "finding_id": finding_id,
        "scan_id": SCAN_ID,
        "type": type_,
        "component": component,
        "version": "1.0.0",
        "severity": "HIGH",
    }


@pytest.mark.asyncio
async def test_relabel_finds_the_scan_by_id():
    db = FakeDatabase()
    await db.scans.insert_one(_scan())
    await db.findings.insert_one(_finding("f1", "SCAN-ERROR-grype", type_="system_warning"))
    await db.findings.insert_one(_finding("f2", "CVE-2024-1"))
    await db.dependencies.insert_one({"_id": "d1", "scan_id": SCAN_ID, "name": "pkg", "version": "1.0.0"})

    counters = await relabel(db, batch_size=100, sleep_ms=0, execute=True)

    assert counters["candidates"] == 1
    assert counters["relabelled"] == 1
    stored = await db.scans.find_one({"_id": SCAN_ID})
    assert stored["status"] == SCAN_STATUS_COMPLETED_WITH_ERRORS
    assert stored["failed_analyzers"] == ["grype"]
    assert stored["latest_run"]["status"] == SCAN_STATUS_COMPLETED_WITH_ERRORS


@pytest.mark.asyncio
async def test_relabel_skips_the_all_failed_shape():
    db = FakeDatabase()
    await db.scans.insert_one(_scan())
    await db.findings.insert_one(_finding("f1", "SCAN-ERROR-system", type_="system_warning"))

    counters = await relabel(db, batch_size=100, sleep_ms=0, execute=True)

    assert counters["skipped_all_failed"] == 1
    assert counters["relabelled"] == 0
    assert (await db.scans.find_one({"_id": SCAN_ID}))["status"] == SCAN_STATUS_COMPLETED


@pytest.mark.asyncio
async def test_dedupe_finds_the_scan_by_id():
    db = FakeDatabase()
    await db.scans.insert_one(_scan(findings_count=2))
    for i in range(2):
        await db.findings.insert_one(_finding(f"a{i}", f"CVE-2024-{i}", component="pkg"))
        await db.findings.insert_one(_finding(f"b{i}", f"CVE-2024-{i}", component="pkg"))

    counters = await dedupe(db, min_retry_count=1, batch_size=100, sleep_ms=0, execute=True)

    assert counters["scans"] == 1
    assert counters["deleted"] == 2
    assert await db.findings.count_documents({"scan_id": SCAN_ID}) == 2
