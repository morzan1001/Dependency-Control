import pytest

from app.core.init_db import create_indexes
from app.repositories.findings import FindingRepository
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]

_SCAN_ID = "severity-scan"


def _finding(i: int, scan_id: str, **fields) -> dict:
    return {
        "_id": f"{scan_id}-{i}",
        "scan_id": scan_id,
        "finding_id": f"CVE-2026-{i:04d}",
        "type": "vulnerability",
        "severity": "HIGH" if i % 2 else "LOW",
        "waived": False,
        **fields,
    }


@pytest.mark.parametrize("finding_type", ["vulnerability", None])
async def test_the_severity_distribution_is_counted_off_the_index_alone(db, finding_type):
    await create_indexes(db)
    findings = [_finding(i, scan_id) for scan_id in (_SCAN_ID, "other-scan") for i in range(40)]
    findings[0].pop("waived")
    findings[1]["waived"] = True
    await db.findings.insert_many(findings)

    counts, entries = await profiled(db, FindingRepository(db).get_severity_distribution([_SCAN_ID], finding_type))

    assert counts == {"HIGH": 19, "LOW": 20}
    plans = [
        (e["planSummary"], e["docsExamined"])
        for e in entries
        if e["ns"].endswith(".findings") and "aggregate" in e["command"]
    ]
    assert plans == [("IXSCAN { scan_id: 1, severity: 1, type: 1, finding_id: 1, waived: 1 }", 0)]
