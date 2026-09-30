"""Two scans holding the same findings report no change, whatever order each side's rows come back in."""

import pytest

from app.services.analytics.findings_delta import compare_findings

_PROJECT = "p1"
_FROM_SCAN = "scan-from"
_TO_SCAN = "scan-to"
_POPULATION = 6


def _vuln(scan_id: str, index: int) -> dict:
    return {
        "_id": f"{scan_id}-{index}",
        "project_id": _PROJECT,
        "scan_id": scan_id,
        "finding_id": f"f-{index}",
        "type": "vulnerability",
        "severity": "HIGH",
        "component": f"lib-{index}",
        "version": "1.0.0",
        "description": f"finding {index}",
        "details": {"vulnerabilities": [{"id": f"CVE-2026-{index:05d}"}]},
    }


@pytest.mark.asyncio
async def test_identical_scans_in_opposite_natural_order_report_no_change(db):
    """A second scan's analyzers emitting in a different order reverse the collection's natural order."""
    findings = db["findings"]
    for scan_id, indices in ((_FROM_SCAN, range(_POPULATION)), (_TO_SCAN, reversed(range(_POPULATION)))):
        for index in indices:
            doc = _vuln(scan_id, index)
            findings._docs[doc["_id"]] = doc

    resp = await compare_findings(
        db, project_id=_PROJECT, from_scan=_FROM_SCAN, to_scan=_TO_SCAN, severity=None, finding_type=None
    )

    assert (resp.totals.added, resp.totals.removed, resp.totals.unchanged) == (0, 0, _POPULATION)
