"""Tests that ScanFindingItem serializes waiver_lapsed and lapsed_waiver_id fields."""

from app.schemas.project import ScanFindingItem


_MINIMAL = dict(
    id="CVE-2021-44228",
    finding_id="CVE-2021-44228",
    type="vulnerability",
    severity="HIGH",
    component="log4j",
    description="Remote code execution",
    project_id="p1",
    scan_id="s1",
)


def test_scan_finding_item_serializes_lapsed_fields():
    item = ScanFindingItem(**_MINIMAL, waiver_lapsed=True, lapsed_waiver_id="w1")
    dumped = item.model_dump()
    assert dumped["waiver_lapsed"] is True
    assert dumped["lapsed_waiver_id"] == "w1"


def test_scan_finding_item_lapsed_fields_default_to_falsy():
    item = ScanFindingItem(**_MINIMAL)
    dumped = item.model_dump()
    assert dumped["waiver_lapsed"] is False
    assert dumped["lapsed_waiver_id"] is None
