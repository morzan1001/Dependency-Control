import pytest
from pydantic import ValidationError

from app.schemas.scan_delta import (
    ComponentDeltaItem,
    CryptoDeltaItem,
    DeltaCategory,
    DeltaChange,
    FindingDeltaItem,
    ScanDeltaResponse,
    ScanDeltaTotals,
)


def test_response_findings_minimal_payload_validates():
    payload = {
        "from_scan_id": "s1",
        "to_scan_id": "s2",
        "project_id": "p1",
        "category": "findings",
        "totals": {"added": 1, "removed": 0, "unchanged": 0},
        "page": 1,
        "page_size": 50,
        "total_pages": 1,
        "items": [
            {
                "change": "added",
                "finding_id": "f-1",
                "finding_type": "vulnerability",
                "severity": "critical",
                "title": "CVE-1",
                "component": "log4j-core@2.17.1",
                "cve_id": "CVE-2025-1",
                "file_path": None,
                "first_seen": "2026-05-11T08:00:00Z",
            }
        ],
    }
    parsed = ScanDeltaResponse.model_validate(payload)
    assert parsed.totals.added == 1
    assert parsed.items[0].change == DeltaChange.ADDED
    assert isinstance(parsed.items[0], FindingDeltaItem)


def test_components_changed_total_present():
    totals = ScanDeltaTotals(added=0, removed=0, unchanged=0, changed=3)
    assert totals.changed == 3
    # Smoke check: the other item types are importable and constructable.
    comp = ComponentDeltaItem(change="version_changed", name="left-pad")
    crypto = CryptoDeltaItem(change="added", name="RSA-1024")
    assert comp.change == DeltaChange.VERSION_CHANGED
    assert crypto.change == DeltaChange.ADDED
    assert DeltaCategory.COMPONENTS.value == "components"


def test_invalid_category_rejected():
    with pytest.raises(ValidationError):
        ScanDeltaResponse.model_validate(
            {
                "from_scan_id": "s1",
                "to_scan_id": "s2",
                "project_id": "p1",
                "category": "nonsense",
                "totals": {"added": 0, "removed": 0, "unchanged": 0},
                "page": 1,
                "page_size": 50,
                "total_pages": 1,
                "items": [],
            }
        )
