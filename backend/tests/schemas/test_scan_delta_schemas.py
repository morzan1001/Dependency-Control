import pytest
from pydantic import ValidationError

from app.models.stats import ReachabilityStats
from app.schemas.scan_delta import (
    ComponentDeltaItem,
    CryptoDeltaItem,
    DeltaCategory,
    DeltaChange,
    FindingDeltaItem,
    ScanDeltaReachability,
    ScanDeltaResponse,
    ScanDeltaTotals,
)

_COVERABLE = 40
_ANALYSED = 37
_UNREPORTED = 0


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
    comp = ComponentDeltaItem(change="version_changed", name="left-pad")
    crypto = CryptoDeltaItem(change="added", name="RSA-1024")
    assert comp.change == DeltaChange.VERSION_CHANGED
    assert crypto.change == DeltaChange.ADDED
    assert DeltaCategory.COMPONENTS.value == "components"


def test_waived_excluded_defaults_to_zero_on_a_payload_that_omits_it():
    """Zero, not null: a category that excludes no findings still makes a countable statement."""
    parsed = ScanDeltaResponse.model_validate(
        {
            "from_scan_id": "s1",
            "to_scan_id": "s2",
            "project_id": "p1",
            "category": "components",
            "totals": {"added": 0, "removed": 0, "unchanged": 0},
            "items": [],
        }
    )
    assert parsed.from_waived_excluded == 0
    assert parsed.to_waived_excluded == 0


def test_reachability_carries_only_the_two_counts_the_delta_reports():
    parsed = ScanDeltaReachability.model_validate({"coverable_count": _COVERABLE, "analyzed_count": _ANALYSED})
    assert parsed.coverable_count == _COVERABLE
    assert parsed.analyzed_count == _ANALYSED


def test_reachability_rejects_the_rest_of_the_stats_document():
    """Feeding it a whole ReachabilityStats document must fail rather than keep two keys quietly,
    so the label can never claim to summarise fields it dropped."""
    with pytest.raises(ValidationError):
        ScanDeltaReachability.model_validate(ReachabilityStats().model_dump())


def test_reachability_defaults_an_unreported_count_to_zero():
    parsed = ScanDeltaReachability.model_validate({"coverable_count": _COVERABLE})
    assert parsed.analyzed_count == _UNREPORTED


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
