"""WaiverCreate.finding_type validates against the FindingType enum."""

import pytest
from pydantic import ValidationError

from app.core.constants import WAIVER_STATUSES
from app.models.finding import FindingType
from app.schemas.waiver import WaiverCreate


def test_invalid_finding_type_rejected_at_schema_level():
    with pytest.raises(ValidationError):
        WaiverCreate(reason="typo", finding_type="vuln")


def test_valid_finding_type_string_accepted_and_coerced():
    waiver = WaiverCreate(reason="ok", finding_type="vulnerability")
    assert waiver.finding_type == FindingType.VULNERABILITY


def test_finding_type_optional_defaults_to_none():
    waiver = WaiverCreate(reason="ok")
    assert waiver.finding_type is None


def test_unknown_status_rejected_at_schema_level():
    # An unlisted status survives to matching.py and is silently treated as accepted_risk.
    with pytest.raises(ValidationError, match="Invalid status"):
        WaiverCreate(reason="ok", status="wont_fix")


def test_every_known_status_is_accepted():
    for status in WAIVER_STATUSES:
        assert WaiverCreate(reason="ok", status=status).status == status


def test_model_dump_keeps_finding_type_value():
    from app.models.waiver import Waiver

    waiver_in = WaiverCreate(reason="ok", finding_type="license")
    waiver = Waiver(**waiver_in.model_dump(), created_by="tester")
    assert waiver.finding_type == FindingType.LICENSE
