"""WaiverCreate.finding_type validates against the FindingType enum."""

from typing import get_args

import pytest
from pydantic import ValidationError

from app.core.constants import WaiverStatus
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
    with pytest.raises(ValidationError):
        WaiverCreate(reason="ok", status="wont_fix")


def test_every_known_status_is_accepted():
    for status in get_args(WaiverStatus):
        assert WaiverCreate(reason="ok", status=status).status == status


def test_model_dump_keeps_finding_type_value():
    from app.models.waiver import Waiver

    waiver_in = WaiverCreate(reason="ok", finding_type="license")
    waiver = Waiver(**waiver_in.model_dump(), created_by="tester")
    assert waiver.finding_type == FindingType.LICENSE


def test_an_update_refuses_a_status_outside_the_vocabulary_and_nulls_the_stored_waiver_requires():
    from app.schemas.waiver import WaiverUpdate

    for rejected in ({"status": "wont_fix"}, {"status": None}, {"reason": None}):
        with pytest.raises(ValidationError):
            WaiverUpdate(**rejected)


def test_an_update_can_still_clear_the_expiry():
    from app.schemas.waiver import WaiverUpdate

    assert WaiverUpdate(expiration_date=None).model_dump(exclude_unset=True) == {"expiration_date": None}
