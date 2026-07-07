"""Tests for WaiverCreate schema validation of finding_type.

Regression: WaiverCreate.finding_type used to be a plain ``Optional[str]``
with no validation, while the persisted ``Waiver`` model requires the
``FindingType`` enum. Invalid values (e.g. "vuln" instead of
"vulnerability") passed request validation and then blew up inside the
create handler when constructing ``Waiver(**waiver_in.model_dump())``,
surfacing as a 500 instead of a descriptive 422.
"""

import pytest
from pydantic import ValidationError

from app.models.finding import FindingType
from app.schemas.waiver import WaiverCreate


def test_invalid_finding_type_rejected_at_schema_level():
    """A bogus finding_type must raise ValidationError (-> 422), not slip through."""
    with pytest.raises(ValidationError):
        WaiverCreate(reason="typo", finding_type="vuln")


def test_valid_finding_type_string_accepted_and_coerced():
    waiver = WaiverCreate(reason="ok", finding_type="vulnerability")
    assert waiver.finding_type == FindingType.VULNERABILITY


def test_finding_type_optional_defaults_to_none():
    waiver = WaiverCreate(reason="ok")
    assert waiver.finding_type is None


def test_model_dump_keeps_finding_type_value():
    """model_dump() output must remain constructible into the Waiver model."""
    from app.models.waiver import Waiver

    waiver_in = WaiverCreate(reason="ok", finding_type="license")
    waiver = Waiver(**waiver_in.model_dump(), created_by="tester")
    assert waiver.finding_type == FindingType.LICENSE
