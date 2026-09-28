"""A broadcast names one of the known types and audiences; anything else is refused where it enters."""

import pytest
from pydantic import ValidationError

from app.schemas.notification import BroadcastRequest

_VALID = {"type": "general", "target_type": "global", "subject": "s", "message": "m"}


@pytest.mark.parametrize("field", ["type", "target_type"])
def test_a_value_outside_the_vocabulary_is_refused(field):
    with pytest.raises(ValidationError):
        BroadcastRequest(**{**_VALID, field: "bogus"})


@pytest.mark.parametrize(
    ("kind", "audience"),
    [("general", "global"), ("general", "teams"), ("advisory", "advisory")],
)
def test_every_documented_combination_is_accepted(kind, audience):
    assert BroadcastRequest(**{**_VALID, "type": kind, "target_type": audience}).target_type == audience
