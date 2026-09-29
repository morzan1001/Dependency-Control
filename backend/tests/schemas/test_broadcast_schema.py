"""A broadcast names one of the known audiences; anything else is refused where it enters."""

import pytest
from pydantic import ValidationError

from app.schemas.notification import BroadcastRequest

_VALID = {"target_type": "global", "subject": "s", "message": "m"}


def test_an_audience_outside_the_vocabulary_is_refused():
    with pytest.raises(ValidationError):
        BroadcastRequest(**{**_VALID, "target_type": "bogus"})


@pytest.mark.parametrize("audience", ["global", "teams", "advisory"])
def test_every_audience_is_accepted(audience):
    assert BroadcastRequest(**{**_VALID, "target_type": audience}).target_type == audience
