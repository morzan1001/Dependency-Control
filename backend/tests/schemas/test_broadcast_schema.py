import pytest
from pydantic import ValidationError

from app.core.constants import NOTIFICATION_CHANNELS
from app.schemas.notification import BroadcastRequest

_VALID = {"target_type": "global", "subject": "s", "message": "m"}


def test_an_audience_outside_the_vocabulary_is_refused():
    with pytest.raises(ValidationError):
        BroadcastRequest(**{**_VALID, "target_type": "bogus"})


@pytest.mark.parametrize("audience", ["global", "teams", "advisory"])
def test_every_audience_is_accepted(audience):
    assert BroadcastRequest(**{**_VALID, "target_type": audience}).target_type == audience


def test_a_channel_no_provider_delivers_on_is_refused():
    with pytest.raises(ValidationError):
        BroadcastRequest(**{**_VALID, "channels": ["email", "sms"]})


def test_every_notification_channel_is_accepted():
    assert BroadcastRequest(**{**_VALID, "channels": NOTIFICATION_CHANNELS}).channels == NOTIFICATION_CHANNELS
