"""Email counts as configured by the mail sender's own precondition, on every path that asks."""

import pytest
from fastapi import BackgroundTasks, HTTPException

from app.api.v1.endpoints import auth
from app.api.v1.helpers.auth import send_verification_email
from app.api.v1.helpers.system import get_available_channels
from app.core.constants import NOTIFICATION_CHANNEL_EMAIL
from app.models.system import SystemSettings
from app.models.user import User

RELAY = SystemSettings(smtp_host="relay.internal", smtp_user=None, emails_from_email="dc@corp.com")
NO_SENDER = SystemSettings(smtp_host="relay.internal", smtp_user="dc", emails_from_email="")


def test_an_unauthenticated_relay_offers_the_email_channel():
    assert NOTIFICATION_CHANNEL_EMAIL in get_available_channels(RELAY)


def test_a_host_without_a_sender_address_offers_no_email_channel():
    assert NOTIFICATION_CHANNEL_EMAIL not in get_available_channels(NO_SENDER)


@pytest.mark.asyncio
async def test_no_verification_mail_is_queued_without_a_sender_address():
    background_tasks = BackgroundTasks()

    await send_verification_email(background_tasks, "a@corp.com", system_settings=NO_SENDER)

    assert background_tasks.tasks == []


@pytest.mark.asyncio
async def test_asking_for_a_verification_mail_without_a_sender_address_is_not_implemented():
    user = User(username="u", email="u@corp.com", is_verified=False)

    with pytest.raises(HTTPException) as exc_info:
        await auth.request_verification_email(BackgroundTasks(), user, NO_SENDER)

    assert exc_info.value.status_code == 501
