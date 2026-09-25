"""Tests for the MIME structure of outgoing notification emails."""

from unittest.mock import AsyncMock

import pytest

from app.models.system import SystemSettings
from app.services.notifications.email_provider import EmailProvider


def test_a_mail_without_logo_is_a_flat_alternative_of_plain_and_html():
    msg = EmailProvider()._build_message("from@x", "to@x", "Subj", "plain body", "<p>html</p>", has_logo=False)

    assert msg.get_content_subtype() == "alternative"
    assert [part.get_content_type() for part in msg.get_payload()] == ["text/plain", "text/html"]
    assert (msg["From"], msg["To"], msg["Subject"]) == ("from@x", "to@x", "Subj")


def test_a_mail_with_logo_nests_the_alternative_inside_a_related_part():
    msg = EmailProvider()._build_message("from@x", "to@x", "Subj", "plain body", None, has_logo=True)

    assert msg.get_content_subtype() == "related"
    (alternative,) = msg.get_payload()
    assert alternative.get_content_subtype() == "alternative"
    assert [part.get_content_type() for part in alternative.get_payload()] == ["text/plain"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("logo_exists", "expected_parts"), [(True, ["multipart/alternative", "image/png"]), (False, ["text/plain"])]
)
async def test_send_attaches_the_logo_only_when_the_file_exists(tmp_path, logo_exists, expected_parts):
    logo = tmp_path / "logo.png"
    if logo_exists:
        logo.write_bytes(b"\x89PNG\r\n\x1a\n")
    provider = EmailProvider()
    provider._send_async = AsyncMock()
    settings = SystemSettings(smtp_host="smtp.test", emails_from_email="dc@test")

    assert await provider.send("to@x", "Subj", "Body", logo_path=str(logo), system_settings=settings) is True

    sent = provider._send_async.await_args.args[-1]
    assert [part.get_content_type() for part in sent.get_payload()] == expected_parts
