"""Tests for the MIME structure of outgoing notification emails."""

from aiosmtplib.email import flatten_message

from app.models.system import SystemSettings
from app.services.notifications.email_provider import EmailProvider
from app.services.notifications.templates import get_announcement_template, get_verification_email_template

SETTINGS = SystemSettings(smtp_host="smtp.test", emails_from_email="dc@corp.example", emails_from_name="DC")


def _build(subject="Subj", message="plain body", html_message=None):
    return EmailProvider()._build_message(SETTINGS, "to@x", subject, message, html_message)


def test_a_mail_without_logo_is_a_flat_alternative_of_plain_and_html():
    msg = _build(html_message="<p>html</p>")

    assert msg.get_content_subtype() == "alternative"
    assert [part.get_content_type() for part in msg.get_payload()] == ["text/plain", "text/html"]
    assert (msg["From"], msg["To"], msg["Subject"]) == ("DC <dc@corp.example>", "to@x", "Subj")


def test_a_templated_mail_nests_the_alternative_inside_a_related_part_with_the_logo():
    msg = _build(html_message=get_verification_email_template("https://dc.example/verify"))

    assert msg.get_content_subtype() == "related"
    alternative, logo = msg.get_payload()
    assert [part.get_content_type() for part in alternative.get_payload()] == ["text/plain", "text/html"]
    assert (logo.get_content_type(), logo["Content-ID"]) == ("image/png", "<logo>")


def test_html_that_does_not_reference_the_logo_carries_no_image():
    msg = _build(html_message="<div><h2>Security Advisory</h2></div>")

    assert "image/png" not in [part.get_content_type() for part in msg.walk()]


def test_a_text_only_mail_carries_no_image():
    msg = _build()

    assert [part.get_content_type() for part in msg.walk()] == ["multipart/alternative", "text/plain"]


def test_the_logo_is_sized_for_mail():
    msg = _build(html_message=get_verification_email_template("https://dc.example/verify"))

    assert len(flatten_message(msg)) < 64 * 1024


def test_every_message_carries_a_date_and_a_message_id_of_the_sender_domain():
    msg = _build()

    assert msg["Date"]
    assert msg["Message-ID"].endswith("@corp.example>")


def test_a_long_announcement_paragraph_goes_out_in_lines_a_relay_accepts():
    paragraph = "word " * 600
    msg = _build(message=paragraph, html_message=get_announcement_template(message=paragraph))

    assert max(len(line) for line in flatten_message(msg).splitlines()) <= 998


def test_a_line_break_in_the_subject_does_not_break_the_message():
    msg = _build(subject="Scan failed: evil\r\nBcc: victim@example.com")

    flattened = flatten_message(msg)

    assert b"\nBcc:" not in flattened
    assert msg["Subject"] == "Scan failed: evil Bcc: victim@example.com"
