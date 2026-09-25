"""Tests for the MIME structure of outgoing notification emails."""

from app.services.notifications.email_provider import EmailProvider


def test_a_mail_without_logo_is_a_flat_alternative_of_plain_and_html():
    msg = EmailProvider()._build_message("from@x", "to@x", "Subj", "plain body", "<p>html</p>", None)

    assert msg.get_content_subtype() == "alternative"
    assert [part.get_content_type() for part in msg.get_payload()] == ["text/plain", "text/html"]
    assert (msg["From"], msg["To"], msg["Subject"]) == ("from@x", "to@x", "Subj")


def test_a_mail_with_logo_nests_the_alternative_inside_a_related_part(tmp_path):
    logo = tmp_path / "logo.png"
    logo.write_bytes(b"png")

    msg = EmailProvider()._build_message("from@x", "to@x", "Subj", "plain body", None, str(logo))

    assert msg.get_content_subtype() == "related"
    (alternative,) = msg.get_payload()
    assert alternative.get_content_subtype() == "alternative"
    assert [part.get_content_type() for part in alternative.get_payload()] == ["text/plain"]
