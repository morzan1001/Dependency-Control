import pytest
from fastapi import BackgroundTasks

from app.api.v1.helpers import auth as mails
from app.core.config import settings
from app.models.system import SystemSettings

_BRAND = "Acme Deps"
_TO = "alice@corp.example"

_SENDERS = {
    "verification": lambda bg, s: mails.send_verification_email(bg, _TO, s),
    "email_change": lambda bg, s: mails.send_email_change_email(bg, "u-1", _TO, s),
    "password_reset": lambda bg, s: mails.send_password_reset_email(bg, {"email": _TO, "hashed_password": "h"}, s),
    "invitation": lambda bg, s: mails.send_system_invitation_email(bg, _TO, "https://dc.example/accept", "admin", s),
    "member_added": lambda bg, s: mails.send_project_member_added_email(
        bg, _TO, "billing", "p-1", "admin", "viewer", s
    ),
    "password_changed": lambda bg, s: mails.send_password_changed_email(bg, _TO, "alice", s),
    "2fa_enabled": lambda bg, s: mails.send_2fa_enabled_email(bg, _TO, "alice", s),
    "2fa_disabled": lambda bg, s: mails.send_2fa_disabled_email(bg, _TO, "alice", s, by_admin=False),
}


def _queued(sender: str, instance_name: str) -> dict:
    background_tasks = BackgroundTasks()
    system_settings = SystemSettings(
        instance_name=instance_name, smtp_host="smtp.test", emails_from_email="dc@corp.example"
    )
    assert _SENDERS[sender](background_tasks, system_settings)
    (task,) = background_tasks.tasks
    return task.kwargs


@pytest.mark.parametrize("sender", _SENDERS)
def test_every_account_mail_is_branded_with_the_instance_name(sender):
    html = _queued(sender, _BRAND)["html_message"]

    assert _BRAND in html
    assert settings.PROJECT_NAME not in html


@pytest.mark.parametrize("sender", ["verification", "email_change", "password_reset", "invitation"])
def test_a_subject_naming_the_service_names_the_instance(sender):
    assert _queued(sender, _BRAND)["subject"].endswith(f" {_BRAND}")


@pytest.mark.parametrize("sender", ["invitation", "password_changed"])
def test_a_plain_text_body_naming_the_service_names_the_instance(sender):
    message = _queued(sender, _BRAND)["message"]

    assert _BRAND in message
    assert settings.PROJECT_NAME not in message


@pytest.mark.parametrize("instance_name", ["", "   "], ids=["empty", "blank"])
def test_a_blank_instance_name_falls_back_to_the_deployment_name(instance_name):
    mail = _queued("invitation", instance_name)

    assert mail["subject"] == f"Invitation to join {settings.PROJECT_NAME}"
    assert f"<h1>{settings.PROJECT_NAME}</h1>" in mail["html_message"]
