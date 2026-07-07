"""Tests for app.schemas.system.

Focus: SystemSettingsResponse must NOT echo stored secrets back to clients
(Finding: SystemSettingsResponse leaked every integration credential in
GET/PUT /system/settings responses). Instead it exposes ``*_configured``
booleans, mirroring the GitLab/GitHub instance ``token_configured`` convention.
"""

from fastapi.encoders import jsonable_encoder

from app.models.system import SystemSettings
from app.schemas.system import SystemSettingsResponse

# Every secret field that used to be echoed back, with a sentinel value.
SECRET_FIELDS = {
    "github_token": "ghp-SECRET",
    "smtp_password": "smtp-SECRET",
    "open_source_malware_api_key": "osm-SECRET",
    "slack_bot_token": "xoxb-SECRET",
    "slack_client_secret": "slack-cs-SECRET",
    "slack_refresh_token": "xoxr-SECRET",
    "oidc_client_secret": "oidc-cs-SECRET",
    "gitlab_access_token": "glpat-SECRET",
    "mattermost_bot_token": "mm-SECRET",
}


def _response_from_secrets():
    settings = SystemSettings(**SECRET_FIELDS)
    return SystemSettingsResponse.model_validate(settings)


def test_response_does_not_echo_secret_values():
    """No secret value may appear anywhere in the serialized response."""
    resp = _response_from_secrets()

    # Serialize the way FastAPI does for the response body.
    for serialized in (resp.model_dump(), jsonable_encoder(resp)):
        blob = str(serialized)
        for field, value in SECRET_FIELDS.items():
            assert field not in serialized, f"{field} leaked as a key in response"
            assert value not in blob, f"{field} value leaked in response body"


def test_response_exposes_configured_booleans_true_when_set():
    resp = _response_from_secrets()
    dumped = resp.model_dump()

    for field in SECRET_FIELDS:
        flag = f"{field}_configured"
        assert dumped.get(flag) is True, f"{flag} should be True when secret is set"


def test_response_configured_booleans_false_when_unset():
    resp = SystemSettingsResponse.model_validate(SystemSettings())
    dumped = resp.model_dump()

    for field in SECRET_FIELDS:
        flag = f"{field}_configured"
        assert flag in dumped, f"{flag} should always be present"
        assert dumped[flag] is False, f"{flag} should be False when secret is unset"


def test_response_still_exposes_non_secret_fields():
    """Non-sensitive config must still round-trip so the settings UI works."""
    settings = SystemSettings(
        instance_name="My Instance",
        smtp_host="mail.example.com",
        smtp_user="mailer",
        slack_client_id="client-123",
        gitlab_url="https://gitlab.example.com",
        oidc_enabled=True,
    )
    dumped = SystemSettingsResponse.model_validate(settings).model_dump()

    assert dumped["instance_name"] == "My Instance"
    assert dumped["smtp_host"] == "mail.example.com"
    assert dumped["smtp_user"] == "mailer"
    assert dumped["slack_client_id"] == "client-123"
    assert dumped["gitlab_url"] == "https://gitlab.example.com"
    assert dumped["oidc_enabled"] is True
