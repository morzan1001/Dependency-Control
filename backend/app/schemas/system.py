from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, computed_field

from app.core.constants import (
    AUTH_PROVIDER_LOCAL,
    DEFAULT_ACTIVE_ANALYZERS,
    DEFAULT_RETENTION_DAYS,
    MAX_RETENTION_DAYS,
    RETENTION_ACTION_DELETE,
    SETTINGS_MODE_PROJECT,
    RetentionAction,
    SettingsMode,
)
from app.models.system import SystemSettingsFields


def _not_the_local_provider(name: str) -> str:
    # OIDC users are stored under this name, so "local" would make them local accounts.
    if name.lower() == AUTH_PROVIDER_LOCAL:
        raise ValueError(f"The OIDC provider name must not be {AUTH_PROVIDER_LOCAL!r}")
    return name


OidcProviderName = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1), AfterValidator(_not_the_local_provider)
]


class SystemSettingsUpdate(SystemSettingsFields):
    # Narrowed only on the way in: the response shares these fields and must stay able to render a
    # setting that predates this constraint.
    oidc_provider_name: OidcProviderName = "GitLab"
    smtp_encryption: Literal["starttls", "ssl", "none"] = "starttls"
    retention_mode: SettingsMode = SETTINGS_MODE_PROJECT
    global_retention_days: int = Field(DEFAULT_RETENTION_DAYS, ge=0, le=MAX_RETENTION_DAYS)
    global_retention_action: RetentionAction = RETENTION_ACTION_DELETE
    rescan_mode: SettingsMode = SETTINGS_MODE_PROJECT
    crypto_policy_mode: SettingsMode = SETTINGS_MODE_PROJECT
    chat_rate_limit_per_minute: int = Field(10, ge=1)
    chat_rate_limit_per_hour: int = Field(60, ge=1)
    chat_max_tool_rounds: int = Field(20, ge=1, le=50)


class SystemSettingsResponse(SystemSettingsFields):
    """Response schema for GET/PUT /system/settings.

    Secret credentials are never echoed back: each is redeclared with
    ``exclude=True`` (still readable to derive the ``*_configured`` flags) and
    exposed only as a boolean ``<field>_configured``.
    """

    model_config = ConfigDict(from_attributes=True)

    # Secret fields: accepted from the stored model, excluded from output.
    github_token: str | None = Field(default=None, exclude=True)
    smtp_password: str | None = Field(default=None, exclude=True)
    open_source_malware_api_key: str | None = Field(default=None, exclude=True)
    slack_bot_token: str | None = Field(default=None, exclude=True)
    slack_client_secret: str | None = Field(default=None, exclude=True)
    slack_refresh_token: str | None = Field(default=None, exclude=True)
    oidc_client_secret: str | None = Field(default=None, exclude=True)
    gitlab_access_token: str | None = Field(default=None, exclude=True)
    mattermost_bot_token: str | None = Field(default=None, exclude=True)

    @computed_field
    @property
    def github_token_configured(self) -> bool:
        return bool(self.github_token)

    @computed_field
    @property
    def smtp_password_configured(self) -> bool:
        return bool(self.smtp_password)

    @computed_field
    @property
    def open_source_malware_api_key_configured(self) -> bool:
        return bool(self.open_source_malware_api_key)

    @computed_field
    @property
    def slack_bot_token_configured(self) -> bool:
        return bool(self.slack_bot_token)

    @computed_field
    @property
    def slack_client_secret_configured(self) -> bool:
        return bool(self.slack_client_secret)

    @computed_field
    @property
    def slack_refresh_token_configured(self) -> bool:
        return bool(self.slack_refresh_token)

    @computed_field
    @property
    def oidc_client_secret_configured(self) -> bool:
        return bool(self.oidc_client_secret)

    @computed_field
    @property
    def gitlab_access_token_configured(self) -> bool:
        return bool(self.gitlab_access_token)

    @computed_field
    @property
    def mattermost_bot_token_configured(self) -> bool:
        return bool(self.mattermost_bot_token)


class NotificationChannels(BaseModel):
    """Available notification channels based on system configuration."""

    email: bool = False
    slack: bool = False
    mattermost: bool = False


class PublicConfig(BaseModel):
    """
    Public configuration available without authentication.
    Used by login/registration pages to determine available options.
    """

    allow_public_registration: bool = False
    enforce_2fa: bool = False
    enforce_email_verification: bool = False
    oidc_enabled: bool = False
    oidc_provider_name: str = "GitLab"


class AppConfig(BaseModel):
    """
    Lightweight configuration for authenticated users.
    Contains only non-sensitive data needed by various frontend components.
    """

    archive_enabled: bool
    project_limit_per_user: int
    retention_mode: str
    global_retention_days: int
    global_retention_action: str
    rescan_mode: str
    global_rescan_enabled: bool
    global_rescan_interval: int
    notifications: NotificationChannels
    # Slack OAuth (non-sensitive, needed for "Add to Slack" button)
    slack_client_id: str | None
    slack_oauth_scopes: str | None
    chat_enabled: bool
    # What a project created without an explicit choice runs; the create dialog starts from it.
    default_project_analyzers: list[str] = Field(default_factory=lambda: list(DEFAULT_ACTIVE_ANALYZERS))
