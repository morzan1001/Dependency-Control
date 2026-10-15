from pydantic import BaseModel, ConfigDict, Field

from app.core.constants import (
    DEFAULT_ACTIVE_ANALYZERS,
    DEFAULT_RETENTION_DAYS,
    RETENTION_ACTION_DELETE,
    SETTINGS_MODE_PROJECT,
)


class SystemSettingsFields(BaseModel):
    instance_name: str = "Dependency Control"

    project_limit_per_user: int = 0  # 0 means unlimited

    allow_public_registration: bool = False
    enforce_2fa: bool = False
    enforce_email_verification: bool = False

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_encryption: str = "starttls"  # starttls, ssl, none
    emails_from_email: str = "info@dependencycontrol.local"
    emails_from_name: str | None = "Dependency Control"

    github_token: str | None = Field(
        None,
        description=(
            "Personal Access Token for GitHub API. Increases rate limits for GHSA lookups and maintainer checks."
        ),
    )
    open_source_malware_api_key: str | None = None
    slack_bot_token: str | None = None
    slack_client_id: str | None = None
    slack_client_secret: str | None = None
    slack_oauth_scopes: str = "channels:read,chat:write,chat:write.customize,files:write"
    slack_refresh_token: str | None = None
    slack_token_expires_at: float | None = None
    mattermost_bot_token: str | None = None
    mattermost_url: str | None = None

    oidc_enabled: bool = False
    oidc_provider_name: str = "GitLab"
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_issuer: str | None = None
    oidc_authorization_endpoint: str | None = None
    oidc_token_endpoint: str | None = None
    oidc_userinfo_endpoint: str | None = None
    oidc_scopes: str = "openid profile email"
    oidc_auto_provision: bool = True

    rescan_mode: str = SETTINGS_MODE_PROJECT
    global_rescan_enabled: bool = False
    global_rescan_interval: int = 24  # Hours

    # For auto-created projects.
    default_active_analyzers: list[str] = Field(default_factory=lambda: list(DEFAULT_ACTIVE_ANALYZERS))

    retention_mode: str = SETTINGS_MODE_PROJECT
    global_retention_days: int = DEFAULT_RETENTION_DAYS  # 0 means keep forever
    global_retention_action: str = RETENTION_ACTION_DELETE

    # "global" ignores project overrides and refuses new ones, but keeps them for a switch back to "project".
    crypto_policy_mode: str = SETTINGS_MODE_PROJECT

    # The chat's on/off switch is deployment-time: settings.CHAT_ENABLED.
    chat_rate_limit_per_minute: int = 10
    chat_rate_limit_per_hour: int = 60
    chat_max_tool_rounds: int = 20


class SystemSettings(SystemSettingsFields):
    id: str = Field(default="current", validation_alias="_id", serialization_alias="_id")

    model_config = ConfigDict(populate_by_name=True)

    @property
    def email_configured(self) -> bool:
        """What EmailProvider.send needs; credentials are optional for an unauthenticated relay."""
        return bool(self.smtp_host and self.emails_from_email)
