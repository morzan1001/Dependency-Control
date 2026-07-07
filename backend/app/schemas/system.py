from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, computed_field


class SystemSettingsBase(BaseModel):
    instance_name: Optional[str] = "Dependency Control"

    # Limits
    project_limit_per_user: int = 0  # 0 means unlimited

    allow_public_registration: bool = False
    enforce_2fa: bool = False
    enforce_email_verification: bool = False

    # Integrations
    github_token: Optional[str] = None

    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_encryption: str = "starttls"
    emails_from_email: Optional[str] = "info@dependencycontrol.local"
    emails_from_name: Optional[str] = "Dependency Control"

    open_source_malware_api_key: Optional[str] = None
    slack_bot_token: Optional[str] = None
    slack_client_id: Optional[str] = None
    slack_client_secret: Optional[str] = None
    slack_oauth_scopes: str = "channels:read,chat:write,chat:write.customize,files:write"
    slack_refresh_token: Optional[str] = None
    slack_token_expires_at: Optional[float] = None
    mattermost_bot_token: Optional[str] = None
    mattermost_url: Optional[str] = None

    # OIDC / SSO
    oidc_enabled: bool = False
    oidc_provider_name: str = "GitLab"
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None
    oidc_issuer: Optional[str] = None
    oidc_authorization_endpoint: Optional[str] = None
    oidc_token_endpoint: Optional[str] = None
    oidc_userinfo_endpoint: Optional[str] = None
    oidc_scopes: str = "openid profile email"

    # GitLab Integration
    gitlab_integration_enabled: bool = False
    gitlab_url: str = "https://gitlab.com"
    gitlab_access_token: Optional[str] = None
    gitlab_auto_create_projects: bool = False
    gitlab_sync_teams: bool = False
    gitlab_oidc_audience: Optional[str] = None

    # Default Analyzers for auto-created projects
    default_active_analyzers: List[str] = ["trivy", "osv", "license_compliance", "end_of_life"]

    # Retention
    retention_mode: str = "project"
    global_retention_days: int = 90
    global_retention_action: str = "delete"  # "delete", "archive", or "none"

    # Periodic Scanning
    rescan_mode: str = "project"  # "project" or "global"
    global_rescan_enabled: bool = False
    global_rescan_interval: int = 24  # Hours

    # Crypto policy enforcement: "project" (allow project overrides) or "global"
    # (enforce system policy for every project, ignoring overrides at scan time
    # and rejecting writes).
    crypto_policy_mode: str = "project"

    # Chat / AI Assistant — feature flag is deployment-time (settings.CHAT_ENABLED)
    chat_rate_limit_per_minute: int = 10
    chat_rate_limit_per_hour: int = 60
    chat_max_tool_rounds: int = 20


class SystemSettingsUpdate(SystemSettingsBase):
    pass


class SystemSettingsResponse(SystemSettingsBase):
    """Response schema for GET/PUT /system/settings.

    SECURITY: secret credentials are NEVER echoed back to the client. This
    mirrors the repo's own convention for integration tokens
    (GitLabInstance/GitHubInstance expose ``token_configured`` rather than the
    token itself). Each secret field below is redeclared with ``exclude=True``
    so its value can still be read from the stored model (to derive the
    ``*_configured`` flags) but is dropped from the serialized response. For
    every secret we instead expose a boolean ``<field>_configured`` so the UI
    can show whether a value is set without leaking the value.

    Updates treat omitted secrets as "keep existing": the update endpoint uses
    ``model_dump(exclude_unset=True)``, and since these fields are no longer
    returned they are absent from a round-tripped form payload and left
    untouched unless the admin explicitly enters a new value.
    """

    model_config = ConfigDict(from_attributes=True)

    # --- Secret fields: accepted from the stored model, excluded from output ---
    github_token: Optional[str] = Field(default=None, exclude=True)
    smtp_password: Optional[str] = Field(default=None, exclude=True)
    open_source_malware_api_key: Optional[str] = Field(default=None, exclude=True)
    slack_bot_token: Optional[str] = Field(default=None, exclude=True)
    slack_client_secret: Optional[str] = Field(default=None, exclude=True)
    slack_refresh_token: Optional[str] = Field(default=None, exclude=True)
    oidc_client_secret: Optional[str] = Field(default=None, exclude=True)
    gitlab_access_token: Optional[str] = Field(default=None, exclude=True)
    mattermost_bot_token: Optional[str] = Field(default=None, exclude=True)

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

    # Feature flags
    archive_enabled: bool = False

    # Limits
    project_limit_per_user: int = 0

    # Retention settings
    retention_mode: str = "project"
    global_retention_days: int = 90
    global_retention_action: str = "delete"

    # Rescan settings
    rescan_mode: str = "project"
    global_rescan_enabled: bool = False
    global_rescan_interval: int = 24

    # Available notification channels
    notifications: NotificationChannels = NotificationChannels()

    # Slack OAuth (non-sensitive, needed for "Add to Slack" button)
    slack_client_id: Optional[str] = None
    slack_oauth_scopes: Optional[str] = None

    # Chat / AI Assistant feature flag
    chat_enabled: bool = False
