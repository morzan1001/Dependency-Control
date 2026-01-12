from typing import Optional

from pydantic import BaseModel


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

    open_source_malware_api_key: Optional[str] = None
    slack_bot_token: Optional[str] = None
    slack_client_id: Optional[str] = None
    slack_client_secret: Optional[str] = None
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

    # Retention
    retention_mode: str = "project"
    global_retention_days: int = 90

    # Periodic Scanning
    rescan_mode: str = "project"  # "project" or "global"
    global_rescan_enabled: bool = False
    global_rescan_interval: int = 24  # Hours


class SystemSettingsUpdate(SystemSettingsBase):
    pass


class SystemSettingsResponse(SystemSettingsBase):
    pass


class NotificationChannels(BaseModel):
    """Available notification channels based on system configuration."""

    email: bool = False
    slack: bool = False
    mattermost: bool = False


class AppConfig(BaseModel):
    """
    Lightweight configuration for authenticated users.
    Contains only non-sensitive data needed by various frontend components.
    """

    # Limits
    project_limit_per_user: int = 0

    # Retention settings
    retention_mode: str = "project"
    global_retention_days: int = 90

    # Rescan settings
    rescan_mode: str = "project"
    global_rescan_enabled: bool = False
    global_rescan_interval: int = 24

    # Integration status (only whether enabled, no secrets)
    gitlab_integration_enabled: bool = False
    gitlab_token_configured: bool = False

    # Available notification channels
    notifications: NotificationChannels = NotificationChannels()
