from pydantic import BaseModel, ConfigDict, Field


class SystemSettings(BaseModel):
    id: str = Field(default="current", validation_alias="_id", serialization_alias="_id")

    # General
    instance_name: str = "Dependency Control"

    # Limits
    project_limit_per_user: int = 0  # 0 means unlimited

    # Security
    allow_public_registration: bool = False
    enforce_2fa: bool = False
    enforce_email_verification: bool = False

    # Email / SMTP
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_encryption: str = "starttls"  # starttls, ssl, none
    emails_from_email: str = "info@dependencycontrol.local"
    emails_from_name: str | None = "Dependency Control"

    # Integrations
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

    # OIDC / SSO
    oidc_enabled: bool = False
    oidc_provider_name: str = "GitLab"
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_issuer: str | None = None  # e.g. https://gitlab.com
    oidc_authorization_endpoint: str | None = None
    oidc_token_endpoint: str | None = None
    oidc_userinfo_endpoint: str | None = None
    oidc_scopes: str = "openid profile email"

    # GitLab Integration
    gitlab_integration_enabled: bool = False
    gitlab_url: str = "https://gitlab.com"
    gitlab_access_token: str | None = Field(
        None,
        description=(
            "Personal or Group Access Token with 'api' scope. "
            "Must have at least 'Reporter' role in the projects to post comments."
        ),
    )
    gitlab_auto_create_projects: bool = False
    gitlab_sync_teams: bool = False
    gitlab_oidc_audience: str | None = Field(
        None,
        description="Expected audience claim for GitLab OIDC tokens. If set, tokens must contain this audience.",
    )

    # Periodic Scanning Defaults
    rescan_mode: str = "project"  # "project" or "global"
    global_rescan_enabled: bool = False
    global_rescan_interval: int = 24  # Hours

    # Default Analyzers for auto-created projects
    default_active_analyzers: list[str] = ["trivy", "osv", "license_compliance", "end_of_life"]

    # Retention
    retention_mode: str = "project"  # "project" or "global"
    global_retention_days: int = 90  # 0 means keep forever
    global_retention_action: str = "delete"  # "delete", "archive", or "none"

    # Crypto policy enforcement
    # "project": each project may override the system rules.
    # "global": the system policy is enforced and project overrides are ignored
    # at resolve-time and rejected on write. Existing override docs are preserved
    # so they re-apply if the mode is switched back to "project".
    crypto_policy_mode: str = "project"

    # Chat / AI Assistant — feature flag is deployment-time (settings.CHAT_ENABLED)
    chat_rate_limit_per_minute: int = 10
    chat_rate_limit_per_hour: int = 60
    chat_max_tool_rounds: int = 20

    model_config = ConfigDict(populate_by_name=True)
