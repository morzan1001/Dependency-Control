from typing import Optional

from pydantic import BaseModel, Field


class SystemSettings(BaseModel):
    # validation_alias="_id": accepts _id from MongoDB
    # serialization_alias="_id": model_dump(by_alias=True) outputs _id for MongoDB
    id: str = Field(default="current", validation_alias="_id", serialization_alias="_id")

    # General
    instance_name: str = "Dependency Control"
    dashboard_url: Optional[str] = None

    # Limits
    project_limit_per_user: int = 0  # 0 means unlimited

    # Security
    allow_public_registration: bool = False
    enforce_2fa: bool = False
    enforce_email_verification: bool = False

    # Email / SMTP
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_encryption: str = "starttls"  # starttls, ssl, none
    emails_from_email: str = "info@dependencycontrol.local"

    # Integrations
    github_token: Optional[str] = Field(
        None,
        description=(
            "Personal Access Token for GitHub API. "
            "Increases rate limits for GHSA lookups and maintainer checks."
        ),
    )
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
    oidc_issuer: Optional[str] = None  # e.g. https://gitlab.com
    oidc_authorization_endpoint: Optional[str] = None
    oidc_token_endpoint: Optional[str] = None
    oidc_userinfo_endpoint: Optional[str] = None
    oidc_scopes: str = "openid profile email"

    # GitLab Integration
    gitlab_integration_enabled: bool = False
    gitlab_url: str = "https://gitlab.com"
    gitlab_access_token: Optional[str] = Field(
        None,
        description=(
            "Personal or Group Access Token with 'api' scope. "
            "Must have at least 'Reporter' role in the projects to post comments."
        ),
    )
    gitlab_auto_create_projects: bool = False
    gitlab_sync_teams: bool = False
    gitlab_oidc_audience: Optional[str] = Field(
        None,
        description="Expected audience claim for GitLab OIDC tokens. If set, tokens must contain this audience.",
    )

    # Periodic Scanning Defaults
    rescan_mode: str = "project"  # "project" or "global"
    global_rescan_enabled: bool = False
    global_rescan_interval: int = 24  # Hours

    # Retention
    retention_mode: str = "project"  # "project" or "global"
    global_retention_days: int = 90  # 0 means keep forever

    class Config:
        populate_by_name = True
