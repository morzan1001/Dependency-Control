from pydantic import BaseModel, Field
from typing import Optional

class SystemSettings(BaseModel):
    id: str = Field(default="current", alias="_id")
    
    # General
    instance_name: str = "Dependency Control"
    
    # Security
    allow_public_registration: bool = False
    enforce_2fa: bool = False
    enforce_email_verification: bool = False
    
    # Email / SMTP
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    emails_from_email: str = "info@dependencycontrol.local"
    
    # Integrations
    open_source_malware_api_key: Optional[str] = None
    slack_bot_token: Optional[str] = None
    mattermost_bot_token: Optional[str] = None
    mattermost_url: Optional[str] = None

    # OIDC / SSO
    oidc_enabled: bool = False
    oidc_provider_name: str = "GitLab"
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None
    oidc_issuer: Optional[str] = None # e.g. https://gitlab.com
    oidc_authorization_endpoint: Optional[str] = None
    oidc_token_endpoint: Optional[str] = None
    oidc_userinfo_endpoint: Optional[str] = None
    oidc_scopes: str = "openid profile email"

    class Config:
        populate_by_name = True
