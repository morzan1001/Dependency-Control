from pydantic import BaseModel, EmailStr
from typing import Optional

class SystemSettingsBase(BaseModel):
    instance_name: Optional[str] = "Dependency Control"
    
    allow_public_registration: bool = False
    enforce_2fa: bool = False
    enforce_email_verification: bool = False
    
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    emails_from_email: Optional[str] = "info@dependencycontrol.local"
    
    open_source_malware_api_key: Optional[str] = None
    slack_bot_token: Optional[str] = None
    mattermost_bot_token: Optional[str] = None
    mattermost_url: Optional[str] = None

class SystemSettingsUpdate(SystemSettingsBase):
    pass

class SystemSettingsResponse(SystemSettingsBase):
    pass
