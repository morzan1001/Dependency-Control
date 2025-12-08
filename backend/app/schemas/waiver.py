from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class WaiverCreate(BaseModel):
    project_id: Optional[str] = None
    finding_id: Optional[str] = Field(None, description="The ID of the finding (e.g. CVE-..., LIC-...)")
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    finding_type: Optional[str] = None
    reason: str
    status: str = "accepted_risk"
    expiration_date: Optional[datetime] = None

class WaiverUpdate(BaseModel):
    reason: Optional[str] = None
    expiration_date: Optional[datetime] = None
    status: Optional[str] = None

class WaiverResponse(WaiverCreate):
    id: str
    created_by: str
    created_at: datetime
