from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class WaiverCreate(BaseModel):
    project_id: Optional[str] = None
    finding_id: Optional[str] = Field(
        None,
        description="The ID of the finding (e.g. aggregated ID like 'lodash:4.17.0')",
    )
    vulnerability_id: Optional[str] = Field(
        None,
        description="Specific vulnerability ID (e.g. CVE-2021-23337) for granular waivers within aggregated findings",
    )
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
