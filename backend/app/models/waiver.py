import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from app.core.constants import WAIVER_STATUS_ACCEPTED_RISK
from app.models.finding import FindingType
from app.models.types import PyObjectId


class Waiver(BaseModel):
    # Use validation_alias so _id is accepted from MongoDB, but 'id' is used in JSON output
    id: PyObjectId = Field(default_factory=lambda: str(uuid.uuid4()), validation_alias="_id")
    project_id: Optional[str] = None  # If None, applies globally (admin only)

    # Matching Criteria
    finding_id: Optional[str] = (
        None  # e.g. "CVE-2023-1234", "LIC-GPL-3.0", "EOL-python"
    )
    package_name: Optional[str] = None  # e.g. "requests"
    package_version: Optional[str] = None  # e.g. "2.26.0"
    finding_type: Optional[FindingType] = (
        None  # e.g. "vulnerability", "license", "malware", "eol"
    )
    vulnerability_id: Optional[str] = None  # e.g. "CVE-2021-23337"

    reason: str
    status: str = WAIVER_STATUS_ACCEPTED_RISK
    expiration_date: Optional[datetime] = None
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
