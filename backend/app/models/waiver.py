from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
import uuid
from app.models.finding import FindingType

class Waiver(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    project_id: Optional[str] = None # If None, applies globally (admin only)
    
    # Matching Criteria
    finding_id: Optional[str] = None # e.g. "CVE-2023-1234", "LIC-GPL-3.0", "EOL-python"
    package_name: Optional[str] = None # e.g. "requests"
    package_version: Optional[str] = None # e.g. "2.26.0"
    finding_type: Optional[FindingType] = None # e.g. "vulnerability", "license", "malware", "eol"
    
    reason: str
    status: str = "accepted_risk" # accepted_risk, false_positive
    expiration_date: Optional[datetime] = None
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
