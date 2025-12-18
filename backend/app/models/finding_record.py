from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import uuid
from app.models.finding import Finding, Severity, FindingType

class FindingRecord(Finding):
    """
    Represents a finding stored in the database, linked to a specific scan.
    Inherits from the base Finding model.
    """
    # We override id to be the database _id, but we also want to keep the finding's logical id (e.g. CVE-2021-44228)
    # So we map the logical id to 'finding_id' and let MongoDB handle _id
    
    mongo_id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    project_id: str = Field(..., description="Reference to the project")
    scan_id: str = Field(..., description="Reference to the scan")
    
    # The logical ID from the analyzer (e.g. CVE-xxx)
    finding_id: str = Field(..., description="Logical ID of the finding (e.g. CVE-2021-44228)")
    
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        populate_by_name = True
