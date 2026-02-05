import uuid
from datetime import datetime, timezone

from pydantic import Field

from app.models.finding import Finding
from app.models.types import PyObjectId


class FindingRecord(Finding):
    """
    Represents a finding stored in the database, linked to a specific scan.
    Inherits from the base Finding model.
    """

    mongo_id: PyObjectId = Field(default_factory=lambda: str(uuid.uuid4()), validation_alias="_id")
    project_id: str = Field(..., description="Reference to the project")
    scan_id: str = Field(..., description="Reference to the scan")

    # The logical ID from the analyzer (e.g. CVE-xxx)
    finding_id: str = Field(
        ..., description="Logical ID of the finding (e.g. CVE-2021-44228)"
    )

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        populate_by_name = True
