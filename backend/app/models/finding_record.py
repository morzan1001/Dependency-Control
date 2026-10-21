import uuid

from pydantic import ConfigDict, Field

from app.models.base import CreatedAtModel
from app.models.finding import FINDING_ID_DESCRIPTION, Finding
from app.models.types import PyObjectId


class FindingRecord(Finding, CreatedAtModel):
    mongo_id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    project_id: str = Field(..., description="Reference to the project")
    scan_id: str = Field(..., description="Reference to the scan")

    finding_id: str = Field(..., description=FINDING_ID_DESCRIPTION)

    model_config = ConfigDict(populate_by_name=True)
