import uuid
from datetime import datetime
from typing import Optional

from pydantic import ConfigDict, Field

from app.core.constants import WAIVER_STATUS_ACCEPTED_RISK
from app.models.base import CreatedAtModel
from app.models.finding import FindingType
from app.models.types import PyObjectId


class Waiver(CreatedAtModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    project_id: Optional[str] = None  # If None, applies globally (admin only)

    # Matching Criteria
    finding_id: Optional[str] = None  # e.g. "CVE-2023-1234", "LIC-GPL-3.0", "EOL-python"
    package_name: Optional[str] = None  # e.g. "requests"
    package_version: Optional[str] = None  # e.g. "2.26.0"
    finding_type: Optional[FindingType] = None  # e.g. "vulnerability", "license", "malware", "eol"
    vulnerability_id: Optional[str] = None  # e.g. "CVE-2021-23337"
    scope: str = "finding"  # "finding" = exact, "file" = same rule+file, "rule" = same rule project-wide
    rule_id: Optional[str] = None  # e.g. "javascript_lang_insufficiently_random_values"

    reason: str
    status: str = WAIVER_STATUS_ACCEPTED_RISK
    expiration_date: Optional[datetime] = None
    created_by: str

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)
