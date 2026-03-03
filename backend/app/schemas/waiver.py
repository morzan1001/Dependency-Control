from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import WAIVER_STATUS_ACCEPTED_RISK, WAIVER_STATUSES
from app.models.types import PyObjectId

WAIVER_SCOPES = ("finding", "file", "rule")


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
    scope: Literal["finding", "file", "rule"] = Field(
        "finding",
        description="'finding' = exact match, 'file' = same rule in same file, 'rule' = same rule project-wide",
    )
    rule_id: Optional[str] = Field(
        None,
        description="Scanner rule ID (e.g. 'javascript_lang_insufficiently_random_values'). Auto-populated from finding_id.",
    )
    reason: str
    status: str = WAIVER_STATUS_ACCEPTED_RISK
    expiration_date: Optional[datetime] = None

    @field_validator("package_version", mode="before")
    @classmethod
    def normalize_package_version(cls, v: Optional[str]) -> Optional[str]:
        """Normalize placeholder values to None so waiver queries don't mismatch."""
        if v in ("Unknown", "UNKNOWN", "unknown", ""):
            return None
        return v

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v not in WAIVER_STATUSES:
            raise ValueError(f"Invalid status. Must be one of: {', '.join(WAIVER_STATUSES)}")
        return v


class WaiverUpdate(BaseModel):
    reason: Optional[str] = None
    expiration_date: Optional[datetime] = None
    status: Optional[str] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in WAIVER_STATUSES:
            raise ValueError(f"Invalid status. Must be one of: {', '.join(WAIVER_STATUSES)}")
        return v


class WaiverResponse(WaiverCreate):
    # Use validation_alias so _id is accepted from MongoDB, but 'id' is used in JSON output
    # PyObjectId handles ObjectId to string conversion
    id: PyObjectId = Field(validation_alias="_id")
    created_by: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
