from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import WAIVER_STATUS_ACCEPTED_RISK, WAIVER_STATUSES
from app.models.finding import FindingType
from app.models.types import PyObjectId

WAIVER_SCOPES = ("finding", "file", "rule")


class WaiverCreate(BaseModel):
    project_id: str | None = None
    finding_id: str | None = Field(
        None,
        description="The ID of the finding (e.g. aggregated ID like 'lodash:4.17.0')",
    )
    vulnerability_id: str | None = Field(
        None,
        description="Specific vulnerability ID (e.g. CVE-2021-23337) for granular waivers within aggregated findings",
    )
    package_name: str | None = None
    package_version: str | None = None
    finding_type: FindingType | None = None
    scope: Literal["finding", "file", "rule"] = Field(
        "finding",
        description="'finding' = exact match, 'file' = same rule in same file, 'rule' = same rule project-wide",
    )
    rule_id: str | None = Field(
        None,
        description="Scanner rule ID (e.g. 'javascript_lang_insufficiently_random_values'). Auto-populated from finding_id.",
    )
    reason: str
    status: str = WAIVER_STATUS_ACCEPTED_RISK
    expiration_date: datetime | None = None

    @field_validator("package_version", mode="before")
    @classmethod
    def normalize_package_version(cls, v: str | None) -> str | None:
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
    reason: str | None = None
    expiration_date: datetime | None = None
    status: str | None = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str | None) -> str | None:
        if v is not None and v not in WAIVER_STATUSES:
            raise ValueError(f"Invalid status. Must be one of: {', '.join(WAIVER_STATUSES)}")
        return v


class WaiverResponse(WaiverCreate):
    id: PyObjectId = Field(validation_alias="_id")
    created_by: str
    created_at: datetime
    last_eval_scan_id: str | None = None
    last_match_count: int | None = None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
