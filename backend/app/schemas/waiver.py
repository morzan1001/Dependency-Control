from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import WAIVER_STATUS_ACCEPTED_RISK, WaiverScope, WaiverStatus
from app.models.finding import FindingType
from app.models.types import PyObjectId


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
    scope: WaiverScope = Field(
        "finding",
        description="'finding' = exact match, 'file' = same rule in same file, 'rule' = same rule project-wide",
    )
    rule_id: str | None = Field(
        None,
        description="Scanner rule ID (e.g. 'javascript_lang_insufficiently_random_values'). Auto-populated from finding_id.",
    )
    reason: str
    status: WaiverStatus = WAIVER_STATUS_ACCEPTED_RISK
    expiration_date: datetime | None = None

    @field_validator("package_name", mode="before")
    @classmethod
    def drop_package_placeholder(cls, v: str | None) -> str | None:
        """The waiver form sends "Unknown" for a finding without a package; lowercase "unknown" is a real name."""
        return None if v == "Unknown" else v

    @field_validator("package_version", mode="before")
    @classmethod
    def normalize_package_version(cls, v: str | None) -> str | None:
        """Normalize placeholder values to None so waiver queries don't mismatch."""
        if v in ("Unknown", "UNKNOWN", "unknown", ""):
            return None
        return v


class WaiverUpdate(BaseModel):
    reason: str | None = None
    expiration_date: datetime | None = None
    status: WaiverStatus | None = None

    @field_validator("reason", "status")
    @classmethod
    def reject_null(cls, v: str | None) -> str:
        """Left out keeps the stored value; an explicit null would store a waiver no reader can load."""
        if v is None:
            raise ValueError("may be omitted but not null")
        return v


class WaiverResponse(WaiverCreate):
    id: PyObjectId = Field(validation_alias="_id")
    created_by: str
    created_at: datetime
    last_eval_scan_id: str | None = None
    last_match_count: int | None = None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
