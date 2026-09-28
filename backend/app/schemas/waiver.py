from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from app.core.constants import WAIVER_SCOPE_FINDING, WAIVER_STATUS_ACCEPTED_RISK, WaiverScope, WaiverStatus
from app.models.finding import FindingType
from app.models.types import PyObjectId
from app.models.waiver import is_waiver_active
from app.schemas._not_null import reject_null


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
        WAIVER_SCOPE_FINDING,
        description="'finding' = exact match, 'file' = same rule in same file, 'rule' = same rule project-wide",
    )
    rule_id: str | None = Field(
        None,
        description="Scanner rule ID (e.g. 'javascript_lang_insufficiently_random_values'). Auto-populated from finding_id.",
    )
    reason: str
    status: WaiverStatus = WAIVER_STATUS_ACCEPTED_RISK
    expiration_date: datetime | None = None

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

    _not_null = field_validator("reason", "status")(reject_null)


class WaiverResponse(BaseModel):
    """Lenient on purpose: a stored legacy status or scope must not fail a whole listing."""

    id: PyObjectId = Field(validation_alias="_id")
    project_id: str | None = None
    finding_id: str | None = None
    vulnerability_id: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    finding_type: FindingType | None = None
    scope: str = "finding"
    rule_id: str | None = None
    reason: str
    status: str
    expiration_date: datetime | None = None
    created_by: str
    created_at: datetime
    last_eval_scan_id: str | None = None
    last_match_count: int | None = None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_active(self) -> bool:
        return is_waiver_active(self.expiration_date)
