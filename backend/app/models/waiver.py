import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import ConfigDict, Field, computed_field

from app.core.constants import WAIVER_STATUS_ACCEPTED_RISK
from app.models.base import CreatedAtModel
from app.models.finding import FindingType
from app.models.match_signature import MatchSignature
from app.models.types import PyObjectId


def is_waiver_active(expiration_date: Optional[datetime], now: Optional[datetime] = None) -> bool:
    """Return True if the waiver is still active. Mirrors WaiverRepository._non_expired_filter; treats naive datetimes as UTC."""
    if expiration_date is None:
        return True
    reference = now or datetime.now(timezone.utc)
    if expiration_date.tzinfo is None:
        expiration_date = expiration_date.replace(tzinfo=timezone.utc)
    return expiration_date > reference


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
    match: Optional[MatchSignature] = None  # snapshot of the matched finding's signature
    last_eval_scan_id: Optional[str] = None  # scan the signature path last evaluated this waiver against
    last_match_count: Optional[int] = None   # #findings this waiver currently suppresses; None = not yet evaluated

    reason: str
    status: str = WAIVER_STATUS_ACCEPTED_RISK
    expiration_date: Optional[datetime] = None
    created_by: str

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_active(self) -> bool:
        return is_waiver_active(self.expiration_date)
