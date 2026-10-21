from datetime import datetime, timezone

from app.core import ensure_utc
from app.core.constants import WAIVER_SCOPE_FINDING, WAIVER_STATUS_ACCEPTED_RISK
from app.models.base import CreatedAtModel
from app.models.finding import FindingType
from app.models.match_signature import MatchSignature
from app.models.types import MongoDocument


def is_waiver_active(expiration_date: datetime | None, now: datetime | None = None) -> bool:
    """Mirrors non_expired_waiver_filter."""
    if expiration_date is None:
        return True
    return ensure_utc(expiration_date) > (now or datetime.now(timezone.utc))


class Waiver(MongoDocument, CreatedAtModel):
    project_id: str | None = None  # If None, applies globally (admin only)

    finding_id: str | None = None  # The analyzer-defined finding id, not a CVE; a CVE goes in vulnerability_id.
    package_name: str | None = None
    package_version: str | None = None
    finding_type: FindingType | None = None
    vulnerability_id: str | None = None
    scope: str = WAIVER_SCOPE_FINDING
    rule_id: str | None = None
    match: MatchSignature | None = None  # snapshot of the matched finding's signature
    last_eval_scan_id: str | None = None  # scan the signature path last evaluated this waiver against
    last_match_count: int | None = None  # #findings this waiver currently suppresses; None = not yet evaluated

    reason: str
    status: str = WAIVER_STATUS_ACCEPTED_RISK
    expiration_date: datetime | None = None
    created_by: str
