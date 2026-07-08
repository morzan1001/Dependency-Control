import hashlib
from typing import Any, Dict, Optional, TYPE_CHECKING

from app.models.finding import Finding, FindingType, Severity
from app.schemas.finding import SecretDetails
from app.services.normalizers.utils import build_finding_id

if TYPE_CHECKING:
    from app.services.aggregation import ResultAggregator


def _extract_file_path(finding: Dict[str, Any]) -> str:
    source_metadata = finding.get("SourceMetadata") or {}
    data = source_metadata.get("Data") or {}

    filesystem = data.get("Filesystem") or {}
    if filesystem.get("file"):
        return str(filesystem["file"])

    git = data.get("Git") or {}
    if git.get("file"):
        return str(git["file"])

    return "unknown"


def normalize_trufflehog(aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None) -> None:
    for finding in result.get("findings") or []:
        file_path = _extract_file_path(finding)
        # Prefer DetectorName; DetectorType is a numeric ordinal that loses the credential type.
        detector = finding.get("DetectorName") or finding.get("DetectorType") or "Generic Secret"

        # Hash the secret so the raw value never lands in the finding key.
        raw_secret = finding.get("Raw") or ""
        secret_hash = hashlib.md5(raw_secret.encode(), usedforsecurity=False).hexdigest() if raw_secret else "nohash"

        finding_id = build_finding_id("SECRET", detector, secret_hash[:8])

        secret_details: SecretDetails = {
            "detector": detector,
            "decoder": finding.get("DecoderName"),
            "verified": finding.get("Verified"),
            "redacted": finding.get("Redacted"),
        }

        aggregator.add_finding(
            Finding(
                id=finding_id,
                type=FindingType.SECRET,
                severity=Severity.CRITICAL,
                component=file_path,
                version="",  # secrets live in files, not packages
                description=f"Secret detected: {detector}",
                scanners=["trufflehog"],
                details=secret_details,
            ),
            source=source,
        )
