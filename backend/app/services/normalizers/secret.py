import hashlib
from typing import Any, Dict, Optional, TYPE_CHECKING

from app.models.finding import Finding, FindingType, Severity
from app.schemas.finding import SecretDetails
from app.services.normalizers.utils import build_finding_id

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator


def normalize_trufflehog(aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None):
    """Normalize TruffleHog secret scan results."""
    # TruffleHog structure: {"findings": [TruffleHogFinding objects]}
    for finding in result.get("findings") or []:
        # Extract file path from various source metadata formats
        file_path = "unknown"
        source_metadata = finding.get("SourceMetadata") or {}
        data = source_metadata.get("Data") or {}

        # Check Filesystem source
        filesystem = data.get("Filesystem") or {}
        if filesystem.get("file"):
            file_path = filesystem["file"]
        else:
            # Check Git source
            git = data.get("Git") or {}
            if git.get("file"):
                file_path = git["file"]

        detector = finding.get("DetectorType") or "Generic Secret"

        # Create a unique ID based on detector, file path, and secret hash
        raw_secret = finding.get("Raw") or ""
        secret_hash = hashlib.md5(raw_secret.encode()).hexdigest() if raw_secret else "nohash"

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
                version="",  # No version for secrets in files
                description=f"Secret detected: {detector}",
                scanners=["trufflehog"],
                details=secret_details,
            ),
            source=source,
        )
