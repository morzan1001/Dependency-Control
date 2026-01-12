import hashlib
from typing import Any, Dict, Optional, TYPE_CHECKING
from app.models.finding import Finding, FindingType, Severity
from app.schemas.finding import SecretDetails

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator


def normalize_trufflehog(
    aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None
):
    """Normalize TruffleHog secret scan results."""
    # TruffleHog structure: {"findings": [TruffleHogFinding objects]}
    for finding in result.get("findings", []):
        # Extract file path
        file_path = "unknown"
        if finding.get("SourceMetadata") and "Data" in finding["SourceMetadata"]:
            # Filesystem mode
            data = finding["SourceMetadata"]["Data"]
            if "Filesystem" in data and "file" in data["Filesystem"]:
                file_path = data["Filesystem"]["file"]
            elif "Git" in data and "file" in data["Git"]:
                file_path = data["Git"]["file"]

        detector = finding.get("DetectorType", "Generic Secret")

        # Create a unique ID based on detector, file path, and secret hash
        raw_secret = finding.get("Raw", "")
        secret_hash = (
            hashlib.md5(raw_secret.encode()).hexdigest() if raw_secret else "nohash"
        )

        finding_id = f"SECRET-{detector}-{secret_hash[:8]}"

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
