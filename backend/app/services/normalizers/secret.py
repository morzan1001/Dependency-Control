import re
from typing import TYPE_CHECKING, Any

from app.models.finding import Finding, FindingType
from app.schemas.finding_details import SecretDetails
from app.schemas.trufflehog import TruffleHogFinding
from app.services.enrichment.scoring import calculate_secret_risk_score, calculate_secret_severity
from app.services.normalizers.utils import FindingIdPrefix, build_finding_id

if TYPE_CHECKING:
    from app.services.aggregation import ResultAggregator


def _extract_file_path(source_metadata: dict[str, Any] | None) -> str:
    data = (source_metadata or {}).get("Data") or {}

    filesystem = data.get("Filesystem") or {}
    if filesystem.get("file"):
        return str(filesystem["file"])

    git = data.get("Git") or {}
    if git.get("file"):
        return str(git["file"])

    return "unknown"


def _extract_source_metadata(source_metadata: dict[str, Any] | None) -> dict[str, Any]:
    data = (source_metadata or {}).get("Data") or {}
    git = data.get("Git") or {}
    line = (git or data.get("Filesystem") or {}).get("line")
    # CI-posted input: str.isdigit() admits "²" and int() rejects over 4300 digits; BSON caps ints at 64 bits.
    line_text = str(line) if isinstance(line, (int, str)) else ""
    return {
        "commit": str(git["commit"]) if git.get("commit") else None,
        "commit_timestamp": str(git["timestamp"]) if git.get("timestamp") else None,
        "line": int(line_text) if re.fullmatch(r"[0-9]{1,9}", line_text) else None,
    }


def normalize_trufflehog(aggregator: "ResultAggregator", result: dict[str, Any], source: str | None = None) -> None:
    for entry in result.get("findings") or []:
        # Stored rows and posted ad-hoc payloads can carry Raw; the model derives the same RawHash from it.
        finding = TruffleHogFinding.model_validate(entry)
        file_path = _extract_file_path(finding.SourceMetadata)
        # The DetectorType ordinal is the stored identity: it reaches finding_id and every secret waiver's match.rule_key.
        detector = str(finding.DetectorType or "Generic Secret")

        finding_id = build_finding_id(FindingIdPrefix.SECRET, detector, (finding.RawHash or "nohash")[:8])

        source_meta = _extract_source_metadata(finding.SourceMetadata)
        in_current_tree = finding.DcInCurrentTree
        verified = finding.Verified
        risk_score, adjusted_risk_score = calculate_secret_risk_score(verified, in_current_tree)

        secret_details = SecretDetails(
            detector=detector,
            detector_name=finding.DetectorName,
            decoder=finding.DecoderName,
            verified=verified,
            redacted=finding.Redacted,
            commit=source_meta["commit"],
            commit_timestamp=source_meta["commit_timestamp"],
            line=source_meta["line"],
            in_current_tree=in_current_tree,
            risk_score=risk_score,
            adjusted_risk_score=adjusted_risk_score,
        ).model_dump(exclude_none=True)

        aggregator.add_finding(
            Finding(
                id=finding_id,
                type=FindingType.SECRET,
                severity=calculate_secret_severity(verified, in_current_tree),
                component=file_path,
                version="",  # secrets live in files, not packages
                description=f"Secret detected: {finding.DetectorName or detector}",
                scanners=["trufflehog"],
                details=secret_details,
            ),
            source=source,
        )
