from typing import TYPE_CHECKING, Any

from app.models.finding import Finding, FindingType, Severity
from app.schemas.finding_details import HashVerificationDetails, OsMalwareDetails
from app.services.normalizers.utils import build_finding_id, safe_get, safe_severity

if TYPE_CHECKING:
    from app.services.aggregation import ResultAggregator


def normalize_malware(aggregator: "ResultAggregator", result: dict[str, Any], source: str | None = None) -> None:
    """os_malware scanner findings; OpenSSF malware arrives via OSV, handled elsewhere."""
    for item in result.get("malware_issues") or []:
        malware_info = item.get("malware_info") or {}
        threats = malware_info.get("threats") or []
        component = safe_get(item, "component", "unknown")
        version = item.get("version")

        report_description = malware_info.get("description")
        tags = [tag for tag in threats if isinstance(tag, str)] if isinstance(threats, list) else []
        if report_description:
            description = f"Malware detected: {report_description}"
        elif tags:
            more = f" (+{len(tags) - 5} more)" if len(tags) > 5 else ""
            description = f"Malware detected: {', '.join(tags[:5])}{more}"
        else:
            description = "Potential malware detected"

        aggregator.add_finding(
            Finding(
                id=build_finding_id("MALWARE", component),
                type=FindingType.MALWARE,
                severity=safe_severity(item.get("severity"), default=Severity.CRITICAL),
                component=component,
                version=version,
                description=description,
                scanners=["os_malware"],
                details=OsMalwareDetails(
                    info=malware_info,
                    threats=threats,
                    reference=malware_info.get("reference"),
                    source="opensourcemalware",
                ).model_dump(exclude_none=True),
            ),
            source=source,
        )


def normalize_hash_verification(
    aggregator: "ResultAggregator", result: dict[str, Any], source: str | None = None
) -> None:
    for item in result.get("hash_issues") or []:
        component = safe_get(item, "component", "unknown")
        algorithm = safe_get(item, "algorithm", "unknown")
        version = item.get("version")

        aggregator.add_finding(
            Finding(
                id=build_finding_id("HASH", component, algorithm),
                type=FindingType.MALWARE,
                severity=safe_severity(item.get("severity"), default=Severity.CRITICAL),
                component=component,
                version=version,
                description=f"Package integrity check failed! {item.get('message') or 'Hash mismatch detected'}",
                scanners=["hash_verification"],
                details=HashVerificationDetails(
                    registry=item.get("registry"),
                    algorithm=algorithm,
                    sbom_hash=item.get("sbom_hash"),
                    expected_hashes=item.get("expected_hashes") or [],
                    verification_failed=True,
                ).model_dump(exclude_none=True),
            ),
            source=source,
        )
