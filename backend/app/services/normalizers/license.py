from typing import Any, Dict, Optional, TYPE_CHECKING

from app.models.finding import Finding, FindingType, Severity
from app.services.normalizers.utils import build_finding_id, safe_get, safe_severity

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator


def normalize_license(aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None):
    """Normalize license compliance findings."""
    for item in result.get("license_issues") or []:
        # Safely parse severity with fallback
        severity = safe_severity(item.get("severity"), default=Severity.MEDIUM)

        component = item.get("component")
        version = item.get("version")
        license_name = safe_get(item, "license", "UNKNOWN")

        # Enrich dependency with license data (aggregation)
        if component and version:
            aggregator.enrich_from_license_scanner(component, version, item)

        aggregator.add_finding(
            Finding(
                id=build_finding_id("LIC", license_name),
                type=FindingType.LICENSE,
                severity=severity,
                component=component,
                version=version,
                description=item.get("message") or f"License issue: {license_name}",
                scanners=["license_compliance"],
                details={
                    "license": license_name,
                    "license_url": item.get("license_url"),
                    "category": item.get("category"),
                    "explanation": item.get("explanation"),
                    "recommendation": item.get("recommendation"),
                    "obligations": item.get("obligations") or [],
                    "risks": item.get("risks") or [],
                    "purl": item.get("purl"),
                },
            ),
            source=source,
        )
