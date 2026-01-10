from typing import Any, Dict, TYPE_CHECKING
from app.models.finding import Finding, FindingType, Severity

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator

def normalize_license(aggregator: "ResultAggregator", result: Dict[str, Any], source: str = None):
    for item in result.get("license_issues", []):
        # Map severity strings to enum (handle INFO as LOW since INFO might not exist)
        severity_str = item.get("severity", "MEDIUM").upper()
        if severity_str == "INFO":
            severity = Severity.LOW
        else:
            severity = Severity(severity_str)

        component = item.get("component")
        version = item.get("version")

        # Enrich dependency with license data (aggregation)
        if component and version:
            aggregator.enrich_from_license_scanner(component, version, item)

        aggregator.add_finding(
            Finding(
                id=f"LIC-{item['license']}",
                type=FindingType.LICENSE,
                severity=severity,
                component=component,
                version=version,
                description=item.get("message"),
                scanners=["license_compliance"],
                details={
                    "license": item.get("license"),
                    "license_url": item.get("license_url"),
                    "category": item.get("category"),
                    "explanation": item.get("explanation"),
                    "recommendation": item.get("recommendation"),
                    "obligations": item.get("obligations", []),
                    "risks": item.get("risks", []),
                    "purl": item.get("purl"),
                },
            ),
            source=source,
        )
