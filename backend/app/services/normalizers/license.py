from typing import TYPE_CHECKING, Any

from app.models.finding import Finding, FindingType, Severity
from app.schemas.finding_details import LicenseDetails
from app.services.normalizers.utils import build_finding_id, safe_get, safe_severity

if TYPE_CHECKING:
    from app.services.aggregation import ResultAggregator


def normalize_license(aggregator: "ResultAggregator", result: dict[str, Any], source: str | None = None) -> None:
    # Enrichment reads the full classification list; issues only exist for policy
    # violations and include synthetic cross-component "A + B" compatibility entries.
    for entry in result.get("component_licenses") or []:
        component = entry.get("component")
        version = entry.get("version")
        if component and version:
            aggregator.enrich_from_license_scanner(component, version, entry)

    for item in result.get("license_issues") or []:
        severity = safe_severity(item.get("severity"), default=Severity.MEDIUM)

        component = item.get("component")
        version = item.get("version")
        license_name = safe_get(item, "license", "UNKNOWN")

        aggregator.add_finding(
            Finding(
                id=build_finding_id("LIC", license_name),
                type=FindingType.LICENSE,
                severity=severity,
                component=component,
                version=version,
                description=item.get("message") or f"License issue: {license_name}",
                scanners=["license_compliance"],
                details=LicenseDetails(
                    license=license_name,
                    license_url=item.get("license_url"),
                    category=item.get("category"),
                    explanation=item.get("explanation"),
                    recommendation=item.get("recommendation"),
                    obligations=item.get("obligations") or [],
                    risks=item.get("risks") or [],
                    purl=item.get("purl"),
                    spdx_expression=item.get("spdx_expression"),
                    context_reason=item.get("context_reason"),
                    effective_severity=item.get("effective_severity"),
                ).model_dump(exclude_none=True),
            ),
            source=source,
        )
