from typing import Any, Dict, Optional, TYPE_CHECKING

from app.models.finding import Finding, FindingType, Severity
from app.services.normalizers.utils import build_finding_id, safe_get, safe_severity

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator


def normalize_outdated(aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None):
    """Normalize outdated package findings."""
    for item in result.get("outdated_dependencies") or []:
        component = safe_get(item, "component", "unknown")

        aggregator.add_finding(
            Finding(
                id=build_finding_id("OUTDATED", component),
                type=FindingType.OUTDATED,
                severity=safe_severity(item.get("severity"), default=Severity.INFO),
                component=component,
                version=item.get("current_version"),
                description=item.get("message") or f"Outdated: {component}",
                scanners=["outdated_packages"],
                details={"fixed_version": item.get("latest_version")},
            ),
            source=source,
        )


def normalize_eol(aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None):
    """Normalize end-of-life findings."""
    for item in result.get("eol_issues") or []:
        eol_info = item.get("eol_info") or {}
        eol_date = eol_info.get("eol")
        cycle = eol_info.get("cycle") or "unknown"
        latest = eol_info.get("latest")
        component = safe_get(item, "component", "unknown")

        aggregator.add_finding(
            Finding(
                id=build_finding_id("EOL", component, cycle),
                type=FindingType.EOL,
                severity=Severity.HIGH,
                component=component,
                version=item.get("version"),
                description=f"End of Life reached on {eol_date} (Cycle {cycle}). Latest: {latest}",
                scanners=["end_of_life"],
                details={
                    "fixed_version": latest,
                    "eol_date": eol_date,
                    "cycle": cycle,
                    "link": eol_info.get("link"),
                    "lts": eol_info.get("lts"),
                },
            ),
            source=source,
        )
