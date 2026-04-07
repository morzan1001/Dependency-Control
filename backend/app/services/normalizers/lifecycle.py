from typing import Any, Dict, Optional, TYPE_CHECKING

from app.models.finding import Finding, FindingType, Severity
from app.services.normalizers.utils import build_finding_id, safe_get, safe_severity

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator


def normalize_outdated(aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None) -> None:
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

    for item in result.get("ahead_of_default") or []:
        component = safe_get(item, "component", "unknown")

        aggregator.add_finding(
            Finding(
                id=build_finding_id("OUTDATED", component, "ahead"),
                type=FindingType.OUTDATED,
                severity=Severity.INFO,
                component=component,
                version=item.get("current_version"),
                description=item.get("message") or f"Ahead of default: {component}",
                scanners=["outdated_packages"],
                details={
                    "default_version": item.get("default_version"),
                    "ahead_of_default": True,
                },
            ),
            source=source,
        )


def normalize_eol(aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None) -> None:
    """Normalize end-of-life findings."""
    for item in result.get("eol_issues") or []:
        eol_info = item.get("eol_info") or {}
        eol_date = eol_info.get("eol")
        cycle = eol_info.get("cycle") or "unknown"
        latest = eol_info.get("latest")
        component = safe_get(item, "component", "unknown")

        # Use recommended version from active cycle if available,
        # otherwise fall back to latest within same cycle
        recommended = eol_info.get("recommended_version") or latest
        recommended_cycle = eol_info.get("recommended_cycle")

        if recommended_cycle:
            description = (
                f"End of Life: Version cycle {cycle} reached EOL on {eol_date}. "
                f"Upgrade to {recommended} (cycle {recommended_cycle})"
            )
        else:
            description = f"End of Life reached on {eol_date} (Cycle {cycle}). Latest: {latest}"

        aggregator.add_finding(
            Finding(
                id=build_finding_id("EOL", component, cycle),
                type=FindingType.EOL,
                severity=safe_severity(item.get("severity"), default=Severity.HIGH),
                component=component,
                version=item.get("version"),
                description=description,
                scanners=["end_of_life"],
                details={
                    "fixed_version": recommended,
                    "eol_date": eol_date,
                    "cycle": cycle,
                    "recommended_cycle": recommended_cycle,
                    "link": eol_info.get("link"),
                    "lts": eol_info.get("lts"),
                },
            ),
            source=source,
        )
