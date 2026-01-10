from typing import Any, Dict, TYPE_CHECKING
from app.models.finding import Finding, FindingType, Severity

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator

def normalize_outdated(aggregator: "ResultAggregator", result: Dict[str, Any], source: str = None):
    for item in result.get("outdated_dependencies", []):
        aggregator.add_finding(
            Finding(
                id=f"OUTDATED-{item['component']}",
                type=FindingType.OUTDATED,
                severity=Severity(item.get("severity", "INFO")),
                component=item.get("component"),
                version=item.get("current_version"),
                description=item.get("message"),
                scanners=["outdated_packages"],
                details={"fixed_version": item.get("latest_version")},
            ),
            source=source,
        )

def normalize_eol(aggregator: "ResultAggregator", result: Dict[str, Any], source: str = None):
    for item in result.get("eol_issues", []):
        eol_info = item.get("eol_info", {})
        eol_date = eol_info.get("eol")
        cycle = eol_info.get("cycle")
        latest = eol_info.get("latest")

        aggregator.add_finding(
            Finding(
                id=f"EOL-{item['component']}-{cycle}",
                type=FindingType.EOL,
                severity=Severity.HIGH,
                component=item.get("component"),
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
