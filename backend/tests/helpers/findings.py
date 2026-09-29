from typing import Any

from app.models.finding import Finding, FindingType
from app.services.aggregation.aggregator import ResultAggregator

_SCANNER_KEYS = ("id", "severity", "fixed_version")


def stored_vulnerability(component: str, version: str, advisories: list[dict[str, Any]]) -> dict[str, Any]:
    """The aggregator's document for one component@version; other advisory keys are set on it afterwards."""
    aggregator = ResultAggregator()
    for advisory in advisories:
        aggregator.add_finding(
            Finding(
                id=advisory["id"],
                type=FindingType.VULNERABILITY,
                severity=advisory.get("severity", "HIGH"),
                component=component,
                version=version,
                description="",
                scanners=["trivy"],
                details={"fixed_version": advisory.get("fixed_version")},
            )
        )
    [finding] = aggregator.get_findings()
    doc = finding.model_dump()
    later = {a["id"]: {k: v for k, v in a.items() if k not in _SCANNER_KEYS} for a in advisories}
    for entry in doc["details"]["vulnerabilities"]:
        entry.update(later[entry["id"]])
    return doc
