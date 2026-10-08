import json
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from app.models.finding import Finding, FindingType
from app.repositories.findings import FindingRepository
from app.services.aggregation.aggregator import ResultAggregator
from app.services.analysis.engine import _persist_findings_and_waivers, _prepare_finding_records

_SCANNER_KEYS = ("id", "severity", "fixed_version")
_GRYPE_OUTPUT = json.loads((Path(__file__).parents[1] / "fixtures/grype/grype_0.119_matches.json").read_text())
_NPM_MATCH = _GRYPE_OUTPUT["matches"][0]


def aggregated_vulnerability(component: str, version: str, *advisories: dict[str, Any]) -> Finding:
    """The aggregator's one finding for component@version holding each advisory's id, severity and fix."""
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
    return finding


def stored_vulnerability(component: str, version: str, advisories: list[dict[str, Any]]) -> dict[str, Any]:
    """The aggregator's document for one component@version; other advisory keys are set on it afterwards."""
    doc = aggregated_vulnerability(component, version, *advisories).model_dump()
    later = {a["id"]: {k: v for k, v in a.items() if k not in _SCANNER_KEYS} for a in advisories}
    for entry in doc["details"]["vulnerabilities"]:
        entry.update(later[entry["id"]])
    return doc


def _grype_match(name: str, version: str, cve: str | None, severity: str | None) -> dict[str, Any]:
    vulnerability = dict(_NPM_MATCH["vulnerability"])
    related = list(_NPM_MATCH["relatedVulnerabilities"])
    if cve:
        vulnerability["id"] = cve
        related = [{**related[0], "id": cve}]
    if severity:
        vulnerability["severity"] = severity
    artifact = {**_NPM_MATCH["artifact"], "name": name, "version": version, "purl": f"pkg:npm/{name}@{version}"}
    return {**_NPM_MATCH, "vulnerability": vulnerability, "relatedVulnerabilities": related, "artifact": artifact}


def grype_findings(matches: Iterable[tuple[str, str, str | None]], *, severity: str | None = None) -> list[Finding]:
    """The aggregator's findings for grype 0.119 output that repeats the fixture's npm match once per
    (package, version, CVE id); a None id keeps the fixture's advisory."""
    report = {**_GRYPE_OUTPUT, "matches": [_grype_match(*match, severity) for match in matches]}
    aggregator = ResultAggregator()
    aggregator.aggregate("grype", report)
    return aggregator.get_findings()


async def persist_findings(
    db: Any, scan_id: str, project_id: str, findings: Iterable[Finding], created_at: datetime
) -> None:
    records, _ = _prepare_finding_records(list(findings), scan_id, project_id, created_at)
    await _persist_findings_and_waivers(records, scan_id, project_id, FindingRepository(db), db)
