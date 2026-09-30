from collections import defaultdict
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from app.core.constants import (
    FINDING_DELTA_THRESHOLD,
    RECURRING_ISSUE_THRESHOLD,
    get_severity_value,
    max_severity,
)
from app.core.cve import canonical_cves, counted_cves
from app.models.finding import FindingType
from app.schemas.recommendation import (
    Effort,
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.analytics.findings_delta import (
    FINDING_IDENTITY_PROJECTION,
    IDENTITY_FIELDS,
    advisory_keys,
    finding_identity_key,
)
from app.services.recommendation.common import (
    ModelOrDict,
    get_attr,
    live_advisories,
    sample_components,
    severity_impact,
)

_RECURRING_ROWS_SHOWN = 10
_NON_SECURITY_TYPES = frozenset({FindingType.OUTDATED.value, FindingType.SYSTEM_WARNING.value})
_FLAGGED_SEVERITIES = frozenset({"CRITICAL", "HIGH"})

PREVIOUS_SCAN_PROJECTION = {
    **FINDING_IDENTITY_PROJECTION,
    "details.vulnerabilities.resolved_cve": 1,
    "details.vulnerabilities.aliases": 1,
}


@dataclass
class PreviousScan:
    """What the regression check keeps of the preceding scan: identity keys and per-artifact advisories."""

    keys: set[tuple[str, str, str]] = field(default_factory=set)
    advisories: set[tuple[str, str]] = field(default_factory=set)

    def add(self, doc: dict[str, Any]) -> None:
        if doc.get("type") == FindingType.VULNERABILITY:
            self.advisories |= advisory_keys(doc)
        elif doc.get("type") not in _NON_SECURITY_TYPES:
            self.keys.add(finding_identity_key(doc))


def _introduced_cves(doc: dict[str, Any], previous: PreviousScan) -> list[tuple[str, str | None]]:
    """Each live CVE the previous scan did not report on this artifact, with its own advisory's severity."""
    new = {cve for _, cve in advisory_keys(doc) - previous.advisories}
    return [
        (cve, entry.get("severity"))
        for entry in live_advisories(doc["details"])
        for cve in new.intersection(counted_cves(entry))
    ]


def analyze_regressions(current_findings: list[ModelOrDict], previous: PreviousScan) -> list[Recommendation]:
    """Findings and advisories the preceding scan did not report."""
    new_count = 0
    new_cves: dict[str, str | None] = {}
    flagged: set[str] = set()
    for finding in current_findings:
        doc = {name: get_attr(finding, name) for name in IDENTITY_FIELDS}
        if doc["type"] == FindingType.VULNERABILITY:
            introduced = _introduced_cves(doc, previous)
            new_count += bool(introduced)
            for cve, severity in introduced:
                new_cves[cve] = max_severity(new_cves.get(cve), severity)
            if any(severity in _FLAGGED_SEVERITIES for _, severity in introduced):
                flagged.add(doc["component"] or "unknown")
        elif doc["type"] not in _NON_SECURITY_TYPES and finding_identity_key(doc) not in previous.keys:
            new_count += 1

    impact = severity_impact(new_cves.values())
    critical, high = impact["critical"], impact["high"]
    if critical or high:
        regression_shown, regression_total = sample_components(sorted(flagged))
        return [
            Recommendation(
                type=RecommendationType.REGRESSION_DETECTED,
                priority=Priority.HIGH if critical else Priority.MEDIUM,
                title=f"Regression: {critical} critical, {high} high severity vulnerabilities introduced",
                description=(
                    f"This scan detected {new_count} new findings compared to "
                    "the previous scan. This may indicate dependency updates that "
                    "introduced new vulnerabilities or new code with security issues."
                ),
                impact=impact,
                affected_components=regression_shown,
                affected_components_total=regression_total,
                action={
                    "type": "investigate_regression",
                    "new_critical_cves": sorted(cve for cve, severity in new_cves.items() if severity == "CRITICAL"),
                    "suggestion": "Review recent dependency updates and code changes",
                },
                effort=Effort.MEDIUM,
            )
        ]
    if new_count > FINDING_DELTA_THRESHOLD:
        return [
            Recommendation(
                type=RecommendationType.REGRESSION_DETECTED,
                priority=Priority.LOW,
                title=f"{new_count} new findings since the last scan",
                description=f"This scan reports {new_count} security findings the previous scan did not.",
                impact={"critical": 0, "high": 0, "medium": 0, "low": new_count, "total": new_count},
                affected_components=[],
                action={"type": "review_changes", "new_findings": new_count},
                effort=Effort.LOW,
            )
        ]
    return []


@dataclass
class CveRecurrence:
    """The scans one CVE was found in, and a row describing it."""

    scans: set[str] = field(default_factory=set)
    severity: str | None = None
    component: str | None = None


async def build_cve_recurrence(vulnerability_findings: AsyncIterator[dict[str, Any]]) -> dict[str, CveRecurrence]:
    """Fold vulnerability findings of a scan window into the scan set each CVE appeared in."""
    recurrence: dict[str, CveRecurrence] = defaultdict(CveRecurrence)
    async for finding in vulnerability_findings:
        scan_id = finding["scan_id"]
        fallback = finding.get("finding_id")
        for cve in canonical_cves([finding.get("details")]) or ([str(fallback)] if fallback else []):
            row = recurrence[cve]
            row.scans.add(scan_id)
            if row.component is None:
                row.severity = finding.get("severity")
                row.component = finding.get("component")
    return recurrence


def analyze_recurring_issues(
    recurrence: dict[str, CveRecurrence],
    window_scans: int,
) -> list[Recommendation]:
    """Identify issues that keep appearing across the scan window the caller folded."""
    recurring = [(cve, row) for cve, row in recurrence.items() if len(row.scans) >= RECURRING_ISSUE_THRESHOLD]

    if not recurring:
        return []

    recurring.sort(
        key=lambda entry: (
            len(entry[1].scans),
            get_severity_value(entry[1].severity),
            entry[0],
        ),
        reverse=True,
    )

    impact = severity_impact(row.severity for _, row in recurring)
    recurring_shown, recurring_total = sample_components(
        f"{cve} ({row.component or 'unknown'}) - {len(row.scans)} scans" for cve, row in recurring
    )

    return [
        Recommendation(
            type=RecommendationType.RECURRING_VULNERABILITY,
            priority=Priority.MEDIUM if impact["critical"] else Priority.LOW,
            title=f"{len(recurring)} vulnerabilities keep recurring across scans",
            description=(
                f"These vulnerabilities have appeared in {RECURRING_ISSUE_THRESHOLD} "
                f"or more of the last {window_scans} scans without being fixed. Consider creating "
                "waivers with justification, or addressing the root cause architecturally."
            ),
            impact=impact,
            affected_components=recurring_shown,
            affected_components_total=recurring_total,
            action={
                "type": "address_recurring",
                "cves": [cve for cve, _row in recurring[:_RECURRING_ROWS_SHOWN]],
                "steps": [
                    "Create waivers with documented justification for accepted risks",
                    "Look for alternative packages without these vulnerabilities",
                    "Consider if the affected functionality can be removed",
                    "Check if upgrading to a different major version resolves the issues",
                ],
            },
            effort=Effort.HIGH,
        )
    ]
