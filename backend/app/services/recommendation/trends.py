from collections import defaultdict
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from app.core.constants import FINDING_DELTA_THRESHOLD, RECURRING_ISSUE_THRESHOLD
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.analytics.findings_delta import finding_identity_key
from app.services.enrichment import canonical_cves
from app.services.recommendation.common import ModelOrDict, get_attr

# What finding_identity_key reads; the scan-scoped ``_id`` stays out, it never matches across a pair.
_IDENTITY_FIELDS = ("type", "component", "version", "details", "finding_id", "description", "found_in")
_RECURRING_ROWS_SHOWN = 10


def _identity(finding: ModelOrDict) -> tuple[str, str, str]:
    """The same cross-scan identity the scan delta matches findings on."""
    return finding_identity_key({field: get_attr(finding, field) for field in _IDENTITY_FIELDS})


def _cves(findings: list[ModelOrDict]) -> set[str]:
    """The CVE ids these findings report; one finding aggregates a whole advisory list."""
    return {cve for f in findings for cve in canonical_cves([get_attr(f, "details", {})])}


def analyze_regressions(
    current_findings: list[ModelOrDict],
    previous_findings: list[ModelOrDict],
) -> list[Recommendation]:
    """Detect regressions - vulnerabilities that were fixed but have returned."""
    recommendations = []

    previous_keys = {_identity(f) for f in previous_findings}
    new_findings = [f for f in current_findings if _identity(f) not in previous_keys]

    new_vulns = [f for f in new_findings if get_attr(f, "type") == "vulnerability"]
    new_critical = [f for f in new_vulns if get_attr(f, "severity") == "CRITICAL"]
    new_high = [f for f in new_vulns if get_attr(f, "severity") == "HIGH"]

    finding_delta = len(current_findings) - len(previous_findings)

    if new_critical or new_high:
        recommendations.append(
            Recommendation(
                type=RecommendationType.REGRESSION_DETECTED,
                priority=Priority.HIGH if new_critical else Priority.MEDIUM,
                title=(
                    f"Regression: {len(new_critical)} critical, "
                    f"{len(new_high)} high severity vulnerabilities introduced"
                ),
                description=(
                    f"This scan detected {len(new_findings)} new findings compared to "
                    "the previous scan. This may indicate dependency updates that "
                    "introduced new vulnerabilities or new code with security issues."
                ),
                impact={
                    "critical": len(new_critical),
                    "high": len(new_high),
                    "medium": len([f for f in new_vulns if get_attr(f, "severity") == "MEDIUM"]),
                    "low": len([f for f in new_vulns if get_attr(f, "severity") == "LOW"]),
                    "total": len(new_vulns),
                },
                affected_components=list({get_attr(f, "component", "unknown") for f in (new_critical + new_high)[:15]}),
                action={
                    "type": "investigate_regression",
                    # A record whose advisory list merely grew is new as a whole, so the CVEs the
                    # previous build already reported are not what this build introduced.
                    "new_critical_cves": sorted(_cves(new_critical) - _cves(previous_findings)),
                    "suggestion": "Review recent dependency updates and code changes",
                },
                effort="medium",
            )
        )
    elif finding_delta > FINDING_DELTA_THRESHOLD:
        recommendations.append(
            Recommendation(
                type=RecommendationType.REGRESSION_DETECTED,
                priority=Priority.LOW,
                title=f"Finding count increased by {finding_delta}",
                description="The total number of security findings has increased significantly since the last scan.",
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": finding_delta,
                    "total": finding_delta,
                },
                affected_components=[],
                action={"type": "review_changes", "delta": finding_delta},
                effort="low",
            )
        )

    return recommendations


@dataclass
class CveRecurrence:
    """The scans one CVE was found in, and a row describing it."""

    scans: set[str] = field(default_factory=set)
    severity: str | None = None
    component: str | None = None


def _cve_keys(finding: ModelOrDict) -> list[str]:
    """Every CVE the finding reports, or the identifier it is known by when it names none."""
    details = get_attr(finding, "details", {})
    cves = canonical_cves([details]) if isinstance(details, dict) else []
    if cves:
        return cves
    fallback = get_attr(finding, "finding_id") or get_attr(finding, "_id")
    return [str(fallback)] if fallback else []


async def build_cve_recurrence(vulnerability_findings: AsyncIterator[ModelOrDict]) -> dict[str, CveRecurrence]:
    """Fold vulnerability findings of a scan window into the scan set each CVE appeared in.

    Folded off the findings collection rather than the scan document's ``findings_summary``,
    which is bounded to keep the scan under Mongo's document limit.
    """
    recurrence: dict[str, CveRecurrence] = defaultdict(CveRecurrence)
    async for finding in vulnerability_findings:
        scan_id = get_attr(finding, "scan_id")
        if not scan_id:
            continue
        for cve in _cve_keys(finding):
            row = recurrence[cve]
            row.scans.add(scan_id)
            if row.component is None:
                row.severity = get_attr(finding, "severity")
                row.component = get_attr(finding, "component")
    return recurrence


def _count_recurring_by_severity(recurring: list[tuple[str, CveRecurrence]], severity: str) -> int:
    """Count recurring issues matching a given severity."""
    return len([1 for _cve, row in recurring if row.severity == severity])


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
            {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(entry[1].severity or "", 0),
            entry[0],
        ),
        reverse=True,
    )

    critical_count = _count_recurring_by_severity(recurring, "CRITICAL")

    return [
        Recommendation(
            type=RecommendationType.RECURRING_VULNERABILITY,
            priority=Priority.MEDIUM if critical_count > 0 else Priority.LOW,
            title=f"{len(recurring)} vulnerabilities keep recurring across scans",
            description=(
                f"These vulnerabilities have appeared in {RECURRING_ISSUE_THRESHOLD} "
                f"or more of the last {window_scans} scans without being fixed. Consider creating "
                "waivers with justification, or addressing the root cause architecturally."
            ),
            impact={
                "critical": critical_count,
                "high": _count_recurring_by_severity(recurring, "HIGH"),
                "medium": _count_recurring_by_severity(recurring, "MEDIUM"),
                "low": _count_recurring_by_severity(recurring, "LOW"),
                "total": len(recurring),
            },
            affected_components=[
                f"{cve} ({row.component or 'unknown'}) - {len(row.scans)} scans"
                for cve, row in recurring[:_RECURRING_ROWS_SHOWN]
            ],
            action={
                "type": "address_recurring",
                "cves": [cve for cve, _row in recurring[:_RECURRING_ROWS_SHOWN]],
                "suggestions": [
                    "Create waivers with documented justification for accepted risks",
                    "Look for alternative packages without these vulnerabilities",
                    "Consider if the affected functionality can be removed",
                    "Check if upgrading to a different major version resolves the issues",
                ],
            },
            effort="high",
        )
    ]
