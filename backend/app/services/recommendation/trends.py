from collections import defaultdict
from typing import Any, Dict, List

from app.core.constants import FINDING_DELTA_THRESHOLD, RECURRING_ISSUE_THRESHOLD
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.recommendation.common import get_attr, ModelOrDict


def analyze_regressions(
    current_findings: List[ModelOrDict],
    previous_findings: List[ModelOrDict],
) -> List[Recommendation]:
    """
    Detect regressions - vulnerabilities that were fixed but have returned.
    """
    recommendations = []

    # Create sets of finding identifiers
    def finding_key(f):
        """Create a unique key for a finding."""
        if get_attr(f, "type") == "vulnerability":
            details = get_attr(f, "details", {})
            cve = details.get("cve_id") or details.get("id") or get_attr(f, "id")
            component = get_attr(f, "component", "")
            return f"vuln:{cve}:{component}"
        else:
            return f"{get_attr(f, 'type')}:{get_attr(f, 'component')}:{get_attr(f, 'id')}"

    # Build sets for comparison
    previous_keys = {finding_key(f) for f in previous_findings}

    # Find new findings (not in previous scan)
    new_findings = []
    for f in current_findings:
        key = finding_key(f)
        if key not in previous_keys:
            new_findings.append(f)

    # Categorize new findings
    new_vulns = [f for f in new_findings if get_attr(f, "type") == "vulnerability"]
    new_critical = [f for f in new_vulns if get_attr(f, "severity") == "CRITICAL"]
    new_high = [f for f in new_vulns if get_attr(f, "severity") == "HIGH"]

    # Count overall change
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
                affected_components=list(
                    set(get_attr(f, "component", "unknown") for f in (new_critical + new_high)[:15])
                ),
                action={
                    "type": "investigate_regression",
                    "new_critical_cves": [
                        get_attr(f, "details", {}).get("cve_id", get_attr(f, "id")) for f in new_critical
                    ],
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


def analyze_recurring_issues(
    scan_history: List[ModelOrDict],
) -> List[Recommendation]:
    """
    Identify issues that keep appearing across multiple scans.
    These are candidates for waivers or architectural fixes.
    """
    recommendations: List[Recommendation] = []

    if not scan_history:
        return recommendations

    # Count how often each CVE/finding appears across scans
    finding_frequency: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "scans": set(), "info": None})

    for scan in scan_history:
        scan_id = get_attr(scan, "_id") or get_attr(scan, "id")
        findings_summary = get_attr(scan, "findings_summary", []) or []

        for f in findings_summary:
            if get_attr(f, "type") == "vulnerability":
                details = get_attr(f, "details", {})
                cve = details.get("cve_id") or get_attr(f, "id")
                if cve:
                    finding_frequency[cve]["count"] += 1
                    finding_frequency[cve]["scans"].add(scan_id)
                    if not finding_frequency[cve]["info"]:
                        finding_frequency[cve]["info"] = {
                            "severity": get_attr(f, "severity"),
                            "component": get_attr(f, "component"),
                            "description": get_attr(f, "description", "")[:100],
                        }

    # Find truly recurring issues (appear in N+ scans)
    recurring = [
        {"cve": cve, **data} for cve, data in finding_frequency.items() if data["count"] >= RECURRING_ISSUE_THRESHOLD
    ]

    if recurring:
        # Sort by frequency and severity
        recurring.sort(
            key=lambda x: (
                x["count"],
                {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x.get("info", {}).get("severity", ""), 0),
            ),
            reverse=True,
        )

        critical_recurring = [r for r in recurring if r.get("info", {}).get("severity") == "CRITICAL"]

        recommendations.append(
            Recommendation(
                type=RecommendationType.RECURRING_VULNERABILITY,
                priority=Priority.MEDIUM if critical_recurring else Priority.LOW,
                title=f"{len(recurring)} vulnerabilities keep recurring across scans",
                description=(
                    f"These vulnerabilities have appeared in {RECURRING_ISSUE_THRESHOLD} "
                    "or more scans without being fixed. Consider creating waivers with "
                    "justification, or addressing the root cause architecturally."
                ),
                impact={
                    "critical": len(critical_recurring),
                    "high": len([r for r in recurring if r.get("info", {}).get("severity") == "HIGH"]),
                    "medium": len([r for r in recurring if r.get("info", {}).get("severity") == "MEDIUM"]),
                    "low": len([r for r in recurring if r.get("info", {}).get("severity") == "LOW"]),
                    "total": len(recurring),
                },
                affected_components=[
                    f"{r['cve']} ({r.get('info', {}).get('component', 'unknown')}) - {r['count']} scans"
                    for r in recurring[:10]
                ],
                action={
                    "type": "address_recurring",
                    "cves": [r["cve"] for r in recurring[:10]],
                    "suggestions": [
                        "Create waivers with documented justification for accepted risks",
                        "Look for alternative packages without these vulnerabilities",
                        "Consider if the affected functionality can be removed",
                        "Check if upgrading to a different major version resolves the issues",
                    ],
                },
                effort="high",
            )
        )

    return recommendations
