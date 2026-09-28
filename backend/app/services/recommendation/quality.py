from collections import defaultdict
from typing import Any

from app.core.constants import SCORECARD_LOW_THRESHOLD
from app.schemas.recommendation import Priority, Recommendation, RecommendationType
from app.services.recommendation.common import ModelOrDict, get_attr, sample_components, scorecard_details


def _keep_lowest(entries: dict[str, dict[str, Any]], entry: dict[str, Any]) -> None:
    """One entry per component: quality findings come one per installed version."""
    kept = entries.get(entry["component"])
    if kept is None or entry["score"] < kept["score"]:
        entries[entry["component"]] = entry


def process_quality(findings: list[ModelOrDict]) -> list[Recommendation]:
    """Process supply chain quality findings from OpenSSF Scorecard."""
    if not findings:
        return []

    recommendations = []
    components_by_issue: dict[str, list[Any]] = defaultdict(list)
    low_score_by_component: dict[str, dict[str, Any]] = {}
    unmaintained_by_component: dict[str, dict[str, Any]] = {}

    for f in findings:
        component = get_attr(f, "component", "unknown")
        details = get_attr(f, "details", {})

        overall_score = details.get("overall_score") if isinstance(details, dict) else None
        if overall_score is None:
            overall_score = 0.0

        sc_details = scorecard_details(details)
        critical_issues = sc_details.get("critical_issues") or []
        failed_checks = sc_details.get("failed_checks") or []
        project_url = sc_details.get("project_url") or ""
        has_maintenance = bool(details.get("has_maintenance_issues")) if isinstance(details, dict) else False

        if overall_score < SCORECARD_LOW_THRESHOLD:
            _keep_lowest(
                low_score_by_component,
                {
                    "component": component,
                    "score": overall_score,
                    "project_url": project_url,
                    "critical_issues": critical_issues,
                },
            )

        if "Maintained" in critical_issues or has_maintenance:
            _keep_lowest(
                unmaintained_by_component,
                {"component": component, "score": overall_score, "project_url": project_url},
            )

        for issue in critical_issues:
            components_by_issue[issue].append(component)

        for check in failed_checks:
            check_name = check.get("name", "") if isinstance(check, dict) else check
            components_by_issue[f"check:{check_name}"].append(component)

    unmaintained_packages = list(unmaintained_by_component.values())
    unmaintained_shown, unmaintained_total = sample_components(unmaintained_by_component)
    if unmaintained_packages:
        recommendations.append(
            Recommendation(
                type=RecommendationType.SUPPLY_CHAIN_RISK,
                priority=Priority.HIGH,
                title="Replace Unmaintained Dependencies",
                description=(
                    f"Found {unmaintained_total} potentially unmaintained packages. "
                    "These packages may not receive security updates, putting your application at risk."
                ),
                impact={
                    "total": unmaintained_total,
                    "packages": unmaintained_shown,
                },
                affected_components=unmaintained_shown,
                affected_components_total=unmaintained_total,
                action={
                    "type": "replace_unmaintained",
                    "steps": [
                        "Identify which unmaintained packages are critical to your application",
                        "Search for actively maintained alternatives on npm/pypi/crates.io",
                        "Consider forking critical packages if no alternatives exist",
                        "Create a migration plan for each unmaintained dependency",
                        "Monitor OpenSSF Scorecard for updates to maintenance status",
                    ],
                    "packages": [
                        {
                            "name": p["component"],
                            "score": p["score"],
                            "url": p.get("project_url"),
                        }
                        for p in unmaintained_packages[:10]
                    ],
                },
                effort="high",
            )
        )

    vuln_packages = components_by_issue.get("Vulnerabilities", [])
    vuln_shown, vuln_total = sample_components(sorted(set(vuln_packages)))
    if vuln_packages:
        recommendations.append(
            Recommendation(
                type=RecommendationType.SUPPLY_CHAIN_RISK,
                priority=Priority.HIGH,
                title="Address Packages with Known Vulnerability Issues",
                description=(
                    f"{vuln_total} packages have unaddressed security vulnerabilities "
                    "according to OpenSSF Scorecard. These need immediate attention."
                ),
                impact={
                    "total": vuln_total,
                },
                affected_components=vuln_shown,
                affected_components_total=vuln_total,
                action={
                    "type": "fix_scorecard_vulnerabilities",
                    "steps": [
                        "Check for available security patches or updates",
                        "Review CVE databases for specific vulnerabilities",
                        "Apply patches or upgrade to fixed versions",
                        "If no fix is available, consider alternatives",
                    ],
                },
                effort="medium",
            )
        )

    low_score_packages = list(low_score_by_component.values())
    low_score_shown, low_score_total = sample_components(low_score_by_component)
    # Skip when unmaintained packages already cover these.
    if low_score_packages and not unmaintained_packages:
        recommendations.append(
            Recommendation(
                type=RecommendationType.SUPPLY_CHAIN_RISK,
                priority=Priority.MEDIUM,
                title="Review Low-Quality Dependencies",
                description=(
                    f"Found {low_score_total} packages with OpenSSF Scorecard "
                    f"scores below {SCORECARD_LOW_THRESHOLD}/10. "
                    "These packages may have quality, security, or maintenance concerns."
                ),
                impact={
                    "total": low_score_total,
                    "average_score": sum(p["score"] for p in low_score_packages) / low_score_total,
                },
                affected_components=low_score_shown,
                affected_components_total=low_score_total,
                action={
                    "type": "review_quality",
                    "steps": [
                        "Review OpenSSF Scorecard details for each package",
                        "Assess if package is critical to your application",
                        "Consider alternatives with higher scorecard ratings",
                        "For critical packages, contribute to improving their security practices",
                    ],
                    "packages": [
                        {
                            "name": p["component"],
                            "score": p["score"],
                            "issues": p.get("critical_issues", []),
                        }
                        for p in sorted(low_score_packages, key=lambda x: x["score"])[:10]
                    ],
                },
                effort="medium",
            )
        )

    code_review_issues = components_by_issue.get("check:Code-Review", [])
    review_shown, review_total = sample_components(sorted(set(code_review_issues)))
    if code_review_issues:
        recommendations.append(
            Recommendation(
                type=RecommendationType.SUPPLY_CHAIN_RISK,
                priority=Priority.LOW,
                title="Dependencies with Limited Code Review",
                description=(
                    f"{review_total} packages have limited or no code review processes. "
                    "This increases the risk of unreviewed malicious or buggy changes."
                ),
                impact={"total": review_total},
                affected_components=review_shown,
                affected_components_total=review_total,
                action={
                    "type": "code_review_concern",
                    "steps": [
                        "Monitor these packages more closely for updates",
                        "Review changelogs before updating",
                        "Consider pinning versions and manually reviewing changes",
                    ],
                },
                effort="low",
            )
        )

    return recommendations
