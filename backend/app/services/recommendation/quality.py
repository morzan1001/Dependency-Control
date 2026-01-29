from collections import defaultdict
from typing import Any, Dict, List

from app.core.constants import SCORECARD_LOW_THRESHOLD
from app.schemas.recommendation import Priority, Recommendation, RecommendationType
from app.services.recommendation.common import get_attr, ModelOrDict


def process_quality(findings: List[ModelOrDict]) -> List[Recommendation]:
    """Process supply chain quality findings from OpenSSF Scorecard."""
    if not findings:
        return []

    recommendations = []
    severity_counts: Dict[str, int] = defaultdict(int)
    components_by_issue: Dict[str, List[Any]] = defaultdict(
        list
    )  # issue_type -> [components]
    low_score_packages: List[Any] = []  # Packages with very low scores
    unmaintained_packages: List[Any] = []

    for f in findings:
        severity = get_attr(f, "severity", "UNKNOWN")
        severity_counts[severity] += 1
        component = get_attr(f, "component", "unknown")
        version = get_attr(f, "version", "")
        details = get_attr(f, "details", {})

        overall_score = details.get("overall_score") if isinstance(details, dict) else None
        if overall_score is None:
            overall_score = 0.0

        critical_issues = details.get("critical_issues", []) if isinstance(details, dict) else []
        failed_checks = details.get("failed_checks", []) if isinstance(details, dict) else []
        project_url = details.get("project_url", "") if isinstance(details, dict) else ""

        # Track packages with very low scores
        if overall_score < SCORECARD_LOW_THRESHOLD:
            low_score_packages.append(
                {
                    "component": component,
                    "version": version,
                    "score": overall_score,
                    "project_url": project_url,
                    "critical_issues": critical_issues,
                }
            )

        # Track by issue type
        if "Maintained" in critical_issues:
            unmaintained_packages.append(
                {
                    "component": component,
                    "version": version,
                    "score": overall_score,
                    "project_url": project_url,
                }
            )

        for issue in critical_issues:
            components_by_issue[issue].append(component)

        # Also categorize by failed checks
        for check in failed_checks:
            check_name = check.get("name", "") if isinstance(check, dict) else check
            components_by_issue[f"check:{check_name}"].append(component)

    # 1. Generate recommendation for unmaintained packages (highest priority)
    if unmaintained_packages:
        recommendations.append(
            Recommendation(
                type=RecommendationType.SUPPLY_CHAIN_RISK,
                priority=Priority.HIGH,
                title="Replace Unmaintained Dependencies",
                description=(
                    f"Found {len(unmaintained_packages)} potentially unmaintained packages. "
                    "These packages may not receive security updates, putting your application at risk."
                ),
                impact={
                    "total": len(unmaintained_packages),
                    "packages": [p["component"] for p in unmaintained_packages[:10]],
                },
                affected_components=[p["component"] for p in unmaintained_packages],
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

    # 2. Generate recommendation for packages with critical security issues
    vuln_packages = components_by_issue.get("Vulnerabilities", [])
    if vuln_packages:
        recommendations.append(
            Recommendation(
                type=RecommendationType.SUPPLY_CHAIN_RISK,
                priority=Priority.HIGH,
                title="Address Packages with Known Vulnerability Issues",
                description=(
                    f"{len(vuln_packages)} packages have unaddressed security vulnerabilities "
                    "according to OpenSSF Scorecard. These need immediate attention."
                ),
                impact={
                    "total": len(vuln_packages),
                },
                affected_components=list(set(vuln_packages))[:20],
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

    # 3. Generate recommendation for low-score packages (general quality concern)
    if (
        low_score_packages and not unmaintained_packages
    ):  # Don't duplicate if already covered
        recommendations.append(
            Recommendation(
                type=RecommendationType.SUPPLY_CHAIN_RISK,
                priority=Priority.MEDIUM,
                title="Review Low-Quality Dependencies",
                description=(
                    f"Found {len(low_score_packages)} packages with OpenSSF Scorecard "
                    f"scores below {SCORECARD_LOW_THRESHOLD}/10. "
                    "These packages may have quality, security, or maintenance concerns."
                ),
                impact={
                    "total": len(low_score_packages),
                    "average_score": sum(p["score"] for p in low_score_packages)
                    / len(low_score_packages),
                },
                affected_components=[p["component"] for p in low_score_packages],
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
                        for p in sorted(low_score_packages, key=lambda x: x["score"])[
                            :10
                        ]
                    ],
                },
                effort="medium",
            )
        )

    # 4. Generate recommendations for specific check failures
    code_review_issues = components_by_issue.get("check:Code-Review", [])
    if code_review_issues:
        recommendations.append(
            Recommendation(
                type=RecommendationType.SUPPLY_CHAIN_RISK,
                priority=Priority.LOW,
                title="Dependencies with Limited Code Review",
                description=(
                    f"{len(set(code_review_issues))} packages have limited or no code review processes. "
                    "This increases the risk of unreviewed malicious or buggy changes."
                ),
                impact={"total": len(set(code_review_issues))},
                affected_components=list(set(code_review_issues))[:15],
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
