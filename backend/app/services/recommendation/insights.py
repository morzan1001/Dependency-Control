from collections import defaultdict
from typing import Any, Dict, List, cast

from app.core.constants import (
    CROSS_PROJECT_MIN_OCCURRENCES,
    SCORECARD_UNMAINTAINED_THRESHOLD,
)
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.recommendation.common import get_attr, ModelOrDict, parse_version_tuple


def correlate_scorecard_with_vulnerabilities(
    vulnerability_findings: List[ModelOrDict],
    quality_findings: List[ModelOrDict],
) -> List[Recommendation]:
    """
    Correlate vulnerability findings with OpenSSF Scorecard quality data.

    Identifies high-risk situations where vulnerabilities exist in packages
    that also have poor maintenance or quality scores.
    """
    recommendations: List[Recommendation] = []

    if not vulnerability_findings or not quality_findings:
        return recommendations

    # Build scorecard lookup by component
    scorecard_by_component = {}
    for qf in quality_findings:
        component = get_attr(qf, "component", "")
        if not component:
            continue
        details = get_attr(qf, "details", {})
        scorecard_by_component[component] = {
            "overall_score": details.get("overall_score", 10) if isinstance(details, dict) else 10,
            "critical_issues": details.get("critical_issues", []) if isinstance(details, dict) else [],
            "project_url": details.get("project_url") if isinstance(details, dict) else None,
            "failed_checks": details.get("failed_checks", []) if isinstance(details, dict) else [],
        }

    # Find vulnerabilities in poorly maintained packages
    high_risk_vulns = []

    for vf in vulnerability_findings:
        component = get_attr(vf, "component", "")
        severity = str(get_attr(vf, "severity", "")).upper()

        # Check if this component has scorecard data
        scorecard = scorecard_by_component.get(component)
        if not scorecard:
            continue

        score = scorecard.get("overall_score", 10)
        critical_issues = scorecard.get("critical_issues", [])
        is_unmaintained = "Maintained" in critical_issues

        # High risk: Critical/High vuln in unmaintained or low-score package
        if severity in ["CRITICAL", "HIGH"] and (is_unmaintained or score < SCORECARD_UNMAINTAINED_THRESHOLD):
            vf_details = get_attr(vf, "details", {})
            high_risk_vulns.append(
                {
                    "component": component,
                    "version": get_attr(vf, "version"),
                    "vuln_severity": severity,
                    "scorecard_score": score,
                    "unmaintained": is_unmaintained,
                    "cves": [
                        v.get("id")
                        for v in (vf_details.get("vulnerabilities", []) if isinstance(vf_details, dict) else [])[:3]
                    ],
                    "project_url": scorecard.get("project_url"),
                }
            )

    if high_risk_vulns:
        # Sort by risk (unmaintained first, then by score)
        high_risk_vulns.sort(key=lambda x: (not x["unmaintained"], x["scorecard_score"]))

        unmaintained_count = sum(1 for v in high_risk_vulns if v["unmaintained"])
        low_score_count = len(high_risk_vulns) - unmaintained_count

        recommendations.append(
            Recommendation(
                type=RecommendationType.CRITICAL_RISK,
                priority=Priority.CRITICAL,
                title="Critical Vulnerabilities in Poorly Maintained Packages",
                description=(
                    f"Found {len(high_risk_vulns)} critical/high vulnerabilities in packages "
                    f"with concerning OpenSSF Scorecard ratings. "
                    f"{unmaintained_count} are in unmaintained packages, "
                    f"{low_score_count} are in packages with scores below {SCORECARD_UNMAINTAINED_THRESHOLD}/10. "
                    "These vulnerabilities may never receive fixes."
                ),
                impact={
                    "critical": sum(1 for v in high_risk_vulns if v["vuln_severity"] == "CRITICAL"),
                    "high": sum(1 for v in high_risk_vulns if v["vuln_severity"] == "HIGH"),
                    "medium": 0,
                    "low": 0,
                    "total": len(high_risk_vulns),
                    "unmaintained_count": unmaintained_count,
                },
                affected_components=[
                    (
                        f"{v['component']}@{v['version']} "
                        f"(score: {v['scorecard_score']:.1f}/10"
                        f"{', UNMAINTAINED' if v['unmaintained'] else ''})"
                    )
                    for v in high_risk_vulns[:10]
                ],
                action={
                    "type": "replace_risky_packages",
                    "packages": [
                        {
                            "name": v["component"],
                            "version": v["version"],
                            "scorecard_score": v["scorecard_score"],
                            "unmaintained": v["unmaintained"],
                            "cves": v["cves"],
                            "project_url": v["project_url"],
                        }
                        for v in high_risk_vulns[:10]
                    ],
                    "steps": [
                        "1. PRIORITY: Find and migrate to actively maintained alternatives",
                        "2. If no alternative exists, evaluate forking the package",
                        "3. Implement additional security controls around these packages",
                        "4. Consider removing functionality that depends on these packages",
                        "5. Monitor for community forks that may have applied security fixes",
                    ],
                },
                effort="high",
            )
        )

    return recommendations


def analyze_cross_project_patterns(
    current_findings: List[ModelOrDict],
    dependencies: List[ModelOrDict],
    cross_project_data: Dict[str, Any],
) -> List[Recommendation]:
    """
    Analyze patterns across multiple projects owned by the same user/team.
    """
    recommendations: List[Recommendation] = []

    if not cross_project_data or not cross_project_data.get("projects"):
        return recommendations

    projects = cross_project_data["projects"]
    total_projects = cross_project_data.get("total_projects", len(projects))

    cve_project_map = defaultdict(list)  # CVE -> list of project names

    for proj in projects:
        for cve in proj.get("cves", []):
            cve_project_map[cve].append(proj.get("project_name", proj.get("project_id")))

    # CVEs affecting multiple projects
    widespread_cves = [
        {"cve": cve, "projects": proj_list, "count": len(proj_list)}
        for cve, proj_list in cve_project_map.items()
        if len(proj_list) >= CROSS_PROJECT_MIN_OCCURRENCES
    ]

    if widespread_cves:
        widespread_cves.sort(key=lambda x: x["count"], reverse=True)

        recommendations.append(
            Recommendation(
                type=RecommendationType.SHARED_VULNERABILITY,
                priority=(Priority.HIGH if len(widespread_cves) > 5 else Priority.MEDIUM),
                title=f"{len(widespread_cves)} vulnerabilities affect multiple projects",
                description=(
                    f"These CVEs appear in {len(widespread_cves)} or more of your projects. "
                    "Fixing them once (e.g., in a shared package or template) "
                    "could benefit all affected projects."
                ),
                impact={
                    "critical": 0,
                    "high": len(widespread_cves),
                    "medium": 0,
                    "low": 0,
                    "total": len(widespread_cves),
                },
                affected_components=[
                    f"{c['cve']} ({c['count']}/{total_projects} projects)" for c in widespread_cves[:10]
                ],
                action={
                    "type": "fix_cross_project_vuln",
                    "cves": [
                        {
                            "cve": c["cve"],
                            "affected_projects": c["projects"][:5],
                            "total_affected": c["count"],
                        }
                        for c in widespread_cves[:5]
                    ],
                    "suggestion": "Consider creating a shared fix or updating your project templates",
                },
                effort="medium",
            )
        )

    package_usage: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"versions": set(), "projects": []})

    for proj in projects:
        for pkg in proj.get("packages", []):
            name = pkg.get("name", "").lower()
            if name:
                cast(set, package_usage[name]["versions"]).add(pkg.get("version", "unknown"))
                cast(list, package_usage[name]["projects"]).append(proj.get("project_name"))

    # Packages with multiple versions across projects
    inconsistent_packages = [
        {
            "name": name,
            "versions": list(data["versions"]),
            "project_count": len(set(data["projects"])),
            "version_count": len(data["versions"]),
        }
        for name, data in package_usage.items()
        if len(data["versions"]) > 1 and len(set(data["projects"])) >= CROSS_PROJECT_MIN_OCCURRENCES
    ]

    if inconsistent_packages:
        # Sort by spread (how many different versions)
        inconsistent_packages.sort(key=lambda x: int(cast(int, x["version_count"])), reverse=True)

        recommendations.append(
            Recommendation(
                type=RecommendationType.CROSS_PROJECT_PATTERN,
                priority=Priority.LOW,
                title=f"Version inconsistency across {len(inconsistent_packages)} shared packages",
                description=(
                    "These packages are used across multiple projects but with "
                    "different versions. Standardizing versions can simplify "
                    "maintenance and reduce security gaps."
                ),
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": len([p for p in inconsistent_packages if int(cast(int, p["version_count"])) > 2]),
                    "low": len([p for p in inconsistent_packages if int(cast(int, p["version_count"])) <= 2]),
                    "total": len(inconsistent_packages),
                },
                affected_components=[
                    f"{p['name']}: {len(p['versions'])} versions across {p['project_count']} projects"
                    for p in inconsistent_packages[:10]
                ],
                action={
                    "type": "standardize_versions",
                    "packages": [
                        {
                            "name": p["name"],
                            "versions": p["versions"][:5],
                            "suggestion": max(
                                (str(v) for v in p["versions"]),
                                key=lambda v: parse_version_tuple(v),
                            ),
                            "project_count": p["project_count"],
                        }
                        for p in inconsistent_packages[:10]
                    ],
                    "suggestions": [
                        "Create a shared package.json or requirements.txt template",
                        "Use a monorepo with shared dependencies",
                        "Implement a dependency bot to keep versions aligned",
                    ],
                },
                effort="medium",
            )
        )

    projects_by_severity = sorted(
        projects,
        key=lambda p: (p.get("total_critical", 0) * 10 + p.get("total_high", 0)),
        reverse=True,
    )

    if len(projects_by_severity) >= 3:
        top_problematic = projects_by_severity[:3]
        if any(p.get("total_critical", 0) > 5 for p in top_problematic):
            recommendations.append(
                Recommendation(
                    type=RecommendationType.CROSS_PROJECT_PATTERN,
                    priority=Priority.MEDIUM,
                    title="Prioritize security fixes in most affected projects",
                    description=(
                        "Some projects have significantly more security findings "
                        "than others. Consider prioritizing remediation efforts "
                        "on these projects."
                    ),
                    impact={
                        "critical": sum(p.get("total_critical", 0) for p in top_problematic),
                        "high": sum(p.get("total_high", 0) for p in top_problematic),
                        "medium": 0,
                        "low": 0,
                        "total": sum(p.get("total_critical", 0) + p.get("total_high", 0) for p in top_problematic),
                    },
                    affected_components=[
                        (
                            f"{p.get('project_name', 'Unknown')}: "
                            f"{p.get('total_critical', 0)} critical, "
                            f"{p.get('total_high', 0)} high"
                        )
                        for p in top_problematic
                    ],
                    action={
                        "type": "prioritize_projects",
                        "priority_projects": [
                            {
                                "name": p.get("project_name"),
                                "id": p.get("project_id"),
                                "critical": p.get("total_critical", 0),
                                "high": p.get("total_high", 0),
                            }
                            for p in top_problematic
                        ],
                    },
                    effort="medium",
                )
            )

    return recommendations
