from collections import defaultdict
from typing import List, Dict, Any

from backend.app.schemas.recommendation import Recommendation, RecommendationType, Priority
from backend.app.services.recommendation.common import parse_version_tuple

def correlate_scorecard_with_vulnerabilities(
    vulnerability_findings: List[Dict[str, Any]],
    quality_findings: List[Dict[str, Any]],
) -> List[Recommendation]:
    """
    Correlate vulnerability findings with OpenSSF Scorecard quality data.

    Identifies high-risk situations where vulnerabilities exist in packages
    that also have poor maintenance or quality scores.
    """
    recommendations = []

    if not vulnerability_findings or not quality_findings:
        return recommendations

    # Build scorecard lookup by component
    scorecard_by_component = {}
    for qf in quality_findings:
        component = qf.get("component", "")
        if not component:
            continue
        scorecard_by_component[component] = {
            "overall_score": qf.get("details", {}).get("overall_score", 10),
            "critical_issues": qf.get("details", {}).get("critical_issues", []),
            "project_url": qf.get("details", {}).get("project_url"),
            "failed_checks": qf.get("details", {}).get("failed_checks", []),
        }

    # Find vulnerabilities in poorly maintained packages
    high_risk_vulns = []

    for vf in vulnerability_findings:
        component = vf.get("component", "")
        severity = vf.get("severity", "").upper()

        # Check if this component has scorecard data
        scorecard = scorecard_by_component.get(component)
        if not scorecard:
            continue

        score = scorecard.get("overall_score", 10)
        critical_issues = scorecard.get("critical_issues", [])
        is_unmaintained = "Maintained" in critical_issues

        # High risk: Critical/High vuln in unmaintained or low-score package
        if severity in ["CRITICAL", "HIGH"] and (is_unmaintained or score < 5.0):
            high_risk_vulns.append(
                {
                    "component": component,
                    "version": vf.get("version"),
                    "vuln_severity": severity,
                    "scorecard_score": score,
                    "unmaintained": is_unmaintained,
                    "cves": [
                        v.get("id")
                        for v in vf.get("details", {}).get("vulnerabilities", [])[
                            :3
                        ]
                    ],
                    "project_url": scorecard.get("project_url"),
                }
            )

    if high_risk_vulns:
        # Sort by risk (unmaintained first, then by score)
        high_risk_vulns.sort(
            key=lambda x: (not x["unmaintained"], x["scorecard_score"])
        )

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
                    f"{low_score_count} are in packages with scores below 5.0/10. "
                    "These vulnerabilities may never receive fixes."
                ),
                impact={
                    "critical": sum(
                        1
                        for v in high_risk_vulns
                        if v["vuln_severity"] == "CRITICAL"
                    ),
                    "high": sum(
                        1 for v in high_risk_vulns if v["vuln_severity"] == "HIGH"
                    ),
                    "medium": 0,
                    "low": 0,
                    "total": len(high_risk_vulns),
                    "unmaintained_count": unmaintained_count,
                },
                affected_components=[
                    f"{v['component']}@{v['version']} (score: {v['scorecard_score']:.1f}/10{', UNMAINTAINED' if v['unmaintained'] else ''})"
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
    current_findings: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
    cross_project_data: Dict[str, Any],
) -> List[Recommendation]:
    """
    Analyze patterns across multiple projects owned by the same user/team.

    cross_project_data structure:
    {
        "projects": [
            {
                "project_id": "...",
                "project_name": "...",
                "cves": ["CVE-2023-..."],
                "packages": [{"name": "lodash", "version": "4.17.20"}],
                "total_critical": 5,
                "total_high": 10
            },
            ...
        ],
        "total_projects": 5
    }
    """
    recommendations = []

    if not cross_project_data or not cross_project_data.get("projects"):
        return recommendations

    projects = cross_project_data["projects"]
    total_projects = cross_project_data.get("total_projects", len(projects))

    # ----------------------------------------------------------------
    # 1. Find CVEs that appear across multiple projects
    # ----------------------------------------------------------------
    cve_project_map = defaultdict(list)  # CVE -> list of project names

    for proj in projects:
        for cve in proj.get("cves", []):
            cve_project_map[cve].append(
                proj.get("project_name", proj.get("project_id"))
            )

    # CVEs affecting multiple projects
    widespread_cves = [
        {"cve": cve, "projects": proj_list, "count": len(proj_list)}
        for cve, proj_list in cve_project_map.items()
        if len(proj_list) >= 2
    ]

    if widespread_cves:
        widespread_cves.sort(key=lambda x: x["count"], reverse=True)

        recommendations.append(
            Recommendation(
                type=RecommendationType.SHARED_VULNERABILITY,
                priority=(
                    Priority.HIGH if len(widespread_cves) > 5 else Priority.MEDIUM
                ),
                title=f"{len(widespread_cves)} vulnerabilities affect multiple projects",
                description=f"These CVEs appear in {len(widespread_cves)} or more of your projects. Fixing them once (e.g., in a shared package or template) could benefit all affected projects.",
                impact={
                    "critical": 0,
                    "high": len(widespread_cves),
                    "medium": 0,
                    "low": 0,
                    "total": len(widespread_cves),
                },
                affected_components=[
                    f"{c['cve']} ({c['count']}/{total_projects} projects)"
                    for c in widespread_cves[:10]
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

    # ----------------------------------------------------------------
    # 2. Find packages used across many projects (standardization candidates)
    # ----------------------------------------------------------------
    package_usage = defaultdict(lambda: {"versions": set(), "projects": []})

    for proj in projects:
        for pkg in proj.get("packages", []):
            name = pkg.get("name", "").lower()
            if name:
                package_usage[name]["versions"].add(pkg.get("version", "unknown"))
                package_usage[name]["projects"].append(proj.get("project_name"))

    # Packages with multiple versions across projects
    inconsistent_packages = [
        {
            "name": name,
            "versions": list(data["versions"]),
            "project_count": len(set(data["projects"])),
            "version_count": len(data["versions"]),
        }
        for name, data in package_usage.items()
        if len(data["versions"]) > 1 and len(set(data["projects"])) >= 2
    ]

    if inconsistent_packages:
        # Sort by spread (how many different versions)
        inconsistent_packages.sort(key=lambda x: x["version_count"], reverse=True)

        recommendations.append(
            Recommendation(
                type=RecommendationType.CROSS_PROJECT_PATTERN,
                priority=Priority.LOW,
                title=f"Version inconsistency across {len(inconsistent_packages)} shared packages",
                description="These packages are used across multiple projects but with different versions. Standardizing versions can simplify maintenance and reduce security gaps.",
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": len(
                        [p for p in inconsistent_packages if p["version_count"] > 2]
                    ),
                    "low": len(
                        [
                            p
                            for p in inconsistent_packages
                            if p["version_count"] <= 2
                        ]
                    ),
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
                                p["versions"],
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

    # ----------------------------------------------------------------
    # 3. Identify organizational patterns (most problematic projects)
    # ----------------------------------------------------------------
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
                    description="Some projects have significantly more security findings than others. Consider prioritizing remediation efforts on these projects.",
                    impact={
                        "critical": sum(
                            p.get("total_critical", 0) for p in top_problematic
                        ),
                        "high": sum(
                            p.get("total_high", 0) for p in top_problematic
                        ),
                        "medium": 0,
                        "low": 0,
                        "total": sum(
                            p.get("total_critical", 0) + p.get("total_high", 0)
                            for p in top_problematic
                        ),
                    },
                    affected_components=[
                        f"{p.get('project_name', 'Unknown')}: {p.get('total_critical', 0)} critical, {p.get('total_high', 0)} high"
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
