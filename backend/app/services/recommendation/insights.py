from collections import defaultdict
from typing import Any, cast

from app.core.constants import (
    CROSS_PROJECT_MIN_OCCURRENCES,
    SCORECARD_UNMAINTAINED_THRESHOLD,
)
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.aggregation.components import build_component_index, lookup_component
from app.services.recommendation.common import (
    ModelOrDict,
    get_attr,
    parse_version_tuple,
    sample_components,
    scorecard_details,
)


def correlate_scorecard_with_vulnerabilities(
    vulnerability_findings: list[ModelOrDict],
    quality_findings: list[ModelOrDict],
) -> list[Recommendation]:
    """Flag vulnerabilities in packages that also have poor OpenSSF Scorecard ratings."""
    recommendations: list[Recommendation] = []

    if not vulnerability_findings or not quality_findings:
        return recommendations

    scorecard_by_component: dict[str, dict[str, Any]] = {}
    for qf in quality_findings:
        component = get_attr(qf, "component", "")
        if not component:
            continue
        details = get_attr(qf, "details", {})
        sc_details = scorecard_details(details)
        overall_score = details.get("overall_score") if isinstance(details, dict) else None
        scorecard_by_component[component] = {
            "overall_score": overall_score if overall_score is not None else 10,
            "critical_issues": sc_details.get("critical_issues") or [],
            "project_url": sc_details.get("project_url"),
            "has_maintenance_issues": bool(details.get("has_maintenance_issues"))
            if isinstance(details, dict)
            else False,
        }

    # Quality findings keep the inventory name while a vulnerability component is group-qualified.
    scorecard_index = build_component_index(scorecard_by_component)

    high_risk_vulns: list[dict[str, Any]] = []

    for vf in vulnerability_findings:
        component = get_attr(vf, "component", "")
        severity = str(get_attr(vf, "severity", "")).upper()

        scorecard = lookup_component(scorecard_index, component)
        if not scorecard:
            continue

        score = scorecard.get("overall_score", 10)
        critical_issues = scorecard.get("critical_issues", [])
        is_unmaintained = "Maintained" in critical_issues or scorecard.get("has_maintenance_issues", False)

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
        high_risk_vulns.sort(key=lambda x: (not x["unmaintained"], x["scorecard_score"]))

        risky_shown, risky_total = sample_components(
            f"{v['component']}@{v['version']} (score: {v['scorecard_score']:.1f}/10"
            f"{', UNMAINTAINED' if v['unmaintained'] else ''})"
            for v in high_risk_vulns
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
                affected_components=risky_shown,
                affected_components_total=risky_total,
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


def _build_cve_project_map(projects: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Build a mapping of CVE -> list of project names from cross-project data."""
    cve_project_map: dict[str, list[str]] = defaultdict(list)
    for proj in projects:
        for cve in proj.get("cves", []):
            cve_project_map[cve].append(str(proj.get("project_name", proj.get("project_id", ""))))
    return cve_project_map


# Versions named per package in the standardize_versions action; version_count carries the total.
_ACTION_VERSION_SAMPLE = 5


def _newest_first(versions: list[Any]) -> list[str]:
    return sorted((str(v) for v in versions), key=parse_version_tuple, reverse=True)


def analyze_cross_project_patterns(
    _current_findings: list[ModelOrDict],
    dependencies: list[ModelOrDict],
    cross_project_data: dict[str, Any],
) -> list[Recommendation]:
    """Analyze patterns across multiple projects owned by the same user/team."""
    recommendations: list[Recommendation] = []

    if not cross_project_data or not cross_project_data.get("projects"):
        return recommendations

    projects = cross_project_data["projects"]
    total_projects = cross_project_data.get("total_projects", len(projects))
    # The comparison covers the projects that were read, not every project the user can see.
    compared = cross_project_data.get("projects_compared", len(projects))
    scope_note = (
        f"compared across {compared} of your {total_projects} projects"
        if compared < total_projects
        else f"compared across all {total_projects} of your projects"
    )

    cve_project_map = _build_cve_project_map(projects)

    widespread_cves = [
        {"cve": cve, "projects": proj_list, "count": len(proj_list)}
        for cve, proj_list in cve_project_map.items()
        if len(proj_list) >= CROSS_PROJECT_MIN_OCCURRENCES
    ]

    if widespread_cves:
        widespread_cves.sort(key=lambda x: cast(int, x["count"]), reverse=True)
        widespread_shown, widespread_total = sample_components(
            f"{c['cve']} ({c['count']}/{compared} projects compared)" for c in widespread_cves
        )

        recommendations.append(
            Recommendation(
                type=RecommendationType.SHARED_VULNERABILITY,
                priority=(Priority.HIGH if len(widespread_cves) > 5 else Priority.MEDIUM),
                title=f"{len(widespread_cves)} vulnerabilities affect multiple projects",
                description=(
                    f"These CVEs appear in {len(widespread_cves)} or more of your projects, {scope_note}. "
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
                affected_components=widespread_shown,
                affected_components_total=widespread_total,
                action={
                    "type": "fix_cross_project_vuln",
                    "cves": [
                        {
                            "cve": c["cve"],
                            "affected_projects": cast(list, c["projects"])[:5],
                            "total_affected": c["count"],
                        }
                        for c in widespread_cves[:5]
                    ],
                    "suggestion": "Consider creating a shared fix or updating your project templates",
                },
                effort="medium",
            )
        )

    # Counted and ordered by the cross-project package aggregation, which sees every dependency
    # row of every compared scan rather than a per-scan sample of them.
    inconsistent_packages: list[dict[str, Any]] = cross_project_data.get("shared_packages") or []

    inconsistent_shown, inconsistent_total = sample_components(
        f"{p['name']}: {p['version_count']} versions across {p['project_count']} projects"
        for p in inconsistent_packages
    )
    if inconsistent_packages:
        recommendations.append(
            Recommendation(
                type=RecommendationType.CROSS_PROJECT_PATTERN,
                priority=Priority.LOW,
                title=f"Version inconsistency across {len(inconsistent_packages)} shared packages",
                description=(
                    f"These packages are used across multiple projects but with "
                    f"different versions, {scope_note}. Standardizing versions can simplify "
                    "maintenance and reduce security gaps."
                ),
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": len([p for p in inconsistent_packages if int(cast(int, p["version_count"])) > 2]),
                    "low": len([p for p in inconsistent_packages if int(cast(int, p["version_count"])) <= 2]),
                    "total": len(inconsistent_packages),
                },
                affected_components=inconsistent_shown,
                affected_components_total=inconsistent_total,
                action={
                    "type": "standardize_versions",
                    "packages": [
                        {
                            "name": p["name"],
                            # $addToSet has no order, so rank before sampling: the newest versions
                            # are the ones a reader standardising on one needs to see.
                            "versions": _newest_first(p["versions"])[:_ACTION_VERSION_SAMPLE],
                            "version_count": p["version_count"],
                            "suggestion": _newest_first(p["versions"])[0],
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
        key=lambda p: p.get("total_critical", 0) * 10 + p.get("total_high", 0),
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
