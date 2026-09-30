from collections import defaultdict
from typing import Any

from app.core.constants import CROSS_PROJECT_MIN_OCCURRENCES
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.aggregation.versions import newest_first
from app.services.component_identity import build_component_index, lookup_component
from app.services.recommendation.common import (
    ACTION_VERSION_SAMPLE,
    ModelOrDict,
    live_cves,
    get_attr,
    sample_components,
    sampled,
    scorecard_details,
    scorecard_score,
    severity_impact,
)

# Advisories named per risky package, and packages detailed in the replace action; each is
# paired with its population by `sampled` or by an explicit total.
_RISKY_PACKAGE_CVES_SAMPLED = 3
_RISKY_PACKAGES_SAMPLED = 10


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
        scorecard_by_component[component] = {
            "overall_score": scorecard_score(details),
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

        score = scorecard["overall_score"]
        is_unmaintained = scorecard["has_maintenance_issues"]

        # A score exists only where deps_dev flagged it under the project's own threshold.
        if severity in ["CRITICAL", "HIGH"] and (is_unmaintained or score is not None):
            high_risk_vulns.append(
                {
                    "component": component,
                    "version": get_attr(vf, "version"),
                    "vuln_severity": severity,
                    "scorecard_score": score,
                    "unmaintained": is_unmaintained,
                    **sampled("cves", live_cves([get_attr(vf, "details")]), _RISKY_PACKAGE_CVES_SAMPLED),
                    "project_url": scorecard.get("project_url"),
                }
            )

    if high_risk_vulns:
        high_risk_vulns.sort(
            key=lambda x: (not x["unmaintained"], x["scorecard_score"] is None, x["scorecard_score"] or 0.0)
        )

        risky_shown, risky_total = sample_components(
            f"{v['component']}@{v['version']} ("
            + ("no scorecard" if v["scorecard_score"] is None else f"score: {v['scorecard_score']:.1f}/10")
            + f"{', UNMAINTAINED' if v['unmaintained'] else ''})"
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
                    f"{low_score_count} are in packages flagged by OpenSSF Scorecard. "
                    "These vulnerabilities may never receive fixes."
                ),
                impact={
                    **severity_impact(v["vuln_severity"] for v in high_risk_vulns),
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
                            "cves_total": v["cves_total"],
                            "project_url": v["project_url"],
                        }
                        for v in high_risk_vulns[:_RISKY_PACKAGES_SAMPLED]
                    ],
                    "packages_total": len(high_risk_vulns),
                    "steps": [
                        "Find and migrate to actively maintained alternatives",
                        "If no alternative exists, evaluate forking the package",
                        "Implement additional security controls around these packages",
                        "Consider removing functionality that depends on these packages",
                        "Monitor for community forks that may have applied security fixes",
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
        for cve in proj["cves"]:
            cve_project_map[cve].append(proj["project_name"])
    return cve_project_map


# Projects named per shared CVE; total_affected carries the population.
_AFFECTED_PROJECTS_SAMPLED = 5
# Packages the two cross-project cards detail, paired with a packages_total.
_WIDESPREAD_CVES_SAMPLED = 5
_INCONSISTENT_PACKAGES_SAMPLED = 10
_SHARED_CVES_HIGH_PRIORITY = 5
_CRITICAL_RANK_WEIGHT = 10
_TOP_PROJECTS = 3
_TOP_PROJECT_CRITICAL_GATE = 5
_WIDE_VERSION_SPREAD = 2


def analyze_cross_project_patterns(cross_project_data: dict[str, Any]) -> list[Recommendation]:
    """Shared-CVE, version-inconsistency and most-affected-project cards across the user's projects."""
    projects = cross_project_data["projects"]
    if not projects:
        return []

    compared, total_projects = len(projects), cross_project_data["total_projects"]
    scope_note = (
        f"compared across {compared} of your {total_projects} projects"
        if compared < total_projects
        else f"compared across all {total_projects} of your projects"
    )
    cards = (
        _shared_vulnerability_card(projects, scope_note),
        _version_inconsistency_card(cross_project_data["shared_packages"], scope_note),
        _most_affected_projects_card(projects),
    )
    return [card for card in cards if card is not None]


def _shared_vulnerability_card(projects: list[dict[str, Any]], scope_note: str) -> Recommendation | None:
    widespread_cves = sorted(
        (
            (cve, proj_list)
            for cve, proj_list in _build_cve_project_map(projects).items()
            if len(proj_list) >= CROSS_PROJECT_MIN_OCCURRENCES
        ),
        key=lambda c: len(c[1]),
        reverse=True,
    )
    if not widespread_cves:
        return None

    widespread_shown, widespread_total = sample_components(
        f"{cve} ({len(proj_list)}/{len(projects)} projects compared)" for cve, proj_list in widespread_cves
    )
    return Recommendation(
        type=RecommendationType.SHARED_VULNERABILITY,
        priority=Priority.HIGH if len(widespread_cves) > _SHARED_CVES_HIGH_PRIORITY else Priority.MEDIUM,
        title=f"{len(widespread_cves)} vulnerabilities affect multiple projects",
        description=(
            f"These CVEs appear in {len(widespread_cves)} or more of your projects, {scope_note}. "
            "Fixing them once (e.g., in a shared package or template) "
            "could benefit all affected projects."
        ),
        impact={"critical": 0, "high": len(widespread_cves), "medium": 0, "low": 0, "total": len(widespread_cves)},
        affected_components=widespread_shown,
        affected_components_total=widespread_total,
        action={
            "type": "fix_cross_project_vuln",
            "cves": [
                {
                    "cve": cve,
                    "affected_projects": proj_list[:_AFFECTED_PROJECTS_SAMPLED],
                    "total_affected": len(proj_list),
                }
                for cve, proj_list in widespread_cves[:_WIDESPREAD_CVES_SAMPLED]
            ],
            "cves_total": len(widespread_cves),
            "suggestion": "Consider creating a shared fix or updating your project templates",
        },
        effort="medium",
    )


def _version_inconsistency_card(inconsistent_packages: list[dict[str, Any]], scope_note: str) -> Recommendation | None:
    # Counted and ordered by the cross-project package aggregation, which sees every dependency
    # row of every compared scan rather than a per-scan sample of them.
    if not inconsistent_packages:
        return None

    inconsistent_shown, inconsistent_total = sample_components(
        f"{p['name']}: {p['version_count']} versions across {p['project_count']} projects"
        for p in inconsistent_packages
    )
    wide = sum(1 for p in inconsistent_packages if p["version_count"] > _WIDE_VERSION_SPREAD)
    return Recommendation(
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
            "medium": wide,
            "low": len(inconsistent_packages) - wide,
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
                    "versions": newest_first(p["versions"])[:ACTION_VERSION_SAMPLE],
                    "version_count": p["version_count"],
                    "suggestion": newest_first(p["versions"])[0],
                    "project_count": p["project_count"],
                }
                for p in inconsistent_packages[:_INCONSISTENT_PACKAGES_SAMPLED]
            ],
            "packages_total": len(inconsistent_packages),
            "steps": [
                "Create a shared package.json or requirements.txt template",
                "Use a monorepo with shared dependencies",
                "Implement a dependency bot to keep versions aligned",
            ],
        },
        effort="medium",
    )


def _most_affected_projects_card(projects: list[dict[str, Any]]) -> Recommendation | None:
    if len(projects) < _TOP_PROJECTS:
        return None
    top_problematic = sorted(
        projects, key=lambda p: p["total_critical"] * _CRITICAL_RANK_WEIGHT + p["total_high"], reverse=True
    )[:_TOP_PROJECTS]
    if not any(p["total_critical"] > _TOP_PROJECT_CRITICAL_GATE for p in top_problematic):
        return None

    critical = sum(p["total_critical"] for p in top_problematic)
    high = sum(p["total_high"] for p in top_problematic)
    return Recommendation(
        type=RecommendationType.CROSS_PROJECT_PATTERN,
        priority=Priority.MEDIUM,
        title="Prioritize security fixes in most affected projects",
        description=(
            "Some projects have significantly more security findings "
            "than others. Consider prioritizing remediation efforts "
            "on these projects."
        ),
        impact={"critical": critical, "high": high, "medium": 0, "low": 0, "total": critical + high},
        affected_components=[
            f"{p['project_name']}: {p['total_critical']} critical, {p['total_high']} high" for p in top_problematic
        ],
        action={
            "type": "prioritize_projects",
            "priority_projects": [
                {
                    "name": p["project_name"],
                    "id": p["project_id"],
                    "critical": p["total_critical"],
                    "high": p["total_high"],
                }
                for p in top_problematic
            ],
        },
        effort="medium",
    )
