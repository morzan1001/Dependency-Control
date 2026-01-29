from collections import defaultdict
from typing import Any, Dict, List

from app.core.constants import QUICK_WIN_SCORING_WEIGHTS
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.recommendation.common import calculate_best_fix_version, get_attr, ModelOrDict


def identify_quick_wins(
    vuln_findings: List[ModelOrDict],
    dependencies: List[ModelOrDict],
) -> List[Recommendation]:
    """
    Identify quick wins - updates that fix many issues with minimal effort.

    Quick wins are:
    - Direct dependencies (easy to update)
    - Have a fixed version available
    - Fix multiple vulnerabilities
    - Or fix critical/KEV vulnerabilities
    """
    recommendations = []

    # Group vulnerabilities by package
    vulns_by_package: Dict[str, List[Dict]] = defaultdict(list)
    for f in vuln_findings:
        component = get_attr(f, "component", "")
        details = get_attr(f, "details", {})
        if component and isinstance(details, dict) and details.get("fixed_version"):
            vulns_by_package[component].append(f)

    # Create a set of direct dependencies
    direct_deps = set()
    for dep in dependencies:
        if get_attr(dep, "direct", False):
            direct_deps.add(get_attr(dep, "name", ""))

    # Find packages where one update fixes multiple issues
    quick_wins = []
    for pkg, vulns in vulns_by_package.items():
        if len(vulns) < 2:
            continue

        # Get all fixed versions
        fixed_versions = []
        for v in vulns:
            v_details = get_attr(v, "details", {})
            if isinstance(v_details, dict) and v_details.get("fixed_version"):
                fixed_versions.append(v_details.get("fixed_version"))
        fixed_versions = list(set(fixed_versions))

        if not fixed_versions:
            continue

        # Calculate impact
        critical_count = len([v for v in vulns if get_attr(v, "severity") == "CRITICAL"])
        high_count = len([v for v in vulns if get_attr(v, "severity") == "HIGH"])
        kev_count = 0
        for v in vulns:
            v_details = get_attr(v, "details", {})
            if isinstance(v_details, dict) and v_details.get("is_kev"):
                kev_count += 1

        is_direct = pkg in direct_deps

        # Score the quick win
        score = (
            len(vulns) * QUICK_WIN_SCORING_WEIGHTS["base_per_vuln"]
            + critical_count * QUICK_WIN_SCORING_WEIGHTS["critical"]
            + high_count * QUICK_WIN_SCORING_WEIGHTS["high"]
            + kev_count * QUICK_WIN_SCORING_WEIGHTS["kev"]
            + (QUICK_WIN_SCORING_WEIGHTS["direct_dep_bonus"] if is_direct else 0)
        )

        quick_wins.append(
            {
                "package": pkg,
                "version": get_attr(vulns[0], "version", "unknown"),
                "fixed_version": calculate_best_fix_version(fixed_versions),
                "vuln_count": len(vulns),
                "critical_count": critical_count,
                "high_count": high_count,
                "kev_count": kev_count,
                "is_direct": is_direct,
                "score": score,
            }
        )

    # Sort by score and take top quick wins
    quick_wins.sort(key=lambda x: x["score"], reverse=True)

    for qw in quick_wins[:5]:  # Top 5 quick wins
        if qw["vuln_count"] < 2 and qw["kev_count"] == 0:
            continue

        dep_type = "direct dependency" if qw["is_direct"] else "transitive dependency"

        recommendations.append(
            Recommendation(
                type=(
                    RecommendationType.SINGLE_UPDATE_MULTI_FIX
                    if qw["vuln_count"] >= 3
                    else RecommendationType.QUICK_WIN
                ),
                priority=(
                    Priority.HIGH
                    if qw["kev_count"] > 0 or qw["critical_count"] > 0
                    else Priority.MEDIUM
                ),
                title=f"Quick Win: Update {qw['package']}",
                description=(
                    f"Updating this {dep_type} from {qw['version']} to {qw['fixed_version']} "
                    f"will fix {qw['vuln_count']} vulnerabilities in a single update! "
                    f"({qw['critical_count']} critical, {qw['high_count']} high)"
                ),
                impact={
                    "critical": qw["critical_count"],
                    "high": qw["high_count"],
                    "medium": qw["vuln_count"]
                    - qw["critical_count"]
                    - qw["high_count"],
                    "low": 0,
                    "total": qw["vuln_count"],
                    "kev_count": qw["kev_count"],
                },
                affected_components=[f"{qw['package']}@{qw['version']}"],
                action={
                    "type": "quick_win_update",
                    "package": qw["package"],
                    "current_version": qw["version"],
                    "target_version": qw["fixed_version"],
                    "is_direct": qw["is_direct"],
                    "fixes_count": qw["vuln_count"],
                },
                effort="low",
            )
        )

    return recommendations
