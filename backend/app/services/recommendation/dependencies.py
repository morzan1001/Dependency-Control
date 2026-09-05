import re
from collections import defaultdict
from typing import Any

from app.core.constants import (
    DEV_DEPENDENCY_PATTERNS,
    SIGNIFICANT_FRAGMENTATION_THRESHOLD,
)
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.recommendation.common import (
    AFFECTED_COMPONENTS_SHOWN,
    ModelOrDict,
    get_attr,
    parse_version_tuple,
    sample_components,
)


def analyze_outdated_dependencies(
    dependencies: list[ModelOrDict],
) -> list[Recommendation]:
    """Identify dependencies the scanner marks outdated (having a latest_version)."""
    recommendations = []

    outdated_deps: list[dict[str, Any]] = []

    for dep in dependencies:
        name = str(get_attr(dep, "name", "")).lower()
        version = get_attr(dep, "version", "")
        latest_version = get_attr(dep, "latest_version")

        # python3-*, python-*, *-python are library packages, not the interpreter.
        if name.startswith(("python3-", "python-")) or name.endswith("-python"):
            continue

        if latest_version and latest_version != version:
            outdated_deps.append(
                {
                    "name": get_attr(dep, "name"),
                    "version": version,
                    "recommended_major": latest_version,
                    "message": f"Newer version {latest_version} is available",
                    "direct": get_attr(dep, "direct", False),
                }
            )

    direct_outdated = [d for d in outdated_deps if d.get("direct")]
    transitive_outdated = [d for d in outdated_deps if not d.get("direct")]
    transitive_shown, transitive_total = sample_components(f"{d['name']}@{d['version']}" for d in transitive_outdated)

    direct_shown, direct_total = sample_components(f"{d['name']}@{d['version']}" for d in direct_outdated)
    if direct_outdated:
        recommendations.append(
            Recommendation(
                type=RecommendationType.OUTDATED_DEPENDENCY,
                priority=Priority.MEDIUM,
                title=f"Upgrade {len(direct_outdated)} outdated direct dependencies",
                description=(
                    "Some direct dependencies are using significantly outdated major "
                    "versions. Upgrading can improve security, performance, and "
                    "maintainability."
                ),
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": len(direct_outdated),
                    "low": 0,
                    "total": len(direct_outdated),
                },
                affected_components=direct_shown,
                affected_components_total=direct_total,
                action={
                    "type": "upgrade_outdated",
                    "packages": [
                        {
                            "name": d["name"],
                            "current": d["version"],
                            "recommended_major": d["recommended_major"],
                            "reason": d["message"],
                        }
                        for d in direct_outdated
                    ],
                },
                effort="medium",
            )
        )

    if len(transitive_outdated) > SIGNIFICANT_FRAGMENTATION_THRESHOLD:
        recommendations.append(
            Recommendation(
                type=RecommendationType.OUTDATED_DEPENDENCY,
                priority=Priority.LOW,
                title=f"{len(transitive_outdated)} transitive dependencies are outdated",
                description=(
                    "Several transitive dependencies use old major versions. "
                    "Updating parent packages may resolve these."
                ),
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": len(transitive_outdated),
                    "total": len(transitive_outdated),
                },
                affected_components=transitive_shown,
                affected_components_total=transitive_total,
                action={
                    "type": "review_transitive",
                    "suggestion": "Update direct dependencies to pull in newer transitive versions",
                },
                effort="low",
            )
        )

    return recommendations


def analyze_version_fragmentation(
    dependencies: list[ModelOrDict],
) -> list[Recommendation]:
    """Detect multiple versions of the same package in the dependency tree."""
    recommendations = []

    deps_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for dep in dependencies:
        name = str(get_attr(dep, "name", "")).lower()
        if name:
            deps_by_name[name].append(
                {
                    "version": get_attr(dep, "version", "unknown"),
                    "purl": get_attr(dep, "purl"),
                    "direct": get_attr(dep, "direct", False),
                    "parent": get_attr(dep, "parent_components", []),
                }
            )

    fragmented: list[dict[str, Any]] = []
    for name, versions in deps_by_name.items():
        unique_versions = {v["version"] for v in versions}
        if len(unique_versions) > 1:
            fragmented.append(
                {
                    "name": name,
                    "versions": list(unique_versions),
                    "count": len(unique_versions),
                    "has_direct": any(v["direct"] for v in versions),
                }
            )

    fragmented.sort(key=lambda x: x["count"], reverse=True)

    significant_fragmented = [f for f in fragmented if f["count"] >= SIGNIFICANT_FRAGMENTATION_THRESHOLD]

    if significant_fragmented:
        priority = (
            Priority.MEDIUM if len(significant_fragmented) > SIGNIFICANT_FRAGMENTATION_THRESHOLD else Priority.LOW
        )

        fragmented_shown, fragmented_total = sample_components(
            f"{f['name']} ({f['count']} versions)" for f in significant_fragmented
        )
        top_fragmented = significant_fragmented[:AFFECTED_COMPONENTS_SHOWN]

        recommendations.append(
            Recommendation(
                type=RecommendationType.VERSION_FRAGMENTATION,
                priority=priority,
                title=(
                    f"Version fragmentation in {len(significant_fragmented)} packages "
                    f"({sum(f['count'] for f in significant_fragmented)} total versions)"
                ),
                description=(
                    f"These packages have {SIGNIFICANT_FRAGMENTATION_THRESHOLD} or more "
                    "versions in your dependency tree. This can increase bundle size "
                    "and cause subtle bugs. Consider deduplication or pinning to a "
                    "single version."
                ),
                impact={
                    "critical": 0,
                    "high": len([f for f in significant_fragmented if f["count"] >= 5]),
                    "medium": len(
                        [f for f in significant_fragmented if SIGNIFICANT_FRAGMENTATION_THRESHOLD <= f["count"] < 5]
                    ),
                    "low": 0,
                    "total": len(significant_fragmented),
                },
                affected_components=fragmented_shown,
                affected_components_total=fragmented_total,
                action={
                    "type": "deduplicate_versions",
                    "packages": [
                        {
                            "name": f["name"],
                            "versions": f["versions"][:5],
                            "version_count": f["count"],
                            "suggestion": f"Pin to {max(f['versions'], key=lambda v: parse_version_tuple(v))}",
                        }
                        for f in top_fragmented
                    ],
                    "commands": [
                        "# For npm: npm dedupe",
                        "# For yarn: yarn dedupe",
                        "# For pnpm: pnpm dedupe",
                    ],
                },
                effort="low",
            )
        )

    return recommendations


def analyze_dev_in_production(
    dependencies: list[ModelOrDict],
) -> list[Recommendation]:
    """
    Identify development dependencies that may be included in production builds.
    """
    recommendations = []

    potential_dev_deps: list[dict[str, Any]] = []

    for dep in dependencies:
        name = str(get_attr(dep, "name") or "").lower()
        scope = str(get_attr(dep, "scope") or "").lower()

        if scope in ("dev", "development", "test"):
            continue

        for pattern in DEV_DEPENDENCY_PATTERNS:
            if re.search(pattern, name, re.IGNORECASE):
                potential_dev_deps.append(
                    {
                        "name": get_attr(dep, "name"),
                        "version": get_attr(dep, "version"),
                        "reason": f"Matches dev pattern: {pattern}",
                    }
                )
                break

    dev_deps_shown, dev_deps_total = sample_components(f"{d['name']}@{d['version']}" for d in potential_dev_deps)
    if potential_dev_deps:
        recommendations.append(
            Recommendation(
                type=RecommendationType.DEV_IN_PRODUCTION,
                priority=Priority.LOW,
                title=f"{len(potential_dev_deps)} potential dev dependencies in production",
                description=(
                    "Some packages typically used for development/testing were detected "
                    "in your build. If these are in your production bundle, consider "
                    "moving them to devDependencies."
                ),
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": len(potential_dev_deps),
                    "total": len(potential_dev_deps),
                },
                affected_components=dev_deps_shown,
                affected_components_total=dev_deps_total,
                action={
                    "type": "review_dev_deps",
                    "packages": [d["name"] for d in potential_dev_deps],
                    "suggestion": "Review if these packages should be moved to devDependencies",
                },
                effort="low",
            )
        )

    return recommendations


def analyze_end_of_life(eol_findings: list[ModelOrDict]) -> list[Recommendation]:
    """Process end-of-life dependency findings."""
    if not eol_findings:
        return []

    affected_packages = []
    for f in eol_findings:
        pkg = get_attr(f, "component", "")
        version = get_attr(f, "version", "")
        details = get_attr(f, "details", {})
        eol_date = details.get("eol_date", "") if isinstance(details, dict) else ""
        if eol_date:
            affected_packages.append(f"{pkg}@{version} (EOL: {eol_date})")
        else:
            affected_packages.append(f"{pkg}@{version}")

    eol_shown, eol_total = sample_components(affected_packages)
    critical_count = len([f for f in eol_findings if get_attr(f, "severity") == "CRITICAL"])
    high_count = len([f for f in eol_findings if get_attr(f, "severity") == "HIGH"])

    priority = Priority.HIGH if critical_count > 0 else Priority.MEDIUM

    return [
        Recommendation(
            type=RecommendationType.EOL_DEPENDENCY,
            priority=priority,
            title="End-of-Life Dependencies",
            description=(
                f"Found {len(eol_findings)} dependencies that have reached end-of-life. "
                f"These will no longer receive security updates, leaving your application vulnerable "
                f"to future CVEs that will never be patched."
            ),
            impact={
                "critical": critical_count,
                "high": high_count,
                "medium": len([f for f in eol_findings if get_attr(f, "severity") == "MEDIUM"]),
                "low": len([f for f in eol_findings if get_attr(f, "severity") == "LOW"]),
                "total": len(eol_findings),
            },
            affected_components=eol_shown,
            affected_components_total=eol_total,
            action={
                "type": "upgrade_eol",
                "packages": affected_packages,
                "steps": [
                    "1. Identify supported versions for each EOL dependency",
                    "2. Review migration guides for major version upgrades",
                    "3. Plan and execute upgrades",
                    "4. For frameworks (Node.js, Python, Java), plan runtime upgrades",
                    "5. Update CI/CD pipelines for new versions",
                ],
            },
            effort="high",
        )
    ]
