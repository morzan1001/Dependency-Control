from collections import defaultdict
from typing import Any

from app.core.constants import (
    DEV_DEPENDENCY_PATTERN,
    DEV_DEPENDENCY_RUNTIME_PACKAGES,
    NON_RUNTIME_SCOPES,
)
from app.core.purl import package_identity
from app.schemas.recommendation import (
    Effort,
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.aggregation.versions import newest_first
from app.services.recommendation.common import (
    ACTION_VERSION_SAMPLE,
    AFFECTED_COMPONENTS_SHOWN,
    ModelOrDict,
    get_attr,
    sample_components,
    sampled,
    severity_impact,
)

# A package held at this many versions is fragmented.
_FRAGMENTATION_MIN_VERSIONS = 3
# Fragmented packages that must be exceeded for a MEDIUM card.
_FRAGMENTED_PACKAGES_FOR_MEDIUM = 3


def analyze_version_fragmentation(
    dependencies: list[ModelOrDict],
) -> list[Recommendation]:
    """Detect multiple versions of the same package in the dependency tree."""
    recommendations = []

    versions_by_package: dict[tuple[str, str], set[str]] = defaultdict(set)
    for dep in dependencies:
        identity = package_identity(
            get_attr(dep, "purl"), get_attr(dep, "name"), get_attr(dep, "type"), get_attr(dep, "group")
        )
        versions_by_package[identity].add(get_attr(dep, "version"))

    significant_fragmented: list[dict[str, Any]] = sorted(
        (
            {"name": name, "versions": list(versions), "count": len(versions)}
            for (_, name), versions in versions_by_package.items()
            if len(versions) >= _FRAGMENTATION_MIN_VERSIONS
        ),
        key=lambda x: x["count"],
        reverse=True,
    )

    if significant_fragmented:
        priority = Priority.MEDIUM if len(significant_fragmented) > _FRAGMENTED_PACKAGES_FOR_MEDIUM else Priority.LOW

        fragmented_shown, fragmented_total = sample_components(f["name"] for f in significant_fragmented)

        recommendations.append(
            Recommendation(
                type=RecommendationType.VERSION_FRAGMENTATION,
                priority=priority,
                title=(
                    f"Version fragmentation in {len(significant_fragmented)} packages "
                    f"({sum(f['count'] for f in significant_fragmented)} total versions)"
                ),
                description=(
                    f"These packages have {_FRAGMENTATION_MIN_VERSIONS} or more "
                    "versions in your dependency tree. This can increase bundle size "
                    "and cause subtle bugs. Consider deduplication or pinning to a "
                    "single version."
                ),
                impact={"total": 0},
                affected_components=fragmented_shown,
                affected_components_total=fragmented_total,
                action={
                    "type": "deduplicate_versions",
                    **sampled(
                        "packages",
                        [
                            {
                                "name": f["name"],
                                # Sets are unordered; rank first so the sample shows the newest versions.
                                "versions": newest_first(f["versions"])[:ACTION_VERSION_SAMPLE],
                                "version_count": f["count"],
                                "suggestion": f"Pin to {newest_first(f['versions'])[0]}",
                            }
                            for f in significant_fragmented
                        ],
                        AFFECTED_COMPONENTS_SHOWN,
                    ),
                    "commands": [
                        "# For npm: npm dedupe",
                        "# For yarn: yarn dedupe",
                        "# For pnpm: pnpm dedupe",
                    ],
                },
                effort=Effort.LOW,
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
        scope = str(get_attr(dep, "scope") or "").lower()
        if scope in NON_RUNTIME_SCOPES:
            continue

        # The qualified name, so a dev-only scope matches where the SBOM split it into group and name.
        ecosystem, name = package_identity(
            get_attr(dep, "purl"), get_attr(dep, "name") or "", get_attr(dep, "type"), get_attr(dep, "group")
        )
        # The patterns and the devDependencies advice are npm's.
        if ecosystem != "npm":
            continue
        if name.lower() not in DEV_DEPENDENCY_RUNTIME_PACKAGES and DEV_DEPENDENCY_PATTERN.match(name.lower()):
            potential_dev_deps.append({"name": name, "version": get_attr(dep, "version")})

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
                impact={"total": 0},
                affected_components=dev_deps_shown,
                affected_components_total=dev_deps_total,
                action={
                    "type": "review_dev_deps",
                    **sampled(
                        "packages",
                        list(dict.fromkeys(d["name"] for d in potential_dev_deps)),
                        AFFECTED_COMPONENTS_SHOWN,
                    ),
                    "suggestion": "Review if these packages should be moved to devDependencies",
                },
                effort=Effort.LOW,
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
        eol_date = details.get("eol_date", "")
        if eol_date:
            affected_packages.append(f"{pkg}@{version} (EOL: {eol_date})")
        else:
            affected_packages.append(f"{pkg}@{version}")

    eol_shown, eol_total = sample_components(affected_packages)
    impact = severity_impact(get_attr(f, "severity") for f in eol_findings)

    return [
        Recommendation(
            type=RecommendationType.EOL_DEPENDENCY,
            priority=Priority.HIGH if impact["high"] else Priority.MEDIUM,
            title="End-of-Life Dependencies",
            description=(
                f"Found {len(eol_findings)} dependencies that have reached end-of-life. "
                f"These will no longer receive security updates, leaving your application vulnerable "
                f"to future CVEs that will never be patched."
            ),
            impact=impact,
            affected_components=eol_shown,
            affected_components_total=eol_total,
            action={
                "type": "upgrade_eol",
                **sampled("packages", affected_packages, AFFECTED_COMPONENTS_SHOWN),
                "steps": [
                    "Identify supported versions for each EOL dependency",
                    "Review migration guides for major version upgrades",
                    "Plan and execute upgrades",
                    "For frameworks (Node.js, Python, Java), plan runtime upgrades",
                    "Update CI/CD pipelines for new versions",
                ],
            },
            effort=Effort.HIGH,
        )
    ]
