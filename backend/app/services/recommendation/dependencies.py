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
from app.services.aggregation.cross_link import is_ahead_of_default
from app.services.aggregation.versions import newest_first
from app.services.recommendation.common import (
    ACTION_VERSION_SAMPLE,
    AFFECTED_COMPONENTS_SHOWN,
    ModelOrDict,
    get_attr,
    installed_copy_lookup,
    newest_clean_version_finder,
    package_label,
    recommend,
    sampled,
    severity_impact,
)

_FRAGMENTATION_MIN_VERSIONS = 3
# Counts that must be exceeded: fragmented packages for a MEDIUM card, outdated transitives for a card at all.
_FRAGMENTED_PACKAGES_FOR_MEDIUM = 3
_OUTDATED_TRANSITIVE_CARD_MIN = 3

_DEDUPE_COMMANDS: dict[str, tuple[str, ...]] = {
    "npm": ("# For npm: npm dedupe", "# For yarn: yarn dedupe", "# For pnpm: pnpm dedupe"),
    # Gradle resolves Maven coordinates, so its packages carry the maven type.
    "maven": ("# For Maven/Gradle: pin one version in dependencyManagement or a dependency constraint",),
    "pypi": ("# For pip: pin one version in a constraints file (pip install -c constraints.txt)",),
}


def analyze_outdated_dependencies(
    outdated_findings: list[ModelOrDict],
    upgrading_findings: list[ModelOrDict],
    join_dependencies: list[ModelOrDict],
) -> list[Recommendation]:
    upgraded = installed_copy_lookup(upgrading_findings, "component")
    row_of = installed_copy_lookup(join_dependencies, "name")
    direct: list[ModelOrDict] = []
    transitive: list[ModelOrDict] = []
    for finding in sorted(outdated_findings, key=lambda f: (get_attr(f, "component").lower(), get_attr(f, "version"))):
        if is_ahead_of_default(get_attr(finding, "type"), get_attr(finding, "details")) or upgraded(finding):
            continue
        row = row_of(finding)
        (direct if row and get_attr(row, "direct", False) else transitive).append(finding)

    recommendations = []
    if direct:
        recommendations.append(
            _outdated_card(
                direct,
                Priority.MEDIUM,
                f"Upgrade {len(direct)} outdated direct dependencies",
                "These direct dependencies are older than the latest release in their registry. "
                "Upgrading can improve security, performance, and maintainability.",
                Effort.MEDIUM,
            )
        )
    if len(transitive) > _OUTDATED_TRANSITIVE_CARD_MIN:
        recommendations.append(
            _outdated_card(
                transitive,
                Priority.LOW,
                f"{len(transitive)} transitive dependencies are outdated",
                "These transitive dependencies are older than the latest release in their registry. "
                "Updating parent packages may resolve these.",
                Effort.LOW,
            )
        )
    return recommendations


def _outdated_card(
    findings: list[ModelOrDict], priority: Priority, title: str, description: str, effort: Effort
) -> Recommendation:
    return recommend(
        rec_type=RecommendationType.OUTDATED_DEPENDENCY,
        priority=priority,
        title=title,
        description=description,
        impact=severity_impact(get_attr(f, "severity") for f in findings),
        components=(f"{get_attr(f, 'component')}@{get_attr(f, 'version')}" for f in findings),
        action={
            "type": "upgrade_outdated",
            **sampled(
                "packages",
                [
                    {
                        "name": get_attr(f, "component"),
                        "current_version": get_attr(f, "version"),
                        "latest_version": get_attr(f, "details", {}).get("fixed_version"),
                    }
                    for f in findings
                ],
                AFFECTED_COMPONENTS_SHOWN,
            ),
        },
        effort=effort,
    )


def analyze_version_fragmentation(
    dependencies: list[ModelOrDict],
    vulns: list[ModelOrDict],
) -> list[Recommendation]:
    recommendations = []

    versions_by_package: dict[tuple[str, str], set[str]] = defaultdict(set)
    for dep in dependencies:
        identity = package_identity(
            get_attr(dep, "purl"), get_attr(dep, "name"), get_attr(dep, "type"), get_attr(dep, "group")
        )
        versions_by_package[identity].add(get_attr(dep, "version"))

    newest_clean = newest_clean_version_finder((get_attr(v, "component"), get_attr(v, "version")) for v in vulns)

    def pin_suggestion(ecosystem: str, name: str, versions: list[str]) -> str | None:
        v = newest_clean(ecosystem, name, versions)
        return f"Pin to {v}" if v else None

    significant_fragmented: list[dict[str, Any]] = sorted(
        (
            {"type": ecosystem, "name": name, "versions": list(versions), "count": len(versions)}
            for (ecosystem, name), versions in versions_by_package.items()
            if len(versions) >= _FRAGMENTATION_MIN_VERSIONS
        ),
        key=lambda x: x["count"],
        reverse=True,
    )

    if significant_fragmented:
        priority = Priority.MEDIUM if len(significant_fragmented) > _FRAGMENTED_PACKAGES_FOR_MEDIUM else Priority.LOW
        ecosystems = {f["type"] for f in significant_fragmented}
        commands = [line for ecosystem, lines in _DEDUPE_COMMANDS.items() if ecosystem in ecosystems for line in lines]

        recommendations.append(
            recommend(
                rec_type=RecommendationType.VERSION_FRAGMENTATION,
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
                components=(package_label(f) for f in significant_fragmented),
                action={
                    "type": "deduplicate_versions",
                    **sampled(
                        "packages",
                        [
                            {
                                "name": f["name"],
                                "type": f["type"],
                                # Sets are unordered; rank first so the sample shows the newest versions.
                                "versions": newest_first(f["versions"])[:ACTION_VERSION_SAMPLE],
                                "version_count": f["count"],
                                "suggestion": pin_suggestion(f["type"], f["name"], f["versions"]),
                            }
                            for f in significant_fragmented
                        ],
                        AFFECTED_COMPONENTS_SHOWN,
                    ),
                    **({"commands": commands} if commands else {}),
                },
                effort=Effort.LOW,
            )
        )

    return recommendations


def analyze_dev_in_production(
    dependencies: list[ModelOrDict],
) -> list[Recommendation]:
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

    if potential_dev_deps:
        recommendations.append(
            recommend(
                rec_type=RecommendationType.DEV_IN_PRODUCTION,
                priority=Priority.LOW,
                title=f"{len(potential_dev_deps)} potential dev dependencies in production",
                description=(
                    "Some packages typically used for development/testing were detected "
                    "in your build. If these are in your production bundle, consider "
                    "moving them to devDependencies."
                ),
                impact={"total": 0},
                components=(f"{d['name']}@{d['version']}" for d in potential_dev_deps),
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
    if not eol_findings:
        return []

    affected_packages = []
    for f in eol_findings:
        pkg = get_attr(f, "component", "")
        version = get_attr(f, "version", "")
        details = get_attr(f, "details", {})
        eol_date = details.get("eol_date")
        # endoflife.date reports an undated end of life as True.
        if isinstance(eol_date, str) and eol_date:
            affected_packages.append(f"{pkg}@{version} (EOL: {eol_date})")
        else:
            affected_packages.append(f"{pkg}@{version}")

    impact = severity_impact(get_attr(f, "severity") for f in eol_findings)

    return [
        recommend(
            rec_type=RecommendationType.EOL_DEPENDENCY,
            priority=Priority.HIGH if impact["high"] else Priority.MEDIUM,
            title="End-of-Life Dependencies",
            description=(
                f"Found {len(eol_findings)} dependencies that have reached end-of-life. "
                f"These will no longer receive security updates, leaving your application vulnerable "
                f"to future CVEs that will never be patched."
            ),
            impact=impact,
            components=affected_packages,
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
