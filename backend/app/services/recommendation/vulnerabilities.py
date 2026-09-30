from collections import defaultdict
from collections.abc import Callable
from typing import Any

from app.core.constants import (
    DETAILS_KEY_IN_KEV,
    EPSS_HIGH_THRESHOLD,
    SOURCE_TYPE_DIRECTORY,
    SOURCE_TYPE_FILE,
    SOURCE_TYPE_IMAGE,
)
from app.core.cve import canonical_cves
from app.core.epss import HIGH_EPSS_LABEL
from app.core.purl import is_os_package_type
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
    VulnerabilityInfo,
)
from app.services.aggregation.versions import normalize_version
from app.services.component_identity import build_component_index, lookup_component
from app.services.recommendation.common import (
    ModelOrDict,
    VulnStats,
    get_attr,
    priority_for,
    sample_components,
    sampled,
    severity_impact,
    summarize_vulns,
    vuln_info,
    vuln_priority,
    worth_a_card,
)

# Evidence samples inside the update action; each is paired with its population by `sampled`.
_CVES_SAMPLED = 10
_MARKED_CVES_SAMPLED = 5


def process_vulnerabilities(
    findings: list[ModelOrDict],
    join_dependencies: list[ModelOrDict],
    source_target: str | None,
) -> list[Recommendation]:
    """Update, base-image and no-fix cards; ``join_dependencies`` holds the inventory rows the findings name."""
    recommendations = []

    vulns_by_source = _categorize_by_source(findings, join_dependencies)

    base_image_rec = _analyze_base_image_vulns(vulns_by_source.get("image", []), source_target)
    if base_image_rec:
        recommendations.append(base_image_rec)

    # One card per installed copy: another version of the package has its own fixes and CVEs.
    for source, transitive in (("application", False), ("transitive", True)):
        for (component, version), group in _by_installed_version(vulns_by_source.get(source, [])).items():
            recommendations.append(_build_update_recommendation(component, version, group, transitive))

    no_fix_recs = _analyze_no_fix_vulns(vulns_by_source.get("no_fix", []))
    recommendations.extend(no_fix_recs)

    return recommendations


def _by_installed_version(vulns: list[VulnerabilityInfo]) -> dict[tuple[str, str], list[VulnerabilityInfo]]:
    groups: dict[tuple[str, str], list[VulnerabilityInfo]] = defaultdict(list)
    for v in vulns:
        groups[(v.package_name, v.current_version or "unknown")].append(v)
    return groups


def _classify_category(vuln: VulnerabilityInfo, dep: ModelOrDict | None) -> str:
    """Determine which category a vulnerability belongs to."""
    # An advisory that records no fixed version does not say a fix is absent, only that it does
    # not name one, so this bucket is "no fix known" and the card it produces says as much.
    if not vuln.fixed_version:
        return "no_fix"
    if not dep:
        return "unresolved"

    source_type = get_attr(dep, "source_type")
    # An explicit filesystem source wins; otherwise an OS package ships with the base image.
    if source_type == SOURCE_TYPE_IMAGE or (
        source_type not in (SOURCE_TYPE_DIRECTORY, SOURCE_TYPE_FILE)
        and is_os_package_type(get_attr(dep, "purl"), get_attr(dep, "type"))
    ):
        return "image"
    if get_attr(dep, "direct", False):
        return "application"
    return "transitive"


def _categorize_by_source(
    findings: list[ModelOrDict],
    join_dependencies: list[ModelOrDict],
) -> dict[str, list[VulnerabilityInfo]]:
    """Categorize vulnerabilities by their source type."""
    deps_by_version: dict[str, dict[str, ModelOrDict]] = defaultdict(dict)
    for row in join_dependencies:
        deps_by_version[normalize_version(get_attr(row, "version"))][get_attr(row, "name")] = row
    index_by_version = {version: build_component_index(deps) for version, deps in deps_by_version.items()}

    categories = defaultdict(list)

    for f in findings:
        if get_attr(f, "type") != "vulnerability":
            continue

        index = index_by_version.get(normalize_version(get_attr(f, "version")), {})
        dep = lookup_component(index, get_attr(f, "component") or "")
        vuln = vuln_info(f)
        vuln.direct_inferred = bool(dep and get_attr(dep, "direct_inferred", False))
        categories[_classify_category(vuln, dep)].append(vuln)

    return categories


def _analyze_base_image_vulns(vulns: list[VulnerabilityInfo], source_target: str | None) -> Recommendation | None:
    """Analyze if a base image update would be beneficial."""

    impact = severity_impact(v.severity for v in vulns)
    if not worth_a_card(impact):
        return None

    affected_packages = {v.package_name for v in vulns}
    image_name = "your base image"
    if source_target:
        repository = source_target.split("@", 1)[0]
        # A ':' before the last '/' is a registry port, not a tag separator.
        tag_colon = repository.rfind(":")
        image_name = repository[:tag_colon] if tag_colon > repository.rfind("/") else repository

    packages_shown, packages_total = sample_components(sorted(affected_packages))
    return Recommendation(
        type=RecommendationType.BASE_IMAGE_UPDATE,
        priority=priority_for(impact),
        title="Update Base Image",
        description=(
            f"Updating the base image could fix {impact['total']} vulnerabilities "
            f"across {len(affected_packages)} OS packages. "
            f"This includes {impact['critical']} critical and {impact['high']} high severity issues."
        ),
        impact=impact,
        affected_components=packages_shown,
        affected_components_total=packages_total,
        action={
            "type": "update_base_image",
            "current_image": source_target,
            "suggestion": f"Check for newer tags of {image_name} or consider switching to a minimal/distroless image",
            "commands": [
                "# Check for available tags:",
                f"docker pull {image_name}:latest",
                "# Or use a specific newer version:",
                f"# FROM {image_name}:<newer-tag>",
            ],
        },
        effort="low" if impact["total"] > 10 else "medium",
    )


def _build_update_description(
    component: str, current_version: str, stats: VulnStats, transitive: bool, direct_inferred: bool
) -> str:
    if transitive:
        headline = (
            f"Transitive dependency {component}@{current_version} has {stats.total} vulnerabilities. "
            f"Update a parent dependency that includes a fixed version ({stats.best_fix}), "
            "or override the transitive version directly."
        )
    else:
        headline = (
            f"Update {component} from {current_version} to {stats.best_fix} to fix {stats.total} vulnerabilities."
        )
    desc_parts = [headline]
    if stats.kev > 0:
        desc_parts.append(f"{stats.kev} CVE(s) are in CISA KEV (actively exploited).")
    if stats.kev_ransomware > 0:
        desc_parts.append(f"{stats.kev_ransomware} are used in ransomware campaigns.")
    if stats.high_epss > 0:
        desc_parts.append(f"{stats.high_epss} have high exploitation probability ({HIGH_EPSS_LABEL}).")
    if stats.reachable > 0:
        desc_parts.append(f"{stats.reachable} are confirmed reachable in your code.")
    if stats.unreachable > 0 and stats.unreachable == stats.total:
        desc_parts.append("All vulnerabilities are unreachable - lower priority.")
    if direct_inferred:
        desc_parts.append(
            f"The SBOM does not record whether {component} is a direct dependency; if it is pulled in "
            "transitively, update the parent that brings it in or add an override."
        )
    return " ".join(desc_parts)


def _marked_cves(vulns: list[VulnerabilityInfo], marked: Callable[[dict[str, Any]], Any]) -> list[str]:
    return canonical_cves([{"vulnerabilities": [a for a in v.advisories if marked(a)]} for v in vulns])


def _build_update_recommendation(
    component: str, current_version: str, component_vulns: list[VulnerabilityInfo], transitive: bool
) -> Recommendation:
    stats = summarize_vulns(component_vulns)
    direct_inferred = not transitive and component_vulns[0].direct_inferred
    label = f"{component}@{current_version}"

    return Recommendation(
        type=RecommendationType.TRANSITIVE_FIX_VIA_PARENT
        if transitive
        else RecommendationType.DIRECT_DEPENDENCY_UPDATE,
        priority=vuln_priority(stats),
        title=f"Update transitive dependency {label}" if transitive else f"Update {label}",
        description=_build_update_description(component, current_version, stats, transitive, direct_inferred),
        impact=stats.impact(),
        affected_components=[label],
        action={
            "type": "update_transitive" if transitive else "update_dependency",
            "package": component,
            "current_version": current_version,
            "target_version": stats.best_fix,
            "direct_inferred": direct_inferred,
            **sampled("cves", stats.cves, _CVES_SAMPLED),
            **sampled(
                "kev_cves",
                _marked_cves(component_vulns, lambda a: a.get(DETAILS_KEY_IN_KEV)),
                _MARKED_CVES_SAMPLED,
            ),
            **sampled(
                "high_epss_cves",
                _marked_cves(component_vulns, lambda a: (a.get("epss_score") or 0) >= EPSS_HIGH_THRESHOLD),
                _MARKED_CVES_SAMPLED,
            ),
        },
        effort="high" if transitive else "medium" if direct_inferred else "low",
    )


def _analyze_no_fix_vulns(vulns: list[VulnerabilityInfo]) -> list[Recommendation]:
    """Analyze vulnerabilities whose advisories name no fixed version."""

    crit_high_vulns = [v for v in vulns if v.severity in ("CRITICAL", "HIGH")]
    if not crit_high_vulns:
        return []

    unfixable_shown, unfixable_total = sample_components(sorted({v.package_name for v in crit_high_vulns}))

    return [
        Recommendation(
            type=RecommendationType.NO_FIX_AVAILABLE,
            priority=Priority.HIGH,
            title="Vulnerability with No Known Fix",
            description=(
                f"{len(crit_high_vulns)} Critical/High vulnerabilities used in your project have "
                "no fixed version in their advisories. That is the absence of a recorded fix, not "
                "proof that none exists, so confirm upstream before replacing a component."
            ),
            impact=severity_impact(v.severity for v in vulns),
            affected_components=unfixable_shown,
            affected_components_total=unfixable_total,
            action={
                "type": "consider_alternative",
                "steps": [
                    "Check the upstream project for a release the advisory has not recorded yet",
                    "Check if the vulnerability actually affects your usage of the component",
                    "Look for alternative libraries that provide similar functionality",
                    "Apply mitigating controls (WAF, network segmentation)",
                    "Accept the risk if it's not exploitable in your context",
                ],
            },
            effort="high",
        )
    ]
