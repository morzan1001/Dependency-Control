from collections import defaultdict

from app.core.constants import EPSS_HIGH_THRESHOLD, OS_PACKAGE_TYPES
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
    VulnerabilityInfo,
)
from app.services.recommendation.common import (
    ModelOrDict,
    VulnStats,
    get_attr,
    sample_components,
    sampled,
    summarize_vulns,
    vuln_info,
    vuln_priority,
)

# Evidence samples inside the update action; each is paired with its population by `sampled`.
_CVES_SAMPLED = 10
_MARKED_CVES_SAMPLED = 5
_TRANSITIVE_CVES_SHOWN = 5


def process_vulnerabilities(
    findings: list[ModelOrDict],
    dep_by_name_version: dict[str, ModelOrDict],
    dependencies: list[ModelOrDict],
    source_target: str | None,
) -> list[Recommendation]:
    """Process vulnerability findings."""
    recommendations = []

    vulns_by_source = _categorize_by_source(findings, dep_by_name_version)

    base_image_rec = _analyze_base_image_vulns(vulns_by_source.get("image", []), dependencies, source_target)
    if base_image_rec:
        recommendations.append(base_image_rec)

    # One card per installed copy: another version of the package has its own fixes and CVEs.
    for (component, version), group in _by_installed_version(vulns_by_source.get("application", [])).items():
        recommendations.append(_build_direct_recommendation(component, version, group))
    for (component, version), group in _by_installed_version(vulns_by_source.get("transitive", [])).items():
        recommendations.append(_build_transitive_recommendation(component, version, group))

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
        return "application"

    source_type = get_attr(dep, "source_type", "")
    if source_type == "image" or _is_os_package(dep):
        return "image"
    if get_attr(dep, "direct", False):
        return "application"
    return "transitive"


def _categorize_by_source(
    findings: list[ModelOrDict],
    dep_by_name_version: dict[str, ModelOrDict],
) -> dict[str, list[VulnerabilityInfo]]:
    """Categorize vulnerabilities by their source type."""

    categories = defaultdict(list)

    for f in findings:
        if get_attr(f, "type") != "vulnerability":
            continue

        dep = dep_by_name_version.get(f"{get_attr(f, 'component', '')}@{get_attr(f, 'version', '')}")
        vuln = vuln_info(f)
        vuln.direct_inferred = bool(dep and get_attr(dep, "direct_inferred", False))
        categories[_classify_category(vuln, dep)].append(vuln)

    return categories


def _is_os_package(dep: ModelOrDict) -> bool:
    """Check if a dependency is an OS-level package."""
    pkg_type = str(get_attr(dep, "type", "")).lower()
    purl = get_attr(dep, "purl", "") or ""

    return pkg_type in OS_PACKAGE_TYPES or any(purl.startswith(f"pkg:{os_type}/") for os_type in OS_PACKAGE_TYPES)


def _analyze_base_image_vulns(
    vulns: list[VulnerabilityInfo],
    _dependencies: list[ModelOrDict],
    source_target: str | None,
) -> Recommendation | None:
    """Analyze if a base image update would be beneficial."""

    if not vulns:
        return None

    severity_counts: dict[str, int] = defaultdict(int)
    affected_packages = set()

    for v in vulns:
        severity_counts[v.severity] += 1
        affected_packages.add(v.package_name)

    total_vulns = len(vulns)
    critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)

    if total_vulns < 3 and critical_high < 1:
        return None

    if severity_counts.get("CRITICAL", 0) > 0:
        priority = Priority.CRITICAL
    elif severity_counts.get("HIGH", 0) > 0:
        priority = Priority.HIGH
    elif severity_counts.get("MEDIUM", 0) > 0:
        priority = Priority.MEDIUM
    else:
        priority = Priority.LOW

    image_name = source_target or "your base image"

    if source_target and ":" in source_target:
        parts = source_target.rsplit(":", 1)
        image_name = parts[0]

    packages_shown, packages_total = sample_components(sorted(affected_packages))
    return Recommendation(
        type=RecommendationType.BASE_IMAGE_UPDATE,
        priority=priority,
        title="Update Base Image",
        description=(
            f"Updating the base image could fix {total_vulns} vulnerabilities "
            f"across {len(affected_packages)} OS packages. "
            f"This includes {severity_counts.get('CRITICAL', 0)} critical and "
            f"{severity_counts.get('HIGH', 0)} high severity issues."
        ),
        impact={
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "total": total_vulns,
        },
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
        effort="low" if total_vulns > 10 else "medium",
    )


def _build_direct_description(component: str, current_version: str, stats: VulnStats, direct_inferred: bool) -> str:
    """Build the description string for a direct-dependency update recommendation."""
    desc_parts = [
        f"Update {component} from {current_version} to {stats.best_fix} to fix {stats.total} vulnerabilities."
    ]
    if stats.kev > 0:
        desc_parts.append(f"{stats.kev} CVE(s) are in CISA KEV (actively exploited).")
    if stats.kev_ransomware > 0:
        desc_parts.append(f"{stats.kev_ransomware} are used in ransomware campaigns.")
    if stats.high_epss > 0:
        desc_parts.append(f"{stats.high_epss} have high exploitation probability (EPSS >10%).")
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


def _build_direct_recommendation(
    component: str, current_version: str, component_vulns: list[VulnerabilityInfo]
) -> Recommendation:
    """Build a single direct-dependency recommendation."""
    stats = summarize_vulns(component_vulns)
    direct_inferred = component_vulns[0].direct_inferred

    return Recommendation(
        type=RecommendationType.DIRECT_DEPENDENCY_UPDATE,
        priority=vuln_priority(stats),
        title=f"Update {component}@{current_version}",
        description=_build_direct_description(component, current_version, stats, direct_inferred),
        impact=stats.impact(),
        affected_components=[f"{component}@{current_version}"],
        action={
            "type": "update_dependency",
            "package": component,
            "current_version": current_version,
            "target_version": stats.best_fix,
            "direct_inferred": direct_inferred,
            **sampled("cves", stats.cves, _CVES_SAMPLED),
            **sampled("kev_cves", [v.cve_id for v in component_vulns if v.is_kev], _MARKED_CVES_SAMPLED),
            **sampled(
                "high_epss_cves",
                [v.cve_id for v in component_vulns if v.epss_score and v.epss_score >= EPSS_HIGH_THRESHOLD],
                _MARKED_CVES_SAMPLED,
            ),
        },
        effort="medium" if direct_inferred else "low",
    )


def _build_transitive_description(component: str, current_version: str, stats: VulnStats) -> str:
    """Build the description for a transitive-dependency recommendation."""
    desc_parts = [
        (
            f"Transitive dependency {component}@{current_version} has "
            f"{stats.total} vulnerabilities. "
            f"Update a parent dependency that includes a fixed version ({stats.best_fix}), "
            f"or override the transitive version directly."
        )
    ]
    if stats.kev > 0:
        desc_parts.append(f"{stats.kev} are actively exploited (KEV).")
    if stats.high_epss > 0:
        desc_parts.append(f"{stats.high_epss} have high EPSS.")
    if stats.reachable > 0:
        desc_parts.append(f"{stats.reachable} are reachable.")
    return " ".join(desc_parts)


def _build_transitive_recommendation(
    component: str, current_version: str, component_vulns: list[VulnerabilityInfo]
) -> Recommendation:
    """Build a transitive-dependency recommendation."""
    stats = summarize_vulns(component_vulns)

    return Recommendation(
        type=RecommendationType.TRANSITIVE_FIX_VIA_PARENT,
        priority=vuln_priority(stats),
        title=f"Update transitive dependency {component}@{current_version}",
        description=_build_transitive_description(component, current_version, stats),
        impact=stats.impact(),
        affected_components=[f"{component}@{current_version}"],
        action={
            "type": "update_transitive",
            "package": component,
            "current_version": current_version,
            "target_version": stats.best_fix,
            "cves": stats.cves[:_TRANSITIVE_CVES_SHOWN],
        },
        effort="high",
    )


def _analyze_no_fix_vulns(vulns: list[VulnerabilityInfo]) -> list[Recommendation]:
    """Analyze vulnerabilities whose advisories name no fixed version."""

    if not vulns:
        return []

    severity_counts: dict[str, int] = defaultdict(int)
    components = set()
    crit_high_vulns = []

    for v in vulns:
        severity_counts[v.severity] += 1
        components.add(v.package_name)
        if v.severity in ["CRITICAL", "HIGH"]:
            crit_high_vulns.append(v)

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
            impact={
                "critical": severity_counts.get("CRITICAL", 0),
                "high": severity_counts.get("HIGH", 0),
                "medium": severity_counts.get("MEDIUM", 0),
                "low": severity_counts.get("LOW", 0),
                "total": len(vulns),
            },
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
