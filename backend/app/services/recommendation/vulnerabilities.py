from collections import defaultdict
from typing import Any, Dict, List, Optional


from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
    VulnerabilityInfo,
)
from app.core.constants import DETAILS_KEY_IN_KEV, DETAILS_KEY_KEV_RANSOMWARE, OS_PACKAGE_TYPES
from app.services.recommendation.common import calculate_best_fix_version, get_attr, ModelOrDict


def process_vulnerabilities(
    findings: List[ModelOrDict],
    dep_by_purl: Dict[str, ModelOrDict],
    dep_by_name_version: Dict[str, ModelOrDict],
    dependencies: List[ModelOrDict],
    source_target: Optional[str],
) -> List[Recommendation]:
    """Process vulnerability findings."""
    recommendations = []

    # Categorize vulnerabilities by source
    vulns_by_source = _categorize_by_source(findings, dep_by_purl, dep_by_name_version)

    # 1. Check for base image update recommendation
    base_image_rec = _analyze_base_image_vulns(vulns_by_source.get("image", []), dependencies, source_target)
    if base_image_rec:
        recommendations.append(base_image_rec)

    # 2. Analyze direct dependency updates
    direct_recs = _analyze_direct_dependencies(vulns_by_source.get("application", []), dep_by_purl, dep_by_name_version)
    recommendations.extend(direct_recs)

    # 3. Analyze transitive dependencies
    transitive_recs = _analyze_transitive_dependencies(vulns_by_source.get("transitive", []), dependencies)
    recommendations.extend(transitive_recs)

    # 4. Handle vulns with no fix
    no_fix_recs = _analyze_no_fix_vulns(vulns_by_source.get("no_fix", []))
    recommendations.extend(no_fix_recs)

    return recommendations


def _resolve_dep(
    details: dict,
    component: str,
    version: str,
    dep_by_purl: Dict[str, ModelOrDict],
    dep_by_name_version: Dict[str, ModelOrDict],
) -> Optional[ModelOrDict]:
    """Resolve a dependency from purl or name@version lookup."""
    purl = details.get("purl") if isinstance(details, dict) else None
    purl = purl or (details.get("package_url") if isinstance(details, dict) else None)

    if purl and purl in dep_by_purl:
        return dep_by_purl[purl]
    if f"{component}@{version}" in dep_by_name_version:
        return dep_by_name_version[f"{component}@{version}"]
    return None


def _resolve_cve_id(f: ModelOrDict) -> str:
    """Resolve the CVE id for a finding, checking aliases as a fallback."""
    cve_id_val = get_attr(f, "id")
    if not cve_id_val or not str(cve_id_val).startswith("CVE-"):
        for alias in get_attr(f, "aliases", []) or []:
            if alias.startswith("CVE-"):
                cve_id_val = alias
                break
    return str(cve_id_val) if cve_id_val else "unknown"


def _build_vuln_info(f: ModelOrDict) -> VulnerabilityInfo:
    """Build a VulnerabilityInfo from a finding."""
    details = get_attr(f, "details", {})
    details_dict = details if isinstance(details, dict) else {}

    return VulnerabilityInfo(
        finding_id=get_attr(f, "id", ""),
        cve_id=_resolve_cve_id(f),
        severity=get_attr(f, "severity", "UNKNOWN"),
        package_name=get_attr(f, "component", ""),
        current_version=get_attr(f, "version", ""),
        fixed_version=details_dict.get("fixed_version"),
        epss_score=details_dict.get("epss_score"),
        is_kev=details_dict.get(DETAILS_KEY_IN_KEV, False),
        kev_ransomware=details_dict.get(DETAILS_KEY_KEV_RANSOMWARE, False),
        is_reachable=get_attr(f, "reachable"),
        reachability_level=get_attr(f, "reachability_level"),
        risk_score=details_dict.get("risk_score"),
    )


def _classify_category(vuln_info: VulnerabilityInfo, dep: Optional[ModelOrDict]) -> str:
    """Determine which category a vulnerability belongs to."""
    if not vuln_info.fixed_version:
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
    findings: List[ModelOrDict],
    dep_by_purl: Dict[str, ModelOrDict],
    dep_by_name_version: Dict[str, ModelOrDict],
) -> Dict[str, List[VulnerabilityInfo]]:
    """Categorize vulnerabilities by their source type."""

    categories = defaultdict(list)

    for f in findings:
        if get_attr(f, "type") != "vulnerability":
            continue

        details = get_attr(f, "details", {})
        details_dict = details if isinstance(details, dict) else {}

        dep = _resolve_dep(
            details_dict,
            get_attr(f, "component", ""),
            get_attr(f, "version", ""),
            dep_by_purl,
            dep_by_name_version,
        )

        vuln_info = _build_vuln_info(f)
        categories[_classify_category(vuln_info, dep)].append(vuln_info)

    return categories


def _is_os_package(dep: ModelOrDict) -> bool:
    """Check if a dependency is an OS-level package."""
    pkg_type = str(get_attr(dep, "type", "")).lower()
    purl = get_attr(dep, "purl", "") or ""

    # Check type
    if pkg_type in OS_PACKAGE_TYPES:
        return True

    # Check PURL prefix
    for os_type in OS_PACKAGE_TYPES:
        if purl.startswith(f"pkg:{os_type}/"):
            return True

    return False


def _analyze_base_image_vulns(
    vulns: List[VulnerabilityInfo],
    _dependencies: List[ModelOrDict],
    source_target: Optional[str],
) -> Optional[Recommendation]:
    """Analyze if a base image update would be beneficial."""

    if not vulns:
        return None

    # Count severities
    severity_counts: Dict[str, int] = defaultdict(int)
    affected_packages = set()

    for v in vulns:
        severity_counts[v.severity] += 1
        affected_packages.add(v.package_name)

    total_vulns = len(vulns)
    critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)

    # Only recommend if significant impact
    if total_vulns < 3 and critical_high < 1:
        return None

    # Determine priority
    if severity_counts.get("CRITICAL", 0) > 0:
        priority = Priority.CRITICAL
    elif severity_counts.get("HIGH", 0) > 0:
        priority = Priority.HIGH
    elif severity_counts.get("MEDIUM", 0) > 0:
        priority = Priority.MEDIUM
    else:
        priority = Priority.LOW

    # Try to determine current image tag
    image_name = source_target or "your base image"

    # Extract image name (without tag) for display
    if source_target and ":" in source_target:
        parts = source_target.rsplit(":", 1)
        image_name = parts[0]

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
        affected_components=list(affected_packages)[:20],  # Limit for display
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


def _aggregate_vuln_stats(component_vulns: List[VulnerabilityInfo]) -> Dict[str, Any]:
    """Aggregate severity, EPSS/KEV, and reachability stats for a component's vulns."""
    severity_counts: Dict[str, int] = defaultdict(int)
    stats: Dict[str, Any] = {
        "cves": [],
        "kev_count": 0,
        "kev_ransomware_count": 0,
        "high_epss_count": 0,
        "medium_epss_count": 0,
        "reachable_count": 0,
        "unreachable_count": 0,
        "reachable_critical": 0,
        "reachable_high": 0,
        "actionable_count": 0,
        "epss_scores": [],
    }

    for v in component_vulns:
        severity_counts[v.severity] += 1
        if v.cve_id:
            stats["cves"].append(v.cve_id)
        if v.is_kev:
            stats["kev_count"] += 1
        if v.kev_ransomware:
            stats["kev_ransomware_count"] += 1

        if v.epss_score is not None:
            stats["epss_scores"].append(v.epss_score)
            if v.epss_score >= 0.1:
                stats["high_epss_count"] += 1
            elif v.epss_score >= 0.01:
                stats["medium_epss_count"] += 1

        if v.is_reachable is True:
            stats["reachable_count"] += 1
            if v.severity == "CRITICAL":
                stats["reachable_critical"] += 1
            elif v.severity == "HIGH":
                stats["reachable_high"] += 1
        elif v.is_reachable is False:
            stats["unreachable_count"] += 1

        if v.is_actionable:
            stats["actionable_count"] += 1

    stats["severity_counts"] = severity_counts
    return stats


def _score_priority(component_vulns: List[VulnerabilityInfo], stats: Dict[str, Any]) -> Priority:
    """Determine recommendation priority from aggregated stats."""
    severity_counts = stats["severity_counts"]

    if stats["kev_count"] > 0 or stats["reachable_critical"] > 0:
        return Priority.CRITICAL

    if severity_counts.get("CRITICAL", 0) > 0:
        critical_vulns = [v for v in component_vulns if v.severity == "CRITICAL"]
        if critical_vulns and all(v.is_reachable is False for v in critical_vulns):
            return Priority.HIGH
        return Priority.CRITICAL

    if stats["high_epss_count"] > 0 or stats["reachable_high"] > 0:
        return Priority.HIGH
    if severity_counts.get("HIGH", 0) > 0:
        return Priority.HIGH
    if severity_counts.get("MEDIUM", 0) > 0:
        return Priority.MEDIUM
    return Priority.LOW


def _build_direct_description(
    component: str,
    current_version: str,
    best_fix: str,
    component_vulns: List[VulnerabilityInfo],
    stats: Dict[str, Any],
) -> str:
    """Build the description string for a direct-dependency update recommendation."""
    desc_parts = [
        f"Update {component} from {current_version} to {best_fix} to fix {len(component_vulns)} vulnerabilities."
    ]
    if stats["kev_count"] > 0:
        desc_parts.append(f"{stats['kev_count']} CVE(s) are in CISA KEV (actively exploited).")
    if stats["kev_ransomware_count"] > 0:
        desc_parts.append(f"{stats['kev_ransomware_count']} are used in ransomware campaigns.")
    if stats["high_epss_count"] > 0:
        desc_parts.append(f"{stats['high_epss_count']} have high exploitation probability (EPSS >10%).")
    if stats["reachable_count"] > 0:
        desc_parts.append(f"{stats['reachable_count']} are confirmed reachable in your code.")
    if stats["unreachable_count"] > 0 and stats["unreachable_count"] == len(component_vulns):
        desc_parts.append("All vulnerabilities are unreachable - lower priority.")
    return " ".join(desc_parts)


def _build_direct_recommendation(
    component: str,
    component_vulns: List[VulnerabilityInfo],
) -> Optional[Recommendation]:
    """Build a single direct-dependency recommendation, returning None if no fix is known."""
    fixed_versions = [v.fixed_version for v in component_vulns if v.fixed_version]
    if not fixed_versions:
        return None

    current_version = (component_vulns[0].current_version if component_vulns else None) or "unknown"
    best_fix = calculate_best_fix_version(fixed_versions)

    stats = _aggregate_vuln_stats(component_vulns)
    severity_counts = stats["severity_counts"]
    epss_scores = stats["epss_scores"]
    priority = _score_priority(component_vulns, stats)
    description = _build_direct_description(component, current_version, best_fix, component_vulns, stats)

    return Recommendation(
        type=RecommendationType.DIRECT_DEPENDENCY_UPDATE,
        priority=priority,
        title=f"Update {component}",
        description=description,
        impact={
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "total": len(component_vulns),
            "kev_count": stats["kev_count"],
            "kev_ransomware_count": stats["kev_ransomware_count"],
            "high_epss_count": stats["high_epss_count"],
            "medium_epss_count": stats["medium_epss_count"],
            "avg_epss": (round(sum(epss_scores) / len(epss_scores), 4) if epss_scores else None),
            "reachable_count": stats["reachable_count"],
            "unreachable_count": stats["unreachable_count"],
            "reachable_critical": stats["reachable_critical"],
            "reachable_high": stats["reachable_high"],
            "actionable_count": stats["actionable_count"],
        },
        affected_components=[component],
        action={
            "type": "update_dependency",
            "package": component,
            "current_version": current_version,
            "target_version": best_fix,
            "cves": stats["cves"][:10],
            "kev_cves": [v.cve_id for v in component_vulns if v.is_kev][:5],
            "high_epss_cves": [v.cve_id for v in component_vulns if v.epss_score and v.epss_score >= 0.1][:5],
        },
        effort="low",
    )


def _analyze_direct_dependencies(
    vulns: List[VulnerabilityInfo],
    _dep_by_purl: Dict[str, ModelOrDict],
    _dep_by_name_version: Dict[str, ModelOrDict],
) -> List[Recommendation]:
    """Analyze direct dependency updates with EPSS/KEV/Reachability prioritization."""

    recommendations = []

    vulns_by_component = defaultdict(list)
    for v in vulns:
        vulns_by_component[v.package_name].append(v)

    for component, component_vulns in vulns_by_component.items():
        rec = _build_direct_recommendation(component, component_vulns)
        if rec is not None:
            recommendations.append(rec)

    return recommendations


def _build_transitive_description(
    component: str, current_version: str, best_fix: str, component_vulns: List[VulnerabilityInfo], stats: Dict[str, Any]
) -> str:
    """Build the description for a transitive-dependency recommendation."""
    desc_parts = [
        f"Transitive dependency {component}@{current_version} has "
        f"{len(component_vulns)} vulnerabilities. "
        f"Update a parent dependency that includes a fixed version ({best_fix}), "
        f"or override the transitive version directly."
    ]
    if stats["kev_count"] > 0:
        desc_parts.append(f"{stats['kev_count']} are actively exploited (KEV).")
    if stats["high_epss_count"] > 0:
        desc_parts.append(f"{stats['high_epss_count']} have high EPSS.")
    if stats["reachable_count"] > 0:
        desc_parts.append(f"{stats['reachable_count']} are reachable.")
    return " ".join(desc_parts)


def _build_transitive_recommendation(
    component: str, component_vulns: List[VulnerabilityInfo]
) -> Optional[Recommendation]:
    """Build a transitive recommendation, returning None when there is no fix."""
    fixed_versions = [v.fixed_version for v in component_vulns if v.fixed_version]
    if not fixed_versions:
        return None

    current_version = (component_vulns[0].current_version if component_vulns else None) or "unknown"
    best_fix = calculate_best_fix_version(fixed_versions)

    stats = _aggregate_vuln_stats(component_vulns)
    severity_counts = stats["severity_counts"]
    priority = _score_priority(component_vulns, stats)
    description = _build_transitive_description(component, current_version, best_fix, component_vulns, stats)

    return Recommendation(
        type=RecommendationType.TRANSITIVE_FIX_VIA_PARENT,
        priority=priority,
        title=f"Update transitive dependency {component}",
        description=description,
        impact={
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "total": len(component_vulns),
            "kev_count": stats["kev_count"],
            "kev_ransomware_count": stats["kev_ransomware_count"],
            "high_epss_count": stats["high_epss_count"],
            "medium_epss_count": stats["medium_epss_count"],
            "reachable_count": stats["reachable_count"],
            "unreachable_count": stats["unreachable_count"],
            "reachable_critical": stats["reachable_critical"],
            "reachable_high": stats["reachable_high"],
            "actionable_count": stats["actionable_count"],
        },
        affected_components=[component],
        action={
            "type": "update_transitive",
            "package": component,
            "current_version": current_version,
            "target_version": best_fix,
            "cves": [v.cve_id for v in component_vulns if v.cve_id][:5],
        },
        effort="high",
    )


def _analyze_transitive_dependencies(
    vulns: List[VulnerabilityInfo], _dependencies: List[ModelOrDict]
) -> List[Recommendation]:
    """Analyze transitive dependency vulnerabilities with EPSS/KEV/Reachability prioritization."""

    recommendations = []

    vulns_by_component = defaultdict(list)
    for v in vulns:
        vulns_by_component[v.package_name].append(v)

    for component, component_vulns in vulns_by_component.items():
        rec = _build_transitive_recommendation(component, component_vulns)
        if rec is not None:
            recommendations.append(rec)

    return recommendations


def _analyze_no_fix_vulns(vulns: List[VulnerabilityInfo]) -> List[Recommendation]:
    """Analyze vulnerabilities with no available fix."""

    if not vulns:
        return []

    severity_counts: Dict[str, int] = defaultdict(int)
    components = set()
    crit_high_vulns = []

    for v in vulns:
        severity_counts[v.severity] += 1
        components.add(v.package_name)
        if v.severity in ["CRITICAL", "HIGH"]:
            crit_high_vulns.append(v)

    if not crit_high_vulns:
        return []

    # If there are critical/high vulnerabilities with no fix, suggest alternatives
    return [
        Recommendation(
            type=RecommendationType.NO_FIX_AVAILABLE,
            priority=Priority.HIGH,
            title="Vulnerability with No Fix Available",
            description=(
                f"{len(crit_high_vulns)} Critical/High vulnerabilities used in your project "
                "have no fix available. Consider switching components."
            ),
            impact={
                "critical": severity_counts.get("CRITICAL", 0),
                "high": severity_counts.get("HIGH", 0),
                "medium": severity_counts.get("MEDIUM", 0),
                "low": severity_counts.get("LOW", 0),
                "total": len(vulns),
            },
            affected_components=list({v.package_name for v in crit_high_vulns})[:20],
            action={
                "type": "consider_alternative",
                "steps": [
                    "Check if the vulnerability actually affects your usage of the component",
                    "Look for alternative libraries that provide similar functionality",
                    "Apply mitigating controls (WAF, network segmentation)",
                    "Accept the risk if it's not exploitable in your context",
                ],
            },
            effort="high",
        )
    ]
