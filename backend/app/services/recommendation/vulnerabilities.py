from collections import defaultdict
from typing import Dict, List, Optional


from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
    VulnerabilityInfo,
)
from app.core.constants import OS_PACKAGE_TYPES
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
    base_image_rec = _analyze_base_image_vulns(
        vulns_by_source.get("image", []), dependencies, source_target
    )
    if base_image_rec:
        recommendations.append(base_image_rec)

    # 2. Analyze direct dependency updates
    direct_recs = _analyze_direct_dependencies(
        vulns_by_source.get("application", []), dep_by_purl, dep_by_name_version
    )
    recommendations.extend(direct_recs)

    # 3. Analyze transitive dependencies
    transitive_recs = _analyze_transitive_dependencies(
        vulns_by_source.get("transitive", []), dependencies
    )
    recommendations.extend(transitive_recs)

    # 4. Handle vulns with no fix
    no_fix_recs = _analyze_no_fix_vulns(vulns_by_source.get("no_fix", []))
    recommendations.extend(no_fix_recs)

    return recommendations


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
        component = get_attr(f, "component", "")
        version = get_attr(f, "version", "")

        # Extract fixed version
        fixed_version = details.get("fixed_version") if isinstance(details, dict) else None

        # Try to find the dependency
        purl = details.get("purl") if isinstance(details, dict) else None
        purl = purl or (details.get("package_url") if isinstance(details, dict) else None)
        dep = None

        if purl and purl in dep_by_purl:
            dep = dep_by_purl[purl]
        elif f"{component}@{version}" in dep_by_name_version:
            dep = dep_by_name_version[f"{component}@{version}"]

        # Extract CVE ID
        cve_id_val = get_attr(f, "id")
        if not cve_id_val or not str(cve_id_val).startswith("CVE-"):
            # Check aliases
            for alias in get_attr(f, "aliases", []) or []:
                if alias.startswith("CVE-"):
                    cve_id_val = alias
                    break

        cve_id = str(cve_id_val) if cve_id_val else "unknown"

        # Extract EPSS/KEV/Reachability data from details
        epss_score = details.get("epss_score") if isinstance(details, dict) else None
        is_kev = details.get("is_kev", False) if isinstance(details, dict) else False
        kev_ransomware = details.get("kev_ransomware", False) if isinstance(details, dict) else False
        risk_score = details.get("risk_score") if isinstance(details, dict) else None

        # Reachability comes from finding-level, not details
        is_reachable = get_attr(f, "reachable")
        reachability_level = get_attr(f, "reachability_level")

        vuln_info = VulnerabilityInfo(
            finding_id=get_attr(f, "id", ""),
            cve_id=cve_id,
            severity=get_attr(f, "severity", "UNKNOWN"),
            package_name=component,
            current_version=version,
            fixed_version=fixed_version,
            # EPSS/KEV/Reachability fields
            epss_score=epss_score,
            is_kev=is_kev,
            kev_ransomware=kev_ransomware,
            is_reachable=is_reachable,
            reachability_level=reachability_level,
            risk_score=risk_score,
        )

        # Categorize based on source and fix availability
        if not fixed_version:
            categories["no_fix"].append(vuln_info)
        elif dep:
            source_type = get_attr(dep, "source_type", "")
            is_direct = get_attr(dep, "direct", False)

            if source_type == "image" or _is_os_package(dep):
                categories["image"].append(vuln_info)
            elif is_direct:
                categories["application"].append(vuln_info)
            else:
                categories["transitive"].append(vuln_info)
        else:
            # No dependency info, assume application
            categories["application"].append(vuln_info)

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
    dependencies: List[ModelOrDict],
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


def _analyze_direct_dependencies(
    vulns: List[VulnerabilityInfo],
    dep_by_purl: Dict[str, ModelOrDict],
    dep_by_name_version: Dict[str, ModelOrDict],
) -> List[Recommendation]:
    """Analyze direct dependency updates with EPSS/KEV/Reachability prioritization."""

    recommendations = []

    # Group vulns by component
    vulns_by_component = defaultdict(list)
    for v in vulns:
        vulns_by_component[v.package_name].append(v)

    for component, component_vulns in vulns_by_component.items():
        # Find the best fix version (one that fixes all vulns)
        fixed_versions = [v.fixed_version for v in component_vulns if v.fixed_version]

        if not fixed_versions:
            continue

        # Get current version (ensure it's never None)
        current_version = (
            component_vulns[0].current_version if component_vulns else None
        ) or "unknown"

        # Calculate best fixed version
        best_fix = calculate_best_fix_version(fixed_versions)

        # Count severities and gather threat intelligence stats
        severity_counts: Dict[str, int] = defaultdict(int)
        cves = []

        # EPSS/KEV/Reachability aggregation
        kev_count = 0
        kev_ransomware_count = 0
        high_epss_count = 0
        medium_epss_count = 0
        reachable_count = 0
        unreachable_count = 0
        reachable_critical = 0
        reachable_high = 0
        actionable_count = 0
        epss_scores = []

        for v in component_vulns:
            severity_counts[v.severity] += 1
            if v.cve_id:
                cves.append(v.cve_id)

            # Count KEV findings
            if v.is_kev:
                kev_count += 1
            if v.kev_ransomware:
                kev_ransomware_count += 1

            # Count EPSS distribution
            if v.epss_score is not None:
                epss_scores.append(v.epss_score)
                if v.epss_score >= 0.1:
                    high_epss_count += 1
                elif v.epss_score >= 0.01:
                    medium_epss_count += 1

            # Count reachability
            if v.is_reachable is True:
                reachable_count += 1
                if v.severity == "CRITICAL":
                    reachable_critical += 1
                elif v.severity == "HIGH":
                    reachable_high += 1
            elif v.is_reachable is False:
                unreachable_count += 1

            # Count actionable vulns
            if v.is_actionable:
                actionable_count += 1

        # Determine priority - now considering EPSS/KEV/Reachability
        if kev_count > 0 or reachable_critical > 0:
            # KEV findings or reachable critical vulns are always critical priority
            priority = Priority.CRITICAL
        elif severity_counts.get("CRITICAL", 0) > 0:
            # Check if ALL critical vulns are confirmed unreachable - can downgrade
            critical_vulns = [v for v in component_vulns if v.severity == "CRITICAL"]
            critical_all_unreachable = all(
                v.is_reachable is False for v in critical_vulns
            )
            # Only downgrade if we have confirmed unreachability (not just unknown)
            if critical_all_unreachable and len(critical_vulns) > 0:
                # Downgrade to HIGH (not MEDIUM) since critical vulns still exist
                priority = Priority.HIGH
            else:
                priority = Priority.CRITICAL
        elif high_epss_count > 0 or reachable_high > 0:
            priority = Priority.HIGH
        elif severity_counts.get("HIGH", 0) > 0:
            priority = Priority.HIGH
        elif severity_counts.get("MEDIUM", 0) > 0:
            priority = Priority.MEDIUM
        else:
            priority = Priority.LOW

        # Build enhanced description with threat context
        desc_parts = [
            f"Update {component} from {current_version} to {best_fix} "
            f"to fix {len(component_vulns)} vulnerabilities."
        ]

        if kev_count > 0:
            desc_parts.append(
                f"{kev_count} CVE(s) are in CISA KEV (actively exploited)."
            )
        if kev_ransomware_count > 0:
            desc_parts.append(
                f"{kev_ransomware_count} are used in ransomware campaigns."
            )
        if high_epss_count > 0:
            desc_parts.append(
                f"{high_epss_count} have high exploitation probability (EPSS >10%)."
            )
        if reachable_count > 0:
            desc_parts.append(
                f"{reachable_count} are confirmed reachable in your code."
            )
        if unreachable_count > 0 and unreachable_count == len(component_vulns):
            desc_parts.append("All vulnerabilities are unreachable - lower priority.")

        recommendations.append(
            Recommendation(
                type=RecommendationType.DIRECT_DEPENDENCY_UPDATE,
                priority=priority,
                title=f"Update {component}",
                description=" ".join(desc_parts),
                impact={
                    "critical": severity_counts.get("CRITICAL", 0),
                    "high": severity_counts.get("HIGH", 0),
                    "medium": severity_counts.get("MEDIUM", 0),
                    "low": severity_counts.get("LOW", 0),
                    "total": len(component_vulns),
                    # Threat intelligence data for scoring
                    "kev_count": kev_count,
                    "kev_ransomware_count": kev_ransomware_count,
                    "high_epss_count": high_epss_count,
                    "medium_epss_count": medium_epss_count,
                    "avg_epss": (
                        round(sum(epss_scores) / len(epss_scores), 4)
                        if epss_scores
                        else None
                    ),
                    # Reachability data
                    "reachable_count": reachable_count,
                    "unreachable_count": unreachable_count,
                    "reachable_critical": reachable_critical,
                    "reachable_high": reachable_high,
                    # Actionable count
                    "actionable_count": actionable_count,
                },
                affected_components=[component],
                action={
                    "type": "update_dependency",
                    "package": component,
                    "current_version": current_version,
                    "target_version": best_fix,
                    "cves": cves[:10],  # Limit CVEs shown
                    "kev_cves": [v.cve_id for v in component_vulns if v.is_kev][:5],
                    "high_epss_cves": [
                        v.cve_id
                        for v in component_vulns
                        if v.epss_score and v.epss_score >= 0.1
                    ][:5],
                },
                effort="low",
            )
        )

    return recommendations


def _analyze_transitive_dependencies(
    vulns: List[VulnerabilityInfo], dependencies: List[ModelOrDict]
) -> List[Recommendation]:
    """Analyze transitive dependency vulnerabilities with EPSS/KEV/Reachability prioritization."""

    recommendations = []

    # Group by component
    vulns_by_component = defaultdict(list)
    for v in vulns:
        vulns_by_component[v.package_name].append(v)

    for component, component_vulns in vulns_by_component.items():
        fixed_versions = [v.fixed_version for v in component_vulns if v.fixed_version]

        if not fixed_versions:
            continue

        # Get current version (ensure it's never None)
        current_version = (
            component_vulns[0].current_version if component_vulns else None
        ) or "unknown"
        best_fix = calculate_best_fix_version(fixed_versions)

        # Count severities and gather threat intelligence stats
        severity_counts: Dict[str, int] = defaultdict(int)
        kev_count = 0
        kev_ransomware_count = 0
        high_epss_count = 0
        medium_epss_count = 0
        reachable_count = 0
        unreachable_count = 0
        reachable_critical = 0
        reachable_high = 0
        actionable_count = 0
        epss_scores = []

        for v in component_vulns:
            severity_counts[v.severity] += 1

            # Aggregate EPSS/KEV data
            if v.is_kev:
                kev_count += 1
            if v.kev_ransomware:
                kev_ransomware_count += 1
            if v.epss_score is not None:
                epss_scores.append(v.epss_score)
                if v.epss_score >= 0.1:
                    high_epss_count += 1
                elif v.epss_score >= 0.01:
                    medium_epss_count += 1

            # Aggregate reachability
            if v.is_reachable is True:
                reachable_count += 1
                if v.severity == "CRITICAL":
                    reachable_critical += 1
                elif v.severity == "HIGH":
                    reachable_high += 1
            elif v.is_reachable is False:
                unreachable_count += 1

            if v.is_actionable:
                actionable_count += 1

        # Determine priority with EPSS/KEV/Reachability
        if kev_count > 0 or reachable_critical > 0:
            priority = Priority.CRITICAL
        elif severity_counts.get("CRITICAL", 0) > 0:
            # Check if ALL critical vulns are confirmed unreachable
            critical_vulns = [v for v in component_vulns if v.severity == "CRITICAL"]
            critical_all_unreachable = all(
                v.is_reachable is False for v in critical_vulns
            )
            if critical_all_unreachable and len(critical_vulns) > 0:
                priority = Priority.HIGH  # Downgrade since critical are unreachable
            else:
                priority = Priority.CRITICAL
        elif high_epss_count > 0 or reachable_high > 0:
            priority = Priority.HIGH
        elif severity_counts.get("HIGH", 0) > 0:
            priority = Priority.HIGH
        elif severity_counts.get("MEDIUM", 0) > 0:
            priority = Priority.MEDIUM
        else:
            priority = Priority.LOW

        # Build description with threat context
        desc_parts = [
            f"Transitive dependency {component}@{current_version} has "
            f"{len(component_vulns)} vulnerabilities. "
            f"Update a parent dependency that includes a fixed version ({best_fix}), "
            f"or override the transitive version directly."
        ]

        if kev_count > 0:
            desc_parts.append(f"{kev_count} are actively exploited (KEV).")
        if high_epss_count > 0:
            desc_parts.append(f"{high_epss_count} have high EPSS.")
        if reachable_count > 0:
            desc_parts.append(f"{reachable_count} are reachable.")

        recommendations.append(
            Recommendation(
                type=RecommendationType.TRANSITIVE_FIX_VIA_PARENT,
                priority=priority,
                title=f"Update transitive dependency {component}",
                description=" ".join(desc_parts),
                impact={
                    "critical": severity_counts.get("CRITICAL", 0),
                    "high": severity_counts.get("HIGH", 0),
                    "medium": severity_counts.get("MEDIUM", 0),
                    "low": severity_counts.get("LOW", 0),
                    "total": len(component_vulns),
                    # Threat intelligence data
                    "kev_count": kev_count,
                    "kev_ransomware_count": kev_ransomware_count,
                    "high_epss_count": high_epss_count,
                    "medium_epss_count": medium_epss_count,
                    # Reachability data
                    "reachable_count": reachable_count,
                    "unreachable_count": unreachable_count,
                    "reachable_critical": reachable_critical,
                    "reachable_high": reachable_high,
                    "actionable_count": actionable_count,
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
        )

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
            affected_components=list(set(v.package_name for v in crit_high_vulns))[:20],
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
