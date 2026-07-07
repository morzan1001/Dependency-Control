from collections import defaultdict
from typing import Any, Dict, List

from app.schemas.recommendation import (
    PackageHotspot,
    Priority,
    Recommendation,
    RecommendationType,
)
from app.core.constants import (
    DETAILS_KEY_IN_KEV,
    EPSS_HIGH_THRESHOLD,
    SCORECARD_LOW_THRESHOLD,
    get_severity_weight,
)
from app.services.recommendation.common import get_attr, ModelOrDict


def _vuln_risk_severity(critical: int, high: int, kev: int) -> str:
    """Determine severity label for vulnerability risk factor."""
    if critical > 0 or kev > 0:
        return "CRITICAL"
    if high > 0:
        return "HIGH"
    return "MEDIUM"


def get_hotspot_remediation_steps(hotspot: PackageHotspot) -> List[str]:
    """Generate specific remediation steps for a hotspot."""
    steps = []

    if hotspot.has_malware:
        steps.extend(
            [
                "URGENT: This package contains known malware",
                "1. Immediately remove this package from your project",
                "2. Check if any malicious code was executed during installation",
                "3. Audit your systems for signs of compromise",
                "4. Find a legitimate alternative package",
            ]
        )
    elif hotspot.kev_count > 0:
        steps.extend(
            [
                "URGENT: This vulnerability is being actively exploited in the wild",
                "1. Update to a fixed version immediately if available",
                "2. If no fix exists, implement compensating controls",
                "3. Monitor for signs of exploitation in your environment",
                "4. Consider WAF rules or network segmentation as temporary mitigation",
            ]
        )
    elif hotspot.fixed_versions:
        steps.extend(
            [
                f"1. Update {hotspot.package} to version {hotspot.fixed_versions[0]} or later",
                "2. Run tests to ensure compatibility",
                "3. Deploy the updated dependency",
                "4. Verify the vulnerabilities are resolved in your next scan",
            ]
        )
    else:
        steps.extend(
            [
                "1. Evaluate if this package is essential to your application",
                "2. Search for alternative packages with better security posture",
                "3. If no alternatives exist, implement compensating controls",
                "4. Monitor for security updates from the package maintainer",
                "5. Consider contributing a fix if the package is open source",
            ]
        )

    return steps


def _new_hotspot_bucket() -> Dict[str, Any]:
    """Build an empty per-package aggregation bucket for hotspot detection."""
    return {
        "vulnerabilities": [],
        "quality_issues": [],
        "license_issues": [],
        "malware": [],
        "eol": [],
        "secrets": [],
        "critical_count": 0,
        "high_count": 0,
        "kev_count": 0,
        "high_epss_count": 0,
        "reachable_count": 0,
        "total_risk_score": 0.0,
    }


def _record_vulnerability(pkg_data: Dict[str, Any], f: ModelOrDict, severity: str, details: Any) -> None:
    """Update a package aggregation bucket with a vulnerability finding."""
    pkg_data["vulnerabilities"].append(f)
    if severity == "CRITICAL":
        pkg_data["critical_count"] += 1
    elif severity == "HIGH":
        pkg_data["high_count"] += 1

    details_dict = details if isinstance(details, dict) else {}
    if details_dict.get(DETAILS_KEY_IN_KEV):
        pkg_data["kev_count"] += 1
    epss = details_dict.get("epss_score")
    if epss is not None and epss >= EPSS_HIGH_THRESHOLD:
        pkg_data["high_epss_count"] += 1
    if get_attr(f, "reachable") is True:
        pkg_data["reachable_count"] += 1
    risk_score = details_dict.get("risk_score", 0)
    pkg_data["total_risk_score"] += risk_score or get_severity_weight(severity)


_FINDING_TYPE_BUCKETS = {
    "quality": "quality_issues",
    "license": "license_issues",
    "malware": "malware",
    "eol": "eol",
}


def _aggregate_findings_by_package(findings: List[ModelOrDict]) -> Dict[str, Dict[str, Any]]:
    """Aggregate findings grouped by package component."""
    package_findings: Dict[str, Dict[str, Any]] = defaultdict(_new_hotspot_bucket)

    for f in findings:
        component = get_attr(f, "component", "")
        if not component:
            continue

        finding_type = get_attr(f, "type", "other")
        severity = get_attr(f, "severity", "UNKNOWN")
        details = get_attr(f, "details", {})
        pkg_data = package_findings[component]

        if finding_type == "vulnerability":
            _record_vulnerability(pkg_data, f, severity, details)
            continue

        bucket = _FINDING_TYPE_BUCKETS.get(finding_type)
        if bucket:
            pkg_data[bucket].append(f)

    return package_findings


def _collect_hotspot_reasons(pkg_data: Dict[str, Any]) -> tuple[bool, List[str]]:
    """Determine if a package is a hotspot and gather its reasons."""
    is_hotspot = False
    reasons: List[str] = []

    if pkg_data["malware"]:
        is_hotspot = True
        reasons.append("Malware detected")
    if pkg_data["kev_count"] > 0:
        is_hotspot = True
        reasons.append(f"{pkg_data['kev_count']} CVE(s) in CISA KEV")
    if pkg_data["high_epss_count"] > 0 and pkg_data["reachable_count"] > 0:
        is_hotspot = True
        reasons.append(f"{pkg_data['high_epss_count']} high-EPSS CVE(s), {pkg_data['reachable_count']} reachable")

    vuln_count = len(pkg_data["vulnerabilities"])
    critical_high = pkg_data["critical_count"] + pkg_data["high_count"]
    if vuln_count >= 3 and critical_high >= 1:
        is_hotspot = True
        reasons.append(
            f"{vuln_count} vulnerabilities ({pkg_data['critical_count']} critical, {pkg_data['high_count']} high)"
        )

    for qi in pkg_data["quality_issues"]:
        qi_details = get_attr(qi, "details", {})
        score = qi_details.get("scorecard_score", 10) if isinstance(qi_details, dict) else 10
        if score < SCORECARD_LOW_THRESHOLD:
            reasons.append(f"Low OpenSSF Scorecard: {score}/10")
            break

    if pkg_data["eol"]:
        reasons.append("End-of-Life dependency")

    return is_hotspot, reasons


def _build_hotspot(pkg_name: str, pkg_data: Dict[str, Any], reasons: List[str]) -> PackageHotspot:
    """Build a PackageHotspot record from aggregated per-package data."""
    version = "unknown"
    if pkg_data["vulnerabilities"]:
        version = get_attr(pkg_data["vulnerabilities"][0], "version", "unknown")

    fixed_versions = []
    for v in pkg_data["vulnerabilities"]:
        v_details = get_attr(v, "details", {})
        if isinstance(v_details, dict) and v_details.get("fixed_version"):
            fixed_versions.append(v_details.get("fixed_version"))

    return PackageHotspot(
        package=pkg_name,
        version=version,
        vuln_count=len(pkg_data["vulnerabilities"]),
        critical_count=pkg_data["critical_count"],
        high_count=pkg_data["high_count"],
        kev_count=pkg_data["kev_count"],
        high_epss_count=pkg_data["high_epss_count"],
        reachable_count=pkg_data["reachable_count"],
        risk_score=pkg_data["total_risk_score"],
        reasons=reasons,
        fixed_versions=list(set(fixed_versions)),
        has_malware=bool(pkg_data["malware"]),
        is_eol=bool(pkg_data["eol"]),
    )


def _build_hotspot_recommendation(hotspot: PackageHotspot) -> Recommendation:
    """Build a recommendation from an identified hotspot."""
    priority = (
        Priority.CRITICAL
        if (hotspot.has_malware or hotspot.kev_count > 0 or hotspot.critical_count > 0)
        else Priority.HIGH
    )

    desc_parts = [
        (f"**{hotspot.package}@{hotspot.version}** is a critical security hotspot that requires immediate attention.")
    ]
    desc_parts.extend(hotspot.reasons)
    if hotspot.fixed_versions:
        desc_parts.append(f"Available fix: Update to {hotspot.fixed_versions[0]}")

    return Recommendation(
        type=RecommendationType.CRITICAL_HOTSPOT,
        priority=priority,
        title=f"Critical Hotspot: {hotspot.package}",
        description=" | ".join(desc_parts),
        impact={
            "critical": hotspot.critical_count,
            "high": hotspot.high_count,
            "medium": 0,
            "low": 0,
            "total": hotspot.vuln_count,
            "kev_count": hotspot.kev_count,
            "high_epss_count": hotspot.high_epss_count,
            "reachable_count": hotspot.reachable_count,
            "risk_score": hotspot.risk_score,
        },
        affected_components=[f"{hotspot.package}@{hotspot.version}"],
        action={
            "type": "fix_hotspot",
            "package": hotspot.package,
            "current_version": hotspot.version,
            "fixed_versions": hotspot.fixed_versions,
            "reasons": hotspot.reasons,
            "is_malware": hotspot.has_malware,
            "is_kev": hotspot.kev_count > 0,
            "steps": get_hotspot_remediation_steps(hotspot),
        },
        effort="low" if hotspot.fixed_versions else "high",
    )


def detect_critical_hotspots(
    findings: List[ModelOrDict],
    _dependencies: List[ModelOrDict],
) -> List[Recommendation]:
    """
    Detect critical hotspots - packages that accumulate multiple severe issues.

    A hotspot is a package that:
    - Has multiple vulnerabilities (3+ CVEs)
    - Has at least one critical/high severity issue
    - May also have other risk factors (quality, license, etc.)

    These are the packages that "hurt" the most and fixing them has highest impact.
    """
    if not findings:
        return []

    package_findings = _aggregate_findings_by_package(findings)

    hotspots: List[PackageHotspot] = []
    for pkg_name, pkg_data in package_findings.items():
        is_hotspot, reasons = _collect_hotspot_reasons(pkg_data)
        if is_hotspot:
            hotspots.append(_build_hotspot(pkg_name, pkg_data, reasons))

    # Sort hotspots lexicographically: malware first, then KEV count, then high-EPSS,
    # then aggregated risk_score. Python compares tuples element-by-element, so the
    # earlier components dominate; the previous *10000/*1000/*100 multipliers were
    # visual noise that hinted at a weighted-sum but actually behaved identically
    # to this tuple sort.
    hotspots.sort(
        key=lambda h: (h.has_malware, h.kev_count, h.high_epss_count, h.risk_score),
        reverse=True,
    )

    return [_build_hotspot_recommendation(h) for h in hotspots[:10]]


def _record_quality_risk(pkg: Dict[str, Any], details: Any) -> None:
    """Record a low-scorecard risk factor if applicable."""
    score = details.get("scorecard_score", 10) if isinstance(details, dict) else 10
    if score >= SCORECARD_LOW_THRESHOLD:
        return
    if "low_scorecard" in [r["type"] for r in pkg["risk_factors"]]:
        return
    pkg["risk_factors"].append(
        {"type": "low_scorecard", "severity": "HIGH", "description": f"OpenSSF Scorecard: {score}/10"}
    )
    pkg["total_score"] += 30


def _record_eol_risk(pkg: Dict[str, Any]) -> None:
    """Record EOL risk factor if not already present."""
    if "eol" in [r["type"] for r in pkg["risk_factors"]]:
        return
    pkg["risk_factors"].append({"type": "eol", "severity": "HIGH", "description": "End-of-Life - no security updates"})
    pkg["total_score"] += 40


def _record_license_risk(pkg: Dict[str, Any], severity: str, details: Any) -> None:
    """Record a license risk factor if severity warrants it."""
    if severity not in ("CRITICAL", "HIGH"):
        return
    if "license_issue" in [r["type"] for r in pkg["risk_factors"]]:
        return
    license_name = details.get("license", "unknown") if isinstance(details, dict) else "unknown"
    pkg["risk_factors"].append(
        {
            "type": "license_issue",
            "severity": severity,
            "description": f"License compliance issue: {license_name}",
        }
    )
    pkg["total_score"] += 20


def _record_malware_risk(pkg: Dict[str, Any]) -> None:
    """Record a malware risk factor."""
    pkg["risk_factors"].append({"type": "malware", "severity": "CRITICAL", "description": "Known malware package"})
    pkg["total_score"] += 100


def _aggregate_package_risks(findings: List[ModelOrDict]) -> Dict[str, Dict[str, Any]]:
    """Aggregate risk factors per package from findings."""
    package_risks: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"risk_factors": [], "total_score": 0, "vulns": [], "details": {}}
    )

    for f in findings:
        component = get_attr(f, "component", "")
        if not component:
            continue

        pkg = package_risks[component]
        finding_type = get_attr(f, "type", "")
        details = get_attr(f, "details", {})

        if finding_type == "vulnerability":
            pkg["vulns"].append(f)
            if len(pkg["vulns"]) == 1:
                pkg["details"]["version"] = get_attr(f, "version", "unknown")
        elif finding_type == "quality":
            _record_quality_risk(pkg, details)
        elif finding_type == "eol":
            _record_eol_risk(pkg)
        elif finding_type == "license":
            _record_license_risk(pkg, get_attr(f, "severity", "LOW"), details)
        elif finding_type == "malware":
            _record_malware_risk(pkg)

    return package_risks


def _append_vuln_risk_factor(pkg: Dict[str, Any]) -> None:
    """Append a summarized vulnerability risk factor and score."""
    vuln_count = len(pkg["vulns"])
    if vuln_count == 0:
        return

    critical = sum(1 for v in pkg["vulns"] if get_attr(v, "severity") == "CRITICAL")
    high = sum(1 for v in pkg["vulns"] if get_attr(v, "severity") == "HIGH")
    kev = sum(
        1
        for v in pkg["vulns"]
        if isinstance(get_attr(v, "details", {}), dict) and get_attr(v, "details", {}).get(DETAILS_KEY_IN_KEV)
    )

    pkg["risk_factors"].append(
        {
            "type": "vulnerabilities",
            "severity": _vuln_risk_severity(critical, high, kev),
            "description": f"{vuln_count} vulnerabilities ({critical} critical, {high} high, {kev} KEV)",
        }
    )
    pkg["total_score"] += critical * 50 + high * 20 + vuln_count * 5 + kev * 100


def _build_toxic_recommendation(component: str, pkg: Dict[str, Any]) -> Recommendation:
    """Build a toxic-dependency recommendation."""
    risk_descriptions = [r["description"] for r in pkg["risk_factors"]]
    version = pkg["details"].get("version", "unknown")

    return Recommendation(
        type=RecommendationType.TOXIC_DEPENDENCY,
        priority=Priority.HIGH,
        title=f"Toxic Dependency: {component}",
        description=(
            f"This package has multiple independent risk factors: "
            f"{' | '.join(risk_descriptions)}. "
            f"Consider replacing it with a safer alternative."
        ),
        impact={
            "critical": sum(1 for v in pkg["vulns"] if get_attr(v, "severity") == "CRITICAL"),
            "high": sum(1 for v in pkg["vulns"] if get_attr(v, "severity") == "HIGH"),
            "medium": sum(1 for v in pkg["vulns"] if get_attr(v, "severity") == "MEDIUM"),
            "low": 0,
            "total": len(pkg["vulns"]),
            "risk_factor_count": len(pkg["risk_factors"]),
            "toxic_score": pkg["total_score"],
        },
        affected_components=[f"{component}@{version}"],
        action={
            "type": "replace_toxic_dependency",
            "package": component,
            "version": version,
            "risk_factors": pkg["risk_factors"],
            "steps": [
                f"1. Evaluate if {component} is essential to your application",
                "2. Search for alternative packages with better security posture",
                "3. Check npm/pypi/crates.io for actively maintained alternatives",
                "4. If essential, implement additional security controls",
                "5. Plan migration to a safer alternative",
            ],
        },
        effort="high",
    )


def detect_toxic_dependencies(
    findings: List[ModelOrDict],
    dependencies: List[ModelOrDict],
) -> List[Recommendation]:
    """
    Detect "toxic" dependencies - packages with multiple independent risk factors.

    A toxic dependency has 2+ of:
    - Multiple vulnerabilities
    - Low OpenSSF Scorecard
    - EOL status
    - License issues
    - Outdated (no updates in years)
    - Malware/Typosquatting flags
    """
    if not findings:
        return []

    package_risks = _aggregate_package_risks(findings)

    for pkg in package_risks.values():
        _append_vuln_risk_factor(pkg)

    toxic_packages = [(c, p) for c, p in package_risks.items() if len(p["risk_factors"]) >= 2]
    toxic_packages.sort(key=lambda x: x[1]["total_score"], reverse=True)

    return [_build_toxic_recommendation(component, pkg) for component, pkg in toxic_packages[:5]]


def analyze_attack_surface(
    dependencies: List[ModelOrDict],
    findings: List[ModelOrDict],
) -> List[Recommendation]:
    """
    Analyze attack surface and recommend reduction strategies.

    Identifies:
    - Unused or rarely used dependencies with vulnerabilities
    - Dependencies that could be replaced with built-in functionality
    - Heavy dependencies that could be replaced with lighter alternatives
    """
    if not dependencies:
        return []

    recommendations = []

    # Count vulnerabilities by package
    vuln_count_by_pkg: Dict[str, int] = defaultdict(int)
    for f in findings:
        if get_attr(f, "type") == "vulnerability":
            vuln_count_by_pkg[get_attr(f, "component", "")] += 1

    # Identify transitive dependencies with many vulnerabilities
    transitive_with_vulns = []
    for dep in dependencies:
        pkg_name = get_attr(dep, "name", "")
        is_direct = get_attr(dep, "direct", False)
        vuln_count = vuln_count_by_pkg.get(pkg_name, 0)

        if not is_direct and vuln_count >= 2:
            transitive_with_vulns.append(
                {
                    "name": pkg_name,
                    "version": get_attr(dep, "version", "unknown"),
                    "vuln_count": vuln_count,
                    "parent": get_attr(dep, "introduced_by", get_attr(dep, "parent", "unknown")),
                }
            )

    if transitive_with_vulns:
        # Sort by vulnerability count
        transitive_with_vulns.sort(key=lambda x: x["vuln_count"], reverse=True)

        total_vulns = sum(t["vuln_count"] for t in transitive_with_vulns)

        recommendations.append(
            Recommendation(
                type=RecommendationType.ATTACK_SURFACE_REDUCTION,
                priority=Priority.MEDIUM,
                title="Reduce Attack Surface via Transitive Dependencies",
                description=(
                    f"Found {len(transitive_with_vulns)} transitive dependencies "
                    f"contributing {total_vulns} vulnerabilities. "
                    "Consider updating or replacing their parent dependencies "
                    "to reduce attack surface."
                ),
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": total_vulns,
                    "low": 0,
                    "total": total_vulns,
                },
                affected_components=[
                    f"{t['name']}@{t['version']} (via {t['parent']})" for t in transitive_with_vulns[:10]
                ],
                action={
                    "type": "reduce_attack_surface",
                    "transitive_deps": transitive_with_vulns[:10],
                    "steps": [
                        "1. Review which parent dependencies introduce vulnerable transitives",
                        "2. Check if parent dependencies have updates that use fixed versions",
                        "3. Consider using dependency overrides to force specific versions",
                        "4. Evaluate if parent dependencies are essential or could be removed",
                    ],
                },
                effort="medium",
            )
        )

    # Identify very large dependency counts
    total_deps = len(dependencies)
    direct_deps = len([d for d in dependencies if get_attr(d, "direct", False)])

    if total_deps > 500 and direct_deps < total_deps * 0.1:
        recommendations.append(
            Recommendation(
                type=RecommendationType.ATTACK_SURFACE_REDUCTION,
                priority=Priority.LOW,
                title="Large Dependency Tree",
                description=(
                    f"Your project has {total_deps} total dependencies but only {direct_deps} direct dependencies. "
                    f"This large transitive tree increases attack surface. Consider auditing heavy dependencies."
                ),
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": total_deps,
                    "total": total_deps,
                },
                affected_components=[f"Total: {total_deps} deps, Direct: {direct_deps} deps"],
                action={
                    "type": "audit_dependencies",
                    "total_deps": total_deps,
                    "direct_deps": direct_deps,
                    "steps": [
                        "1. Run 'npm ls' or 'pip show' to understand dependency tree",
                        "2. Identify 'heavy' packages that bring many transitive deps",
                        "3. Consider lighter alternatives for heavy packages",
                        "4. Remove unused dependencies",
                        "5. Use tools like depcheck (npm) to find unused deps",
                    ],
                },
                effort="medium",
            )
        )

    return recommendations
