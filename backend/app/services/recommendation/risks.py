from collections import defaultdict
from typing import List, Dict, Any

from app.core.constants import EPSS_HIGH_THRESHOLD
from app.schemas.recommendation import (
    Recommendation,
    RecommendationType,
    Priority,
)
from app.core.constants import EPSS_HIGH_THRESHOLD, SEVERITY_WEIGHTS


def get_hotspot_remediation_steps(hotspot: Dict[str, Any]) -> List[str]:
    """Generate specific remediation steps for a hotspot."""
    steps = []

    if hotspot["has_malware"]:
        steps.extend(
            [
                "URGENT: This package contains known malware",
                "1. Immediately remove this package from your project",
                "2. Check if any malicious code was executed during installation",
                "3. Audit your systems for signs of compromise",
                "4. Find a legitimate alternative package",
            ]
        )
    elif hotspot["kev_count"] > 0:
        steps.extend(
            [
                "URGENT: This vulnerability is being actively exploited in the wild",
                "1. Update to a fixed version immediately if available",
                "2. If no fix exists, implement compensating controls",
                "3. Monitor for signs of exploitation in your environment",
                "4. Consider WAF rules or network segmentation as temporary mitigation",
            ]
        )
    elif hotspot["fixed_versions"]:
        steps.extend(
            [
                f"1. Update {hotspot['package']} to version {hotspot['fixed_versions'][0]} or later",
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


def detect_critical_hotspots(
    findings: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
    dep_by_purl: Dict[str, Dict],
    dep_by_name_version: Dict[str, Dict],
) -> List[Recommendation]:
    """
    Detect critical hotspots - packages that accumulate multiple severe issues.

    A hotspot is a package that:
    - Has multiple vulnerabilities (3+ CVEs)
    - Has at least one critical/high severity issue
    - May also have other risk factors (quality, license, etc.)

    These are the packages that "hurt" the most and fixing them has highest impact.
    """
    recommendations = []

    # Aggregate all findings by package
    package_findings: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
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
    )

    for f in findings:
        component = f.get("component", "")
        if not component:
            continue

        finding_type = f.get("type", "other")
        severity = f.get("severity", "UNKNOWN")
        details = f.get("details", {})

        pkg_data = package_findings[component]

        if finding_type == "vulnerability":
            pkg_data["vulnerabilities"].append(f)
            if severity == "CRITICAL":
                pkg_data["critical_count"] += 1
            elif severity == "HIGH":
                pkg_data["high_count"] += 1
            if details.get("is_kev"):
                pkg_data["kev_count"] += 1
            if (
                details.get("epss_score")
                and details.get("epss_score") >= EPSS_HIGH_THRESHOLD
            ):
                pkg_data["high_epss_count"] += 1
            if f.get("reachable") is True:
                pkg_data["reachable_count"] += 1
            pkg_data["total_risk_score"] += details.get(
                "risk_score", 0
            ) or SEVERITY_WEIGHTS.get(severity, 0)
        elif finding_type == "quality":
            pkg_data["quality_issues"].append(f)
        elif finding_type == "license":
            pkg_data["license_issues"].append(f)
        elif finding_type == "malware":
            pkg_data["malware"].append(f)
        elif finding_type == "eol":
            pkg_data["eol"].append(f)

    # Identify hotspots
    hotspots = []
    for pkg_name, pkg_data in package_findings.items():
        vuln_count = len(pkg_data["vulnerabilities"])
        critical_high = pkg_data["critical_count"] + pkg_data["high_count"]

        # Hotspot criteria:
        # 1. Multiple vulnerabilities with at least one critical/high
        # 2. OR KEV/high-EPSS with reachability
        # 3. OR malware detected
        is_hotspot = False
        hotspot_reasons = []

        if pkg_data["malware"]:
            is_hotspot = True
            hotspot_reasons.append("Malware detected")

        if pkg_data["kev_count"] > 0:
            is_hotspot = True
            hotspot_reasons.append(f"{pkg_data['kev_count']} CVE(s) in CISA KEV")

        if pkg_data["high_epss_count"] > 0 and pkg_data["reachable_count"] > 0:
            is_hotspot = True
            hotspot_reasons.append(
                f"{pkg_data['high_epss_count']} high-EPSS CVE(s), {pkg_data['reachable_count']} reachable"
            )

        if vuln_count >= 3 and critical_high >= 1:
            is_hotspot = True
            hotspot_reasons.append(
                f"{vuln_count} vulnerabilities ({pkg_data['critical_count']} critical, {pkg_data['high_count']} high)"
            )

        if pkg_data["quality_issues"]:
            # Check for low scorecard
            for qi in pkg_data["quality_issues"]:
                score = qi.get("details", {}).get("scorecard_score", 10)
                if score < 4:
                    hotspot_reasons.append(f"Low OpenSSF Scorecard: {score}/10")
                    break

        if pkg_data["eol"]:
            hotspot_reasons.append("End-of-Life dependency")

        if is_hotspot:
            # Get version
            version = "unknown"
            if pkg_data["vulnerabilities"]:
                version = pkg_data["vulnerabilities"][0].get("version", "unknown")

            # Find fixed version
            fixed_versions = [
                v.get("details", {}).get("fixed_version")
                for v in pkg_data["vulnerabilities"]
                if v.get("details", {}).get("fixed_version")
            ]

            hotspots.append(
                {
                    "package": pkg_name,
                    "version": version,
                    "vuln_count": vuln_count,
                    "critical_count": pkg_data["critical_count"],
                    "high_count": pkg_data["high_count"],
                    "kev_count": pkg_data["kev_count"],
                    "high_epss_count": pkg_data["high_epss_count"],
                    "reachable_count": pkg_data["reachable_count"],
                    "risk_score": pkg_data["total_risk_score"],
                    "reasons": hotspot_reasons,
                    "fixed_versions": list(set(fixed_versions)),
                    "has_malware": bool(pkg_data["malware"]),
                    "is_eol": bool(pkg_data["eol"]),
                }
            )

    # Sort hotspots by severity (malware > KEV > risk_score)
    hotspots.sort(
        key=lambda h: (
            h["has_malware"] * 10000,
            h["kev_count"] * 1000,
            h["high_epss_count"] * 100,
            h["risk_score"],
        ),
        reverse=True,
    )

    # Create recommendations for top hotspots
    for hotspot in hotspots[:10]:  # Top 10 hotspots
        priority = (
            Priority.CRITICAL
            if (
                hotspot["has_malware"]
                or hotspot["kev_count"] > 0
                or hotspot["critical_count"] > 0
            )
            else Priority.HIGH
        )

        desc_parts = [
            f"**{hotspot['package']}@{hotspot['version']}** is a critical security hotspot that requires immediate attention."
        ]
        desc_parts.extend(hotspot["reasons"])

        if hotspot["fixed_versions"]:
            desc_parts.append(
                f"Available fix: Update to {hotspot['fixed_versions'][0]}"
            )

        recommendations.append(
            Recommendation(
                type=RecommendationType.CRITICAL_HOTSPOT,
                priority=priority,
                title=f"Critical Hotspot: {hotspot['package']}",
                description=" | ".join(desc_parts),
                impact={
                    "critical": hotspot["critical_count"],
                    "high": hotspot["high_count"],
                    "medium": 0,
                    "low": 0,
                    "total": hotspot["vuln_count"],
                    "kev_count": hotspot["kev_count"],
                    "high_epss_count": hotspot["high_epss_count"],
                    "reachable_count": hotspot["reachable_count"],
                    "risk_score": hotspot["risk_score"],
                },
                affected_components=[f"{hotspot['package']}@{hotspot['version']}"],
                action={
                    "type": "fix_hotspot",
                    "package": hotspot["package"],
                    "current_version": hotspot["version"],
                    "fixed_versions": hotspot["fixed_versions"],
                    "reasons": hotspot["reasons"],
                    "is_malware": hotspot["has_malware"],
                    "is_kev": hotspot["kev_count"] > 0,
                    "steps": get_hotspot_remediation_steps(hotspot),
                },
                effort="low" if hotspot["fixed_versions"] else "high",
            )
        )

    return recommendations


def detect_toxic_dependencies(
    findings: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
    dep_by_purl: Dict[str, Dict],
    dep_by_name_version: Dict[str, Dict],
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
    recommendations = []

    # Aggregate risk factors by package
    package_risks: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "risk_factors": [],
            "total_score": 0,
            "vulns": [],
            "details": {},
        }
    )

    for f in findings:
        component = f.get("component", "")
        if not component:
            continue

        pkg = package_risks[component]
        finding_type = f.get("type", "")
        details = f.get("details", {})

        if finding_type == "vulnerability":
            pkg["vulns"].append(f)
            if len(pkg["vulns"]) == 1:
                pkg["details"]["version"] = f.get("version", "unknown")
        elif finding_type == "quality":
            score = details.get("scorecard_score", 10)
            if score < 4:
                if "low_scorecard" not in [r["type"] for r in pkg["risk_factors"]]:
                    pkg["risk_factors"].append(
                        {
                            "type": "low_scorecard",
                            "severity": "HIGH",
                            "description": f"OpenSSF Scorecard: {score}/10",
                        }
                    )
                    pkg["total_score"] += 30
        elif finding_type == "eol":
            if "eol" not in [r["type"] for r in pkg["risk_factors"]]:
                pkg["risk_factors"].append(
                    {
                        "type": "eol",
                        "severity": "HIGH",
                        "description": "End-of-Life - no security updates",
                    }
                )
                pkg["total_score"] += 40
        elif finding_type == "license":
            severity = f.get("severity", "LOW")
            if severity in ["CRITICAL", "HIGH"]:
                if "license_issue" not in [r["type"] for r in pkg["risk_factors"]]:
                    pkg["risk_factors"].append(
                        {
                            "type": "license_issue",
                            "severity": severity,
                            "description": f"License compliance issue: {details.get('license', 'unknown')}",
                        }
                    )
                    pkg["total_score"] += 20
        elif finding_type == "malware":
            pkg["risk_factors"].append(
                {
                    "type": "malware",
                    "severity": "CRITICAL",
                    "description": "Known malware package",
                }
            )
            pkg["total_score"] += 100

    # Add vulnerability risk factor summary
    for component, pkg in package_risks.items():
        vuln_count = len(pkg["vulns"])
        if vuln_count > 0:
            critical = len([v for v in pkg["vulns"] if v.get("severity") == "CRITICAL"])
            high = len([v for v in pkg["vulns"] if v.get("severity") == "HIGH"])
            kev = len([v for v in pkg["vulns"] if v.get("details", {}).get("is_kev")])

            pkg["risk_factors"].append(
                {
                    "type": "vulnerabilities",
                    "severity": (
                        "CRITICAL"
                        if critical > 0 or kev > 0
                        else ("HIGH" if high > 0 else "MEDIUM")
                    ),
                    "description": f"{vuln_count} vulnerabilities ({critical} critical, {high} high, {kev} KEV)",
                }
            )
            pkg["total_score"] += critical * 50 + high * 20 + vuln_count * 5 + kev * 100

    # Filter to packages with 2+ risk factors
    toxic_packages = [
        (component, pkg)
        for component, pkg in package_risks.items()
        if len(pkg["risk_factors"]) >= 2
    ]

    # Sort by total score
    toxic_packages.sort(key=lambda x: x[1]["total_score"], reverse=True)

    for component, pkg in toxic_packages[:5]:  # Top 5 toxic packages
        risk_descriptions = [r["description"] for r in pkg["risk_factors"]]

        recommendations.append(
            Recommendation(
                type=RecommendationType.TOXIC_DEPENDENCY,
                priority=Priority.HIGH,
                title=f"Toxic Dependency: {component}",
                description=(
                    f"This package has multiple independent risk factors: "
                    f"{' | '.join(risk_descriptions)}. "
                    f"Consider replacing it with a safer alternative."
                ),
                impact={
                    "critical": len(
                        [v for v in pkg["vulns"] if v.get("severity") == "CRITICAL"]
                    ),
                    "high": len(
                        [v for v in pkg["vulns"] if v.get("severity") == "HIGH"]
                    ),
                    "medium": len(
                        [v for v in pkg["vulns"] if v.get("severity") == "MEDIUM"]
                    ),
                    "low": 0,
                    "total": len(pkg["vulns"]),
                    "risk_factor_count": len(pkg["risk_factors"]),
                    "toxic_score": pkg["total_score"],
                },
                affected_components=[
                    f"{component}@{pkg['details'].get('version', 'unknown')}"
                ],
                action={
                    "type": "replace_toxic_dependency",
                    "package": component,
                    "version": pkg["details"].get("version", "unknown"),
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
        )

    return recommendations


def analyze_attack_surface(
    dependencies: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
) -> List[Recommendation]:
    """
    Analyze attack surface and recommend reduction strategies.

    Identifies:
    - Unused or rarely used dependencies with vulnerabilities
    - Dependencies that could be replaced with built-in functionality
    - Heavy dependencies that could be replaced with lighter alternatives
    """
    recommendations = []

    # Count vulnerabilities by package
    vuln_count_by_pkg: Dict[str, int] = defaultdict(int)
    for f in findings:
        if f.get("type") == "vulnerability":
            vuln_count_by_pkg[f.get("component", "")] += 1

    # Identify transitive dependencies with many vulnerabilities
    transitive_with_vulns = []
    for dep in dependencies:
        pkg_name = dep.get("name", "")
        is_direct = dep.get("direct", False)
        vuln_count = vuln_count_by_pkg.get(pkg_name, 0)

        if not is_direct and vuln_count >= 2:
            transitive_with_vulns.append(
                {
                    "name": pkg_name,
                    "version": dep.get("version", "unknown"),
                    "vuln_count": vuln_count,
                    "parent": dep.get("introduced_by", dep.get("parent", "unknown")),
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
                    f"Found {len(transitive_with_vulns)} transitive dependencies contributing {total_vulns} vulnerabilities. "
                    f"Consider updating or replacing their parent dependencies to reduce attack surface."
                ),
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": total_vulns,
                    "low": 0,
                    "total": total_vulns,
                },
                affected_components=[
                    f"{t['name']}@{t['version']} (via {t['parent']})"
                    for t in transitive_with_vulns[:10]
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
    direct_deps = len([d for d in dependencies if d.get("direct", False)])

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
                affected_components=[
                    f"Total: {total_deps} deps, Direct: {direct_deps} deps"
                ],
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
