"""
Recommendation Engine for Security Findings

Analyzes vulnerabilities, secrets, SAST, IAC, and other findings
to generate actionable remediation recommendations.
"""

import logging
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional

from app.schemas.recommendation import (Priority, Recommendation,
                                        RecommendationType, VulnerabilityInfo)

logger = logging.getLogger(__name__)


# OS package types that typically come from base images
OS_PACKAGE_TYPES = {"deb", "rpm", "apk", "alpm", "pacman", "dpkg"}

# Application package types
APP_PACKAGE_TYPES = {
    "npm",
    "pypi",
    "maven",
    "gradle",
    "cargo",
    "gem",
    "nuget",
    "golang",
    "go-module",
    "pip",
    "composer",
}


class RecommendationEngine:
    """
    Generates remediation recommendations based on all finding types:
    - Vulnerabilities (CVEs in dependencies)
    - Secrets (exposed credentials)
    - SAST (code security issues)
    - IAC (infrastructure misconfigurations)
    - License (compliance issues)
    - Quality (supply chain risks)
    - Dependency Health (outdated, unmaintained, fragmented)
    - Trend Analysis (regressions, recurring issues)
    - Dependency Graph (deep chains, duplicates)
    - Cross-Project Patterns (shared vulnerabilities)
    """

    def __init__(self):
        self.severity_weights = {
            "CRITICAL": 100,
            "HIGH": 50,
            "MEDIUM": 20,
            "LOW": 5,
            "NEGLIGIBLE": 1,
            "INFO": 0,
            "UNKNOWN": 10,
        }
        # Packages considered outdated after X days without updates
        self.outdated_threshold_days = 365 * 2  # 2 years
        # Max acceptable depth for transitive dependencies
        self.max_dependency_depth = 5

    async def generate_recommendations(
        self,
        findings: List[Dict[str, Any]],
        dependencies: List[Dict[str, Any]],
        source_target: Optional[str] = None,
        # New parameters for extended analysis
        previous_scan_findings: Optional[List[Dict[str, Any]]] = None,
        scan_history: Optional[List[Dict[str, Any]]] = None,
        cross_project_data: Optional[Dict[str, Any]] = None,
    ) -> List[Recommendation]:
        """
        Generate remediation recommendations based on ALL finding types.

        Args:
            findings: List of all findings (vulnerabilities, secrets, SAST, IAC, etc.)
            dependencies: List of dependencies from the scan
            source_target: The source target (e.g., Docker image name)

        Returns:
            List of prioritized recommendations
        """
        recommendations = []

        # Separate findings by type
        findings_by_type = defaultdict(list)
        for f in findings:
            finding_type = f.get("type", "other")
            findings_by_type[finding_type].append(f)

        # Build lookup maps for dependencies
        dep_by_purl = {d.get("purl"): d for d in dependencies if d.get("purl")}
        dep_by_name_version = {
            f"{d.get('name')}@{d.get('version')}": d for d in dependencies
        }

        # 1. Process VULNERABILITIES
        vuln_findings = findings_by_type.get("vulnerability", [])
        if vuln_findings:
            vuln_recs = await self._process_vulnerabilities(
                vuln_findings,
                dep_by_purl,
                dep_by_name_version,
                dependencies,
                source_target,
            )
            recommendations.extend(vuln_recs)

        # 2. Process SECRETS
        secret_findings = findings_by_type.get("secret", [])
        if secret_findings:
            secret_recs = self._process_secrets(secret_findings)
            recommendations.extend(secret_recs)

        # 3. Process SAST (code security)
        sast_findings = findings_by_type.get("sast", [])
        if sast_findings:
            sast_recs = self._process_sast(sast_findings)
            recommendations.extend(sast_recs)

        # 4. Process IAC (infrastructure as code)
        iac_findings = findings_by_type.get("iac", [])
        if iac_findings:
            iac_recs = self._process_iac(iac_findings)
            recommendations.extend(iac_recs)

        # 5. Process LICENSE issues
        license_findings = findings_by_type.get("license", [])
        if license_findings:
            license_recs = self._process_licenses(license_findings)
            recommendations.extend(license_recs)

        # 6. Process QUALITY issues (maintainer risk, etc.)
        quality_findings = findings_by_type.get("quality", [])
        if quality_findings:
            quality_recs = self._process_quality(quality_findings)
            recommendations.extend(quality_recs)

        # 7. Check for outdated dependencies
        outdated_recs = self._analyze_outdated_dependencies(dependencies)
        recommendations.extend(outdated_recs)

        # 8. Check for version fragmentation (multiple versions of same package)
        fragmentation_recs = self._analyze_version_fragmentation(dependencies)
        recommendations.extend(fragmentation_recs)

        # 9. Check for dev dependencies in production scope
        dev_prod_recs = self._analyze_dev_in_production(dependencies)
        recommendations.extend(dev_prod_recs)

        if previous_scan_findings is not None:
            # 10. Detect regressions (new/reappearing issues)
            regression_recs = self._analyze_regressions(
                findings, previous_scan_findings
            )
            recommendations.extend(regression_recs)

            # 11. Detect recurring vulnerabilities (issues that keep coming back)
            recurring_recs = self._analyze_recurring_issues(
                findings, scan_history or []
            )
            recommendations.extend(recurring_recs)

        # 12. Analyze deep dependency chains
        deep_chain_recs = self._analyze_deep_dependency_chains(dependencies)
        recommendations.extend(deep_chain_recs)

        # 13. Detect duplicate functionality (similar packages)
        duplicate_recs = self._analyze_duplicate_packages(dependencies)
        recommendations.extend(duplicate_recs)

        if cross_project_data:
            # 14. Find patterns across user's projects
            cross_project_recs = self._analyze_cross_project_patterns(
                findings, dependencies, cross_project_data
            )
            recommendations.extend(cross_project_recs)

        # 15. Identify high-risk vulnerabilities in poorly maintained packages
        scorecard_vuln_recs = self._correlate_scorecard_with_vulnerabilities(
            vuln_findings, quality_findings
        )
        recommendations.extend(scorecard_vuln_recs)

        # 16. Detect critical hotspots (packages with multiple severe issues)
        hotspot_recs = self._detect_critical_hotspots(
            findings, dependencies, dep_by_purl, dep_by_name_version
        )
        recommendations.extend(hotspot_recs)

        # 17. Known Exploit / KEV / Ransomware recommendations
        exploit_recs = self._detect_known_exploits(vuln_findings)
        recommendations.extend(exploit_recs)

        # 18. Malware detection recommendations
        malware_findings = findings_by_type.get("malware", [])
        if malware_findings:
            malware_recs = self._process_malware(malware_findings)
            recommendations.extend(malware_recs)

        # 19. Typosquatting detection recommendations
        typosquat_findings = [
            f
            for f in quality_findings
            if "typosquat" in f.get("details", {}).get("risk_type", "").lower()
        ]
        if typosquat_findings:
            typosquat_recs = self._process_typosquatting(typosquat_findings)
            recommendations.extend(typosquat_recs)

        # 20. End-of-Life dependencies
        eol_findings = findings_by_type.get("eol", [])
        if eol_findings:
            eol_recs = self._process_end_of_life(eol_findings)
            recommendations.extend(eol_recs)

        # 21. Quick Wins - high impact, low effort
        quick_win_recs = self._identify_quick_wins(vuln_findings, dependencies)
        recommendations.extend(quick_win_recs)

        # 22. Toxic Dependencies - multiple risk factors combined
        toxic_recs = self._detect_toxic_dependencies(
            findings, dependencies, dep_by_purl, dep_by_name_version
        )
        recommendations.extend(toxic_recs)

        # 23. Attack Surface Reduction
        attack_surface_recs = self._analyze_attack_surface(dependencies, findings)
        recommendations.extend(attack_surface_recs)

        # Sort by priority and impact
        recommendations.sort(key=lambda r: self._recommendation_score(r), reverse=True)

        return recommendations

    async def _process_vulnerabilities(
        self,
        findings: List[Dict[str, Any]],
        dep_by_purl: Dict[str, Dict],
        dep_by_name_version: Dict[str, Dict],
        dependencies: List[Dict[str, Any]],
        source_target: Optional[str],
    ) -> List[Recommendation]:
        """Process vulnerability findings."""
        recommendations = []

        # Categorize vulnerabilities by source
        vulns_by_source = self._categorize_by_source(
            findings, dep_by_purl, dep_by_name_version
        )

        # 1. Check for base image update recommendation
        base_image_rec = self._analyze_base_image_vulns(
            vulns_by_source.get("image", []), dependencies, source_target
        )
        if base_image_rec:
            recommendations.append(base_image_rec)

        # 2. Analyze direct dependency updates
        direct_recs = self._analyze_direct_dependencies(
            vulns_by_source.get("application", []), dep_by_purl, dep_by_name_version
        )
        recommendations.extend(direct_recs)

        # 3. Analyze transitive dependencies
        transitive_recs = self._analyze_transitive_dependencies(
            vulns_by_source.get("transitive", []), dependencies
        )
        recommendations.extend(transitive_recs)

        # 4. Handle vulns with no fix
        no_fix_recs = self._analyze_no_fix_vulns(vulns_by_source.get("no_fix", []))
        recommendations.extend(no_fix_recs)

        return recommendations

    def _process_secrets(self, findings: List[Dict[str, Any]]) -> List[Recommendation]:
        """Process secret/credential findings."""
        if not findings:
            return []

        # Group secrets by type/detector
        secrets_by_type = defaultdict(list)
        for f in findings:
            details = f.get("details", {})
            detector = (
                details.get("detector_type") or details.get("rule_id") or "generic"
            )
            secrets_by_type[detector].append(f)

        recommendations = []

        # Count severities
        severity_counts = defaultdict(int)
        files_affected = set()

        for f in findings:
            severity_counts[f.get("severity", "UNKNOWN")] += 1
            component = f.get("component", "")
            if component:
                files_affected.add(component)

        # Determine priority
        if severity_counts.get("CRITICAL", 0) > 0 or severity_counts.get("HIGH", 0) > 0:
            priority = Priority.CRITICAL  # Secrets are always critical
        else:
            priority = Priority.HIGH

        # Create main recommendation
        secret_types = list(secrets_by_type.keys())[:5]

        recommendations.append(
            Recommendation(
                type=RecommendationType.ROTATE_SECRETS,
                priority=priority,
                title="Rotate Exposed Credentials",
                description=(
                    f"Found {len(findings)} exposed secrets/credentials in {len(files_affected)} files. "
                    f"These include: {', '.join(secret_types)}. "
                    f"Immediately rotate all affected credentials and remove from code."
                ),
                impact={
                    "critical": severity_counts.get("CRITICAL", 0),
                    "high": severity_counts.get("HIGH", 0),
                    "medium": severity_counts.get("MEDIUM", 0),
                    "low": severity_counts.get("LOW", 0),
                    "total": len(findings),
                },
                affected_components=list(files_affected)[:20],
                action={
                    "type": "rotate_secrets",
                    "secret_types": secret_types,
                    "files": list(files_affected)[:10],
                    "steps": [
                        "1. Immediately rotate/regenerate all exposed credentials",
                        "2. Update applications using these credentials",
                        "3. Remove secrets from code and use environment variables or secret managers",
                        "4. Add secret patterns to .gitignore and pre-commit hooks",
                        "5. Scan git history for previously committed secrets",
                    ],
                },
                effort="high",
            )
        )

        return recommendations

    def _process_sast(self, findings: List[Dict[str, Any]]) -> List[Recommendation]:
        """Process SAST (Static Application Security Testing) findings."""
        if not findings:
            return []

        # Group by rule/category
        findings_by_category = defaultdict(list)
        for f in findings:
            details = f.get("details", {})
            category = (
                details.get("category")
                or details.get("rule_id")
                or details.get("check_id")
                or "security"
            )
            # Normalize category
            category_lower = category.lower()
            if "inject" in category_lower or "sqli" in category_lower:
                category = "Injection"
            elif "xss" in category_lower or "cross-site" in category_lower:
                category = "XSS"
            elif "auth" in category_lower:
                category = "Authentication"
            elif "crypto" in category_lower or "cipher" in category_lower:
                category = "Cryptography"
            elif "path" in category_lower or "traversal" in category_lower:
                category = "Path Traversal"

            findings_by_category[category].append(f)

        recommendations = []

        # Create recommendations per category if significant
        for category, cat_findings in findings_by_category.items():
            severity_counts = defaultdict(int)
            files_affected = set()

            for f in cat_findings:
                severity_counts[f.get("severity", "UNKNOWN")] += 1
                files_affected.add(f.get("component", "unknown"))

            critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get(
                "HIGH", 0
            )

            # Only create recommendations for significant issues
            if critical_high < 1 and len(cat_findings) < 3:
                continue

            if severity_counts.get("CRITICAL", 0) > 0:
                priority = Priority.CRITICAL
            elif severity_counts.get("HIGH", 0) > 0:
                priority = Priority.HIGH
            elif severity_counts.get("MEDIUM", 0) > 0:
                priority = Priority.MEDIUM
            else:
                priority = Priority.LOW

            recommendations.append(
                Recommendation(
                    type=RecommendationType.FIX_CODE_SECURITY,
                    priority=priority,
                    title=f"Fix {category} Issues",
                    description=(
                        f"Found {len(cat_findings)} {category} security issues in {len(files_affected)} files. "
                        f"Includes {severity_counts.get('CRITICAL', 0)} critical and "
                        f"{severity_counts.get('HIGH', 0)} high severity issues."
                    ),
                    impact={
                        "critical": severity_counts.get("CRITICAL", 0),
                        "high": severity_counts.get("HIGH", 0),
                        "medium": severity_counts.get("MEDIUM", 0),
                        "low": severity_counts.get("LOW", 0),
                        "total": len(cat_findings),
                    },
                    affected_components=list(files_affected)[:20],
                    action={
                        "type": "fix_code",
                        "category": category,
                        "files": list(files_affected)[:10],
                        "rules": list(
                            set(
                                f.get("details", {}).get("rule_id", "")
                                for f in cat_findings
                                if f.get("details", {}).get("rule_id")
                            )
                        )[:10],
                    },
                    effort="medium" if len(cat_findings) < 10 else "high",
                )
            )

        return recommendations

    def _process_iac(self, findings: List[Dict[str, Any]]) -> List[Recommendation]:
        """Process IAC (Infrastructure as Code) findings."""
        if not findings:
            return []

        # Group by platform/category
        findings_by_platform = defaultdict(list)
        for f in findings:
            details = f.get("details", {})
            platform = (
                details.get("platform") or details.get("query_name", "").split(".")[0]
                if details.get("query_name")
                else "infrastructure"
            )
            # Normalize platform
            platform_lower = platform.lower()
            if "docker" in platform_lower:
                platform = "Docker"
            elif "kubernetes" in platform_lower or "k8s" in platform_lower:
                platform = "Kubernetes"
            elif "terraform" in platform_lower:
                platform = "Terraform"
            elif "cloudformation" in platform_lower or "aws" in platform_lower:
                platform = "AWS/CloudFormation"
            elif "ansible" in platform_lower:
                platform = "Ansible"
            elif "helm" in platform_lower:
                platform = "Helm"

            findings_by_platform[platform].append(f)

        recommendations = []

        for platform, plat_findings in findings_by_platform.items():
            severity_counts = defaultdict(int)
            files_affected = set()

            for f in plat_findings:
                severity_counts[f.get("severity", "UNKNOWN")] += 1
                files_affected.add(f.get("component", "unknown"))

            critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get(
                "HIGH", 0
            )

            if critical_high < 1 and len(plat_findings) < 3:
                continue

            if severity_counts.get("CRITICAL", 0) > 0:
                priority = Priority.CRITICAL
            elif severity_counts.get("HIGH", 0) > 0:
                priority = Priority.HIGH
            elif severity_counts.get("MEDIUM", 0) > 0:
                priority = Priority.MEDIUM
            else:
                priority = Priority.LOW

            recommendations.append(
                Recommendation(
                    type=RecommendationType.FIX_INFRASTRUCTURE,
                    priority=priority,
                    title=f"Fix {platform} Misconfigurations",
                    description=(
                        f"Found {len(plat_findings)} infrastructure security issues in {platform} configurations. "
                        f"Includes {severity_counts.get('CRITICAL', 0)} critical and "
                        f"{severity_counts.get('HIGH', 0)} high severity misconfigurations."
                    ),
                    impact={
                        "critical": severity_counts.get("CRITICAL", 0),
                        "high": severity_counts.get("HIGH", 0),
                        "medium": severity_counts.get("MEDIUM", 0),
                        "low": severity_counts.get("LOW", 0),
                        "total": len(plat_findings),
                    },
                    affected_components=list(files_affected)[:20],
                    action={
                        "type": "fix_infrastructure",
                        "platform": platform,
                        "files": list(files_affected)[:10],
                        "common_issues": self._get_common_iac_issues(plat_findings),
                    },
                    effort="medium",
                )
            )

        return recommendations

    def _get_common_iac_issues(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Extract common IAC issue types."""
        issues = defaultdict(int)
        for f in findings:
            details = f.get("details", {})
            issue_type = (
                details.get("query_name")
                or details.get("check_id")
                or f.get("description", "")[:50]
            )
            issues[issue_type] += 1

        # Sort by frequency and return top 5
        sorted_issues = sorted(issues.items(), key=lambda x: x[1], reverse=True)
        return [issue for issue, count in sorted_issues[:5]]

    def _process_licenses(self, findings: List[Dict[str, Any]]) -> List[Recommendation]:
        """Process license compliance findings."""
        if not findings:
            return []

        # Group by license type
        by_license = defaultdict(list)
        for f in findings:
            details = f.get("details", {})
            license_name = (
                details.get("license") or details.get("license_id") or "unknown"
            )
            by_license[license_name].append(f)

        severity_counts = defaultdict(int)
        components = set()

        for f in findings:
            severity_counts[f.get("severity", "UNKNOWN")] += 1
            components.add(f.get("component", "unknown"))

        if severity_counts.get("CRITICAL", 0) > 0:
            priority = Priority.CRITICAL
        elif severity_counts.get("HIGH", 0) > 0:
            priority = Priority.HIGH
        else:
            priority = Priority.MEDIUM

        problematic_licenses = list(by_license.keys())[:10]

        return [
            Recommendation(
                type=RecommendationType.LICENSE_COMPLIANCE,
                priority=priority,
                title="Resolve License Compliance Issues",
                description=(
                    f"Found {len(findings)} license compliance issues across {len(components)} components. "
                    f"Problematic licenses include: {', '.join(problematic_licenses[:5])}."
                ),
                impact={
                    "critical": severity_counts.get("CRITICAL", 0),
                    "high": severity_counts.get("HIGH", 0),
                    "medium": severity_counts.get("MEDIUM", 0),
                    "low": severity_counts.get("LOW", 0),
                    "total": len(findings),
                },
                affected_components=list(components)[:20],
                action={
                    "type": "license_compliance",
                    "problematic_licenses": problematic_licenses,
                    "steps": [
                        "Review license compatibility with your project's license",
                        "Consider replacing components with restrictive licenses",
                        "Consult legal team for commercial license requirements",
                        "Document license decisions and exceptions",
                    ],
                },
                effort="medium",
            )
        ]

    def _process_quality(self, findings: List[Dict[str, Any]]) -> List[Recommendation]:
        """Process supply chain quality findings from OpenSSF Scorecard."""
        if not findings:
            return []

        recommendations = []
        severity_counts = defaultdict(int)
        components_by_issue = defaultdict(list)  # issue_type -> [components]
        low_score_packages = []  # Packages with very low scores
        unmaintained_packages = []

        for f in findings:
            severity = f.get("severity", "UNKNOWN")
            severity_counts[severity] += 1
            component = f.get("component", "unknown")
            version = f.get("version", "")
            details = f.get("details", {})

            overall_score = details.get("overall_score", 0)
            critical_issues = details.get("critical_issues", [])
            failed_checks = details.get("failed_checks", [])
            project_url = details.get("project_url", "")

            # Track packages with very low scores
            if overall_score < 4.0:
                low_score_packages.append(
                    {
                        "component": component,
                        "version": version,
                        "score": overall_score,
                        "project_url": project_url,
                        "critical_issues": critical_issues,
                    }
                )

            # Track by issue type
            if "Maintained" in critical_issues:
                unmaintained_packages.append(
                    {
                        "component": component,
                        "version": version,
                        "score": overall_score,
                        "project_url": project_url,
                    }
                )

            for issue in critical_issues:
                components_by_issue[issue].append(component)

            # Also categorize by failed checks
            for check in failed_checks:
                check_name = check.get("name", "") if isinstance(check, dict) else check
                components_by_issue[f"check:{check_name}"].append(component)

        # 1. Generate recommendation for unmaintained packages (highest priority)
        if unmaintained_packages:
            recommendations.append(
                Recommendation(
                    type=RecommendationType.SUPPLY_CHAIN_RISK,
                    priority=Priority.HIGH,
                    title="Replace Unmaintained Dependencies",
                    description=(
                        f"Found {len(unmaintained_packages)} potentially unmaintained packages. "
                        "These packages may not receive security updates, putting your application at risk."
                    ),
                    impact={
                        "total": len(unmaintained_packages),
                        "packages": [
                            p["component"] for p in unmaintained_packages[:10]
                        ],
                    },
                    affected_components=[p["component"] for p in unmaintained_packages],
                    action={
                        "type": "replace_unmaintained",
                        "steps": [
                            "Identify which unmaintained packages are critical to your application",
                            "Search for actively maintained alternatives on npm/pypi/crates.io",
                            "Consider forking critical packages if no alternatives exist",
                            "Create a migration plan for each unmaintained dependency",
                            "Monitor OpenSSF Scorecard for updates to maintenance status",
                        ],
                        "packages": [
                            {
                                "name": p["component"],
                                "score": p["score"],
                                "url": p.get("project_url"),
                            }
                            for p in unmaintained_packages[:10]
                        ],
                    },
                    effort="high",
                )
            )

        # 2. Generate recommendation for packages with critical security issues
        vuln_packages = components_by_issue.get("Vulnerabilities", [])
        if vuln_packages:
            recommendations.append(
                Recommendation(
                    type=RecommendationType.SUPPLY_CHAIN_RISK,
                    priority=Priority.HIGH,
                    title="Address Packages with Known Vulnerability Issues",
                    description=(
                        f"{len(vuln_packages)} packages have unaddressed security vulnerabilities "
                        "according to OpenSSF Scorecard. These need immediate attention."
                    ),
                    impact={
                        "total": len(vuln_packages),
                    },
                    affected_components=list(set(vuln_packages))[:20],
                    action={
                        "type": "fix_scorecard_vulnerabilities",
                        "steps": [
                            "Check for available security patches or updates",
                            "Review CVE databases for specific vulnerabilities",
                            "Apply patches or upgrade to fixed versions",
                            "If no fix is available, consider alternatives",
                        ],
                    },
                    effort="medium",
                )
            )

        # 3. Generate recommendation for low-score packages (general quality concern)
        if (
            low_score_packages and not unmaintained_packages
        ):  # Don't duplicate if already covered
            recommendations.append(
                Recommendation(
                    type=RecommendationType.SUPPLY_CHAIN_RISK,
                    priority=Priority.MEDIUM,
                    title="Review Low-Quality Dependencies",
                    description=(
                        f"Found {len(low_score_packages)} packages with OpenSSF Scorecard scores below 4.0/10. "
                        "These packages may have quality, security, or maintenance concerns."
                    ),
                    impact={
                        "total": len(low_score_packages),
                        "average_score": sum(p["score"] for p in low_score_packages)
                        / len(low_score_packages),
                    },
                    affected_components=[p["component"] for p in low_score_packages],
                    action={
                        "type": "review_quality",
                        "steps": [
                            "Review OpenSSF Scorecard details for each package",
                            "Assess if package is critical to your application",
                            "Consider alternatives with higher scorecard ratings",
                            "For critical packages, contribute to improving their security practices",
                        ],
                        "packages": [
                            {
                                "name": p["component"],
                                "score": p["score"],
                                "issues": p.get("critical_issues", []),
                            }
                            for p in sorted(
                                low_score_packages, key=lambda x: x["score"]
                            )[:10]
                        ],
                    },
                    effort="medium",
                )
            )

        # 4. Generate recommendations for specific check failures
        code_review_issues = components_by_issue.get("check:Code-Review", [])
        if code_review_issues:
            recommendations.append(
                Recommendation(
                    type=RecommendationType.SUPPLY_CHAIN_RISK,
                    priority=Priority.LOW,
                    title="Dependencies with Limited Code Review",
                    description=(
                        f"{len(set(code_review_issues))} packages have limited or no code review processes. "
                        "This increases the risk of unreviewed malicious or buggy changes."
                    ),
                    impact={"total": len(set(code_review_issues))},
                    affected_components=list(set(code_review_issues))[:15],
                    action={
                        "type": "code_review_concern",
                        "steps": [
                            "Monitor these packages more closely for updates",
                            "Review changelogs before updating",
                            "Consider pinning versions and manually reviewing changes",
                        ],
                    },
                    effort="low",
                )
            )

        # Fallback: if no specific recommendations were generated
        if not recommendations and findings:
            priority = (
                Priority.MEDIUM if severity_counts.get("HIGH", 0) > 0 else Priority.LOW
            )
            recommendations.append(
                Recommendation(
                    type=RecommendationType.SUPPLY_CHAIN_RISK,
                    priority=priority,
                    title="Review Supply Chain Quality",
                    description=(
                        f"Found {len(findings)} supply chain quality observations from OpenSSF Scorecard. "
                        f"Distribution: {severity_counts.get('HIGH', 0)} high, "
                        f"{severity_counts.get('MEDIUM', 0)} medium, {severity_counts.get('LOW', 0)} low."
                    ),
                    impact={
                        "critical": severity_counts.get("CRITICAL", 0),
                        "high": severity_counts.get("HIGH", 0),
                        "medium": severity_counts.get("MEDIUM", 0),
                        "low": severity_counts.get("LOW", 0),
                        "total": len(findings),
                    },
                    affected_components=list(set(f.get("component") for f in findings))[
                        :20
                    ],
                    action={
                        "type": "supply_chain_review",
                        "steps": [
                            "Review OpenSSF Scorecard details for flagged packages",
                            "Prioritize packages with multiple failed checks",
                            "Consider alternatives for poorly-scoring packages",
                            "Monitor scorecard updates over time",
                        ],
                    },
                    effort="medium",
                )
            )

        return recommendations

    def _categorize_by_source(
        self,
        findings: List[Dict[str, Any]],
        dep_by_purl: Dict[str, Dict],
        dep_by_name_version: Dict[str, Dict],
    ) -> Dict[str, List[VulnerabilityInfo]]:
        """Categorize vulnerabilities by their source type."""

        categories = defaultdict(list)

        for f in findings:
            if f.get("type") != "vulnerability":
                continue

            details = f.get("details", {})
            component = f.get("component", "")
            version = f.get("version", "")

            # Extract fixed version
            fixed_version = details.get("fixed_version")

            # Try to find the dependency
            purl = details.get("purl") or details.get("package_url")
            dep = None

            if purl and purl in dep_by_purl:
                dep = dep_by_purl[purl]
            elif f"{component}@{version}" in dep_by_name_version:
                dep = dep_by_name_version[f"{component}@{version}"]

            # Extract CVE ID
            cve_id = f.get("id")
            if not cve_id or not cve_id.startswith("CVE-"):
                # Check aliases
                for alias in f.get("aliases", []):
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break

            # Extract EPSS/KEV/Reachability data from details
            epss_score = details.get("epss_score")
            is_kev = details.get("is_kev", False)
            kev_ransomware = details.get("kev_ransomware", False)
            risk_score = details.get("risk_score")

            # Reachability comes from finding-level, not details
            is_reachable = f.get("reachable")
            reachability_level = f.get("reachability_level")

            vuln_info = VulnerabilityInfo(
                finding_id=f.get("id", ""),
                cve_id=cve_id,
                severity=f.get("severity", "UNKNOWN"),
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
                source_type = dep.get("source_type", "")
                is_direct = dep.get("direct", False)

                if source_type == "image" or self._is_os_package(dep):
                    categories["image"].append(vuln_info)
                elif is_direct:
                    categories["application"].append(vuln_info)
                else:
                    categories["transitive"].append(vuln_info)
            else:
                # No dependency info, assume application
                categories["application"].append(vuln_info)

        return categories

    def _is_os_package(self, dep: Dict[str, Any]) -> bool:
        """Check if a dependency is an OS-level package."""
        pkg_type = dep.get("type", "").lower()
        purl = dep.get("purl", "")

        # Check type
        if pkg_type in OS_PACKAGE_TYPES:
            return True

        # Check PURL prefix
        for os_type in OS_PACKAGE_TYPES:
            if purl.startswith(f"pkg:{os_type}/"):
                return True

        return False

    def _analyze_base_image_vulns(
        self,
        vulns: List[VulnerabilityInfo],
        dependencies: List[Dict[str, Any]],
        source_target: Optional[str],
    ) -> Optional[Recommendation]:
        """Analyze if a base image update would be beneficial."""

        if not vulns:
            return None

        # Count severities
        severity_counts = defaultdict(int)
        affected_packages = set()

        for v in vulns:
            severity_counts[v.severity] += 1
            affected_packages.add(v.package_name)

        total_vulns = len(vulns)
        critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get(
            "HIGH", 0
        )

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
        self,
        vulns: List[VulnerabilityInfo],
        dep_by_purl: Dict[str, Dict],
        dep_by_name_version: Dict[str, Dict],
    ) -> List[Recommendation]:
        """Analyze direct dependency updates with EPSS/KEV/Reachability prioritization."""

        recommendations = []

        # Group vulns by component
        vulns_by_component = defaultdict(list)
        for v in vulns:
            vulns_by_component[v.package_name].append(v)

        for component, component_vulns in vulns_by_component.items():
            # Find the best fix version (one that fixes all vulns)
            fixed_versions = [
                v.fixed_version for v in component_vulns if v.fixed_version
            ]

            if not fixed_versions:
                continue

            # Get current version
            current_version = (
                component_vulns[0].current_version if component_vulns else "unknown"
            )

            # Calculate best fixed version
            best_fix = self._calculate_best_fix_version(fixed_versions)

            # Count severities and gather threat intelligence stats
            severity_counts = defaultdict(int)
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
                # Check if critical vulns are unreachable - might downgrade
                critical_unreachable = all(
                    v.is_reachable is False
                    for v in component_vulns
                    if v.severity == "CRITICAL"
                )
                if critical_unreachable and unreachable_count == len(component_vulns):
                    priority = Priority.MEDIUM  # Downgrade if all unreachable
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
                desc_parts.append(
                    "All vulnerabilities are unreachable - lower priority."
                )

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
        self, vulns: List[VulnerabilityInfo], dependencies: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """Analyze transitive dependency vulnerabilities with EPSS/KEV/Reachability prioritization."""

        recommendations = []

        # Group by component
        vulns_by_component = defaultdict(list)
        for v in vulns:
            vulns_by_component[v.package_name].append(v)

        for component, component_vulns in vulns_by_component.items():
            fixed_versions = [
                v.fixed_version for v in component_vulns if v.fixed_version
            ]

            if not fixed_versions:
                continue

            current_version = (
                component_vulns[0].current_version if component_vulns else "unknown"
            )
            best_fix = self._calculate_best_fix_version(fixed_versions)

            # Count severities and gather threat intelligence stats
            severity_counts = defaultdict(int)
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
                if unreachable_count == len(component_vulns):
                    priority = Priority.MEDIUM
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
                        "suggestions": [
                            "Update parent dependencies that depend on this package",
                            "Use dependency override/resolution in your package manager",
                            "For npm: Add to 'overrides' in package.json",
                            "For Maven: Add to 'dependencyManagement'",
                            "For pip: Pin the version directly in requirements.txt",
                        ],
                    },
                    effort="medium",
                )
            )

        return recommendations

        return recommendations

    def _analyze_no_fix_vulns(
        self, vulns: List[VulnerabilityInfo]
    ) -> List[Recommendation]:
        """Analyze vulnerabilities with no known fix."""

        if not vulns:
            return []

        # Group by component
        vulns_by_component = defaultdict(list)
        for v in vulns:
            vulns_by_component[v.package_name].append(v)

        recommendations = []

        # Only create recommendations for high-impact no-fix vulns
        for component, component_vulns in vulns_by_component.items():
            severity_counts = defaultdict(int)
            cves = []

            for v in component_vulns:
                severity_counts[v.severity] += 1
                if v.cve_id:
                    cves.append(v.cve_id)

            critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get(
                "HIGH", 0
            )

            if critical_high == 0:
                continue  # Skip low-severity no-fix vulns

            if severity_counts.get("CRITICAL", 0) > 0:
                priority = Priority.HIGH  # Downgrade from critical since no fix
            else:
                priority = Priority.MEDIUM

            current_version = (
                component_vulns[0].current_version if component_vulns else "unknown"
            )

            recommendations.append(
                Recommendation(
                    type=RecommendationType.NO_FIX_AVAILABLE,
                    priority=priority,
                    title=f"No fix available for {component}",
                    description=(
                        f"{component}@{current_version} has {len(component_vulns)} vulnerabilities "
                        f"with no known fix. Consider alternatives or apply mitigating controls."
                    ),
                    impact={
                        "critical": severity_counts.get("CRITICAL", 0),
                        "high": severity_counts.get("HIGH", 0),
                        "medium": severity_counts.get("MEDIUM", 0),
                        "low": severity_counts.get("LOW", 0),
                        "total": len(component_vulns),
                    },
                    affected_components=[component],
                    action={
                        "type": "no_fix",
                        "package": component,
                        "version": current_version,
                        "cves": cves[:10],
                        "options": [
                            "Monitor for fix availability",
                            "Consider alternative packages",
                            "Apply compensating controls (WAF, network segmentation, etc.)",
                            "Create a waiver if risk is accepted",
                        ],
                    },
                    effort="high",
                )
            )

        return recommendations

    def _calculate_best_fix_version(self, versions: List[str]) -> str:
        """Calculate the best version that fixes all vulnerabilities."""
        if not versions:
            return "unknown"

        if len(versions) == 1:
            return versions[0]

        # Parse and find the highest version
        parsed = []
        for v in versions:
            # Handle comma-separated versions (multiple options)
            for part in v.split(","):
                part = part.strip()
                if part:
                    parsed.append(part)

        if not parsed:
            return versions[0]

        # Sort by version (best effort)
        try:
            parsed.sort(key=lambda x: self._parse_version_tuple(x), reverse=True)
            return parsed[0]
        except Exception:
            return parsed[0]

    def _parse_version_tuple(self, version: str) -> tuple:
        """Parse a version string into a comparable tuple."""
        # Extract numeric parts
        parts = re.findall(r"\d+", version)
        return tuple(int(p) for p in parts)

    def _recommendation_score(self, rec: Recommendation) -> int:
        """
        Calculate a score for sorting recommendations.

        Incorporates EPSS/KEV/Reachability data for intelligent prioritization:
        - KEV findings get significant boost (known exploited in wild)
        - High EPSS findings get boost (likely to be exploited)
        - Reachable findings get boost (actually affect the application)
        - Unreachable findings get deprioritized
        """
        priority_scores = {
            Priority.CRITICAL: 10000,
            Priority.HIGH: 1000,
            Priority.MEDIUM: 100,
            Priority.LOW: 10,
        }

        base_score = priority_scores.get(rec.priority, 0)

        # Add impact score
        impact_score = (
            rec.impact.get("critical", 0) * 100
            + rec.impact.get("high", 0) * 50
            + rec.impact.get("medium", 0) * 20
            + rec.impact.get("low", 0) * 5
        )

        threat_intel_score = 0

        # KEV bonus: Known exploited vulnerabilities are highest priority
        kev_count = rec.impact.get("kev_count", 0)
        if kev_count > 0:
            threat_intel_score += kev_count * 500  # Major boost for KEV findings

        # KEV Ransomware: Even higher priority if ransomware campaigns use it
        kev_ransomware_count = rec.impact.get("kev_ransomware_count", 0)
        if kev_ransomware_count > 0:
            threat_intel_score += kev_ransomware_count * 250  # Additional boost

        # High EPSS bonus: Vulnerabilities likely to be exploited soon
        high_epss_count = rec.impact.get("high_epss_count", 0)
        if high_epss_count > 0:
            threat_intel_score += high_epss_count * 200

        # Medium EPSS: Some probability of exploitation
        medium_epss_count = rec.impact.get("medium_epss_count", 0)
        if medium_epss_count > 0:
            threat_intel_score += medium_epss_count * 50

        # Active exploitation: Currently being exploited in the wild
        active_exploitation = rec.impact.get("active_exploitation_count", 0)
        if active_exploitation > 0:
            threat_intel_score += active_exploitation * 300

        reachability_modifier = 1.0

        # Reachable vulnerabilities are more important
        reachable_count = rec.impact.get("reachable_count", 0)
        reachable_critical = rec.impact.get("reachable_critical", 0)
        reachable_high = rec.impact.get("reachable_high", 0)

        if reachable_count > 0:
            # Boost for confirmed reachable vulns
            threat_intel_score += reachable_critical * 150
            threat_intel_score += reachable_high * 75
            threat_intel_score += (
                reachable_count - reachable_critical - reachable_high
            ) * 25

        # Unreachable vulnerabilities should be deprioritized
        unreachable_count = rec.impact.get("unreachable_count", 0)
        if unreachable_count > 0 and rec.impact.get("total", 1) > 0:
            unreachable_ratio = unreachable_count / rec.impact.get("total", 1)
            # If mostly unreachable, reduce priority significantly
            if unreachable_ratio > 0.8:
                reachability_modifier = 0.4
            elif unreachable_ratio > 0.5:
                reachability_modifier = 0.7

        actionable_count = rec.impact.get("actionable_count", 0)
        if actionable_count > 0:
            # Actionable vulns are the ones that matter most
            threat_intel_score += actionable_count * 100

        # Prefer lower effort
        effort_bonus = {"low": 50, "medium": 20, "high": 0}.get(rec.effort, 0)

        # Type-based bonus - prioritize critical security issues
        type_bonus = {
            # Critical security issues - highest priority
            RecommendationType.MALWARE_DETECTED: 5000,
            RecommendationType.RANSOMWARE_RISK: 4000,
            RecommendationType.KNOWN_EXPLOIT: 3000,
            RecommendationType.ACTIVELY_EXPLOITED: 2500,
            RecommendationType.CRITICAL_HOTSPOT: 2000,
            RecommendationType.TYPOSQUAT_DETECTED: 1500,
            # High impact updates
            RecommendationType.BASE_IMAGE_UPDATE: 500,
            RecommendationType.SINGLE_UPDATE_MULTI_FIX: 400,
            RecommendationType.QUICK_WIN: 300,
            RecommendationType.TOXIC_DEPENDENCY: 250,
            # Standard updates
            RecommendationType.DIRECT_DEPENDENCY_UPDATE: 100,
            RecommendationType.EOL_DEPENDENCY: 80,
            RecommendationType.TRANSITIVE_FIX_VIA_PARENT: 50,
            # Secrets are always urgent
            RecommendationType.ROTATE_SECRETS: 2000,
            # Other security
            RecommendationType.FIX_INFRASTRUCTURE: 100,
            RecommendationType.FIX_CODE_SECURITY: 80,
            RecommendationType.SUPPLY_CHAIN_RISK: 60,
            RecommendationType.ATTACK_SURFACE_REDUCTION: 40,
        }.get(rec.type, 0)

        # Calculate final score with reachability modifier
        total_score = (
            base_score + impact_score + threat_intel_score + effort_bonus + type_bonus
        )
        return int(total_score * reachability_modifier)

    # ========================================================================
    # DEPENDENCY HEALTH & HYGIENE ANALYSIS
    # ========================================================================

    def _analyze_outdated_dependencies(
        self, dependencies: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """
        Identify dependencies that appear to be outdated based on version patterns.
        Checks for:
        - Very old major versions (e.g., v1.x when v5.x exists commonly)
        - Dependencies without recent activity indicators
        """
        recommendations = []

        # Known outdated patterns for common packages
        # Format: package_name (exact or starts with) -> (min_recommended_major, message, match_type)
        # match_type: "exact" = exact match, "startswith" = name starts with pattern, "contains" = pattern in name
        known_outdated = {
            # JavaScript/Frontend frameworks - use "exact" or "startswith" to avoid false matches
            "react": (
                18,
                "React 18+ offers concurrent features and better performance",
                "exact",
            ),
            "@angular/core": (
                15,
                "Consider upgrading to Angular 15+ for better performance",
                "exact",
            ),
            "vue": (
                3,
                "Vue 3 offers Composition API and improved TypeScript support",
                "exact",
            ),
            # Python frameworks - exact matches only
            "django": (
                4,
                "Django 4+ offers async support and improved security",
                "exact",
            ),
            "flask": (2, "Flask 2+ has async support and improved CLI", "exact"),
            # Node.js packages
            "express": (4, "Express 4+ is the stable maintained version", "exact"),
            "lodash": (4, "Lodash 4+ is the current stable release", "exact"),
            # Deprecated packages
            "jquery": (
                3,
                "Consider migrating away from jQuery to modern frameworks",
                "exact",
            ),
            "moment": (
                2,
                "Consider migrating to date-fns or dayjs - moment is in maintenance mode",
                "exact",
            ),
            "request": (
                2,
                "The 'request' package is deprecated - use axios or node-fetch",
                "exact",
            ),
        }

        outdated_deps = []

        for dep in dependencies:
            name = dep.get("name", "").lower()
            version = dep.get("version", "")

            # Skip python library packages (python3-*, python-*, *-python)
            # These are NOT Python interpreter versions
            if (
                name.startswith("python3-")
                or name.startswith("python-")
                or name.endswith("-python")
            ):
                continue

            # Check against known patterns with proper matching
            for pattern, (min_major, message, match_type) in known_outdated.items():
                matched = False
                if match_type == "exact":
                    matched = name == pattern
                elif match_type == "startswith":
                    matched = name.startswith(pattern)
                elif match_type == "contains":
                    matched = pattern in name

                if matched:
                    try:
                        # Extract major version
                        major = int(re.search(r"^v?(\d+)", version).group(1))
                        if major < min_major:
                            outdated_deps.append(
                                {
                                    "name": dep.get("name"),
                                    "version": version,
                                    "recommended_major": min_major,
                                    "message": message,
                                    "direct": dep.get("direct", False),
                                }
                            )
                    except (AttributeError, ValueError):
                        pass

        # Group by priority (direct deps are more important)
        direct_outdated = [d for d in outdated_deps if d.get("direct")]
        transitive_outdated = [d for d in outdated_deps if not d.get("direct")]

        if direct_outdated:
            recommendations.append(
                Recommendation(
                    type=RecommendationType.OUTDATED_DEPENDENCY,
                    priority=Priority.MEDIUM,
                    title=f"Upgrade {len(direct_outdated)} outdated direct dependencies",
                    description="Some direct dependencies are using significantly outdated major versions. Upgrading can improve security, performance, and maintainability.",
                    impact={
                        "critical": 0,
                        "high": 0,
                        "medium": len(direct_outdated),
                        "low": 0,
                        "total": len(direct_outdated),
                    },
                    affected_components=[
                        f"{d['name']}@{d['version']}" for d in direct_outdated
                    ],
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

        if len(transitive_outdated) > 3:
            recommendations.append(
                Recommendation(
                    type=RecommendationType.OUTDATED_DEPENDENCY,
                    priority=Priority.LOW,
                    title=f"{len(transitive_outdated)} transitive dependencies are outdated",
                    description="Several transitive dependencies use old major versions. Updating parent packages may resolve these.",
                    impact={
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": len(transitive_outdated),
                        "total": len(transitive_outdated),
                    },
                    affected_components=[
                        f"{d['name']}@{d['version']}" for d in transitive_outdated[:10]
                    ],
                    action={
                        "type": "review_transitive",
                        "suggestion": "Update direct dependencies to pull in newer transitive versions",
                    },
                    effort="low",
                )
            )

        return recommendations

    def _analyze_version_fragmentation(
        self, dependencies: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """
        Detect when multiple versions of the same package exist in the dependency tree.
        This can lead to bundle bloat and unexpected behavior.
        """
        recommendations = []

        # Group dependencies by name (normalize to lowercase)
        deps_by_name = defaultdict(list)
        for dep in dependencies:
            name = dep.get("name", "").lower()
            if name:
                deps_by_name[name].append(
                    {
                        "version": dep.get("version", "unknown"),
                        "purl": dep.get("purl"),
                        "direct": dep.get("direct", False),
                        "parent": dep.get("parent_components", []),
                    }
                )

        # Find packages with multiple versions
        fragmented = []
        for name, versions in deps_by_name.items():
            unique_versions = set(v["version"] for v in versions)
            if len(unique_versions) > 1:
                fragmented.append(
                    {
                        "name": name,
                        "versions": list(unique_versions),
                        "count": len(unique_versions),
                        "has_direct": any(v["direct"] for v in versions),
                    }
                )

        # Sort by impact (more versions = worse)
        fragmented.sort(key=lambda x: x["count"], reverse=True)

        # Only report if there are significant fragmentation issues (3+ versions)
        significant_fragmented = [f for f in fragmented if f["count"] >= 3]

        if significant_fragmented:
            # High priority if many packages have 3+ versions
            priority = (
                Priority.MEDIUM if len(significant_fragmented) > 3 else Priority.LOW
            )

            # Limit to top 15 most fragmented
            top_fragmented = significant_fragmented[:15]

            recommendations.append(
                Recommendation(
                    type=RecommendationType.VERSION_FRAGMENTATION,
                    priority=priority,
                    title=f"Version fragmentation in {len(significant_fragmented)} packages ({sum(f['count'] for f in significant_fragmented)} total versions)",
                    description="These packages have 3 or more versions in your dependency tree. This can increase bundle size and cause subtle bugs. Consider deduplication or pinning to a single version.",
                    impact={
                        "critical": 0,
                        "high": len(
                            [f for f in significant_fragmented if f["count"] >= 5]
                        ),
                        "medium": len(
                            [f for f in significant_fragmented if 3 <= f["count"] < 5]
                        ),
                        "low": 0,
                        "total": len(significant_fragmented),
                    },
                    affected_components=[
                        f"{f['name']} ({f['count']} versions)" for f in top_fragmented
                    ],
                    action={
                        "type": "deduplicate_versions",
                        "packages": [
                            {
                                "name": f["name"],
                                "versions": f["versions"][
                                    :5
                                ],  # Limit displayed versions
                                "version_count": f["count"],
                                "suggestion": f"Pin to {max(f['versions'], key=lambda v: self._parse_version_tuple(v))}",
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

    def _analyze_dev_in_production(
        self, dependencies: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """
        Identify development dependencies that may be included in production builds.
        """
        recommendations = []

        # Common dev-only package patterns
        dev_patterns = [
            r"jest",
            r"mocha",
            r"chai",
            r"sinon",
            r"enzyme",
            r"testing-library",
            r"eslint",
            r"prettier",
            r"tslint",
            r"stylelint",
            r"webpack-dev",
            r"nodemon",
            r"ts-node",
            r"@types/",
            r"typescript$",
            r"storybook",
            r"chromatic",
            r"cypress",
            r"playwright",
            r"puppeteer",
            r"husky",
            r"lint-staged",
            r"commitlint",
            r"babel-jest",
            r"ts-jest",
        ]

        potential_dev_deps = []

        for dep in dependencies:
            name = (dep.get("name") or "").lower()
            scope = (dep.get("scope") or "").lower()

            # Skip if already marked as dev
            if scope in ("dev", "development", "test"):
                continue

            # Check if it matches dev patterns
            for pattern in dev_patterns:
                if re.search(pattern, name, re.IGNORECASE):
                    potential_dev_deps.append(
                        {
                            "name": dep.get("name"),
                            "version": dep.get("version"),
                            "reason": f"Matches dev pattern: {pattern}",
                        }
                    )
                    break

        if potential_dev_deps:
            recommendations.append(
                Recommendation(
                    type=RecommendationType.DEV_IN_PRODUCTION,
                    priority=Priority.LOW,
                    title=f"{len(potential_dev_deps)} potential dev dependencies in production",
                    description="Some packages typically used for development/testing were detected in your build. If these are in your production bundle, consider moving them to devDependencies.",
                    impact={
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": len(potential_dev_deps),
                        "total": len(potential_dev_deps),
                    },
                    affected_components=[
                        f"{d['name']}@{d['version']}" for d in potential_dev_deps[:15]
                    ],
                    action={
                        "type": "review_dev_deps",
                        "packages": [d["name"] for d in potential_dev_deps],
                        "suggestion": "Review if these packages should be moved to devDependencies",
                    },
                    effort="low",
                )
            )

        return recommendations

    # ========================================================================
    # TREND-BASED ANALYSIS
    # ========================================================================

    def _analyze_regressions(
        self,
        current_findings: List[Dict[str, Any]],
        previous_findings: List[Dict[str, Any]],
    ) -> List[Recommendation]:
        """
        Detect regressions - vulnerabilities that were fixed but have returned.
        """
        recommendations = []

        # Create sets of finding identifiers
        def finding_key(f):
            """Create a unique key for a finding."""
            if f.get("type") == "vulnerability":
                details = f.get("details", {})
                cve = details.get("cve_id") or details.get("id") or f.get("id")
                component = f.get("component", "")
                return f"vuln:{cve}:{component}"
            else:
                return f"{f.get('type')}:{f.get('component')}:{f.get('id')}"

        # Build sets for comparison
        previous_keys = {finding_key(f) for f in previous_findings}

        # Find new findings (not in previous scan)
        new_findings = []
        for f in current_findings:
            key = finding_key(f)
            if key not in previous_keys:
                new_findings.append(f)

        # Categorize new findings
        new_vulns = [f for f in new_findings if f.get("type") == "vulnerability"]
        new_critical = [f for f in new_vulns if f.get("severity") == "CRITICAL"]
        new_high = [f for f in new_vulns if f.get("severity") == "HIGH"]

        # Count overall change
        finding_delta = len(current_findings) - len(previous_findings)

        if new_critical or new_high:
            recommendations.append(
                Recommendation(
                    type=RecommendationType.REGRESSION_DETECTED,
                    priority=Priority.HIGH if new_critical else Priority.MEDIUM,
                    title=f"Regression: {len(new_critical)} critical, {len(new_high)} high severity vulnerabilities introduced",
                    description=f"This scan detected {len(new_findings)} new findings compared to the previous scan. This may indicate dependency updates that introduced new vulnerabilities or new code with security issues.",
                    impact={
                        "critical": len(new_critical),
                        "high": len(new_high),
                        "medium": len(
                            [f for f in new_vulns if f.get("severity") == "MEDIUM"]
                        ),
                        "low": len(
                            [f for f in new_vulns if f.get("severity") == "LOW"]
                        ),
                        "total": len(new_vulns),
                    },
                    affected_components=list(
                        set(
                            f.get("component", "unknown")
                            for f in (new_critical + new_high)[:15]
                        )
                    ),
                    action={
                        "type": "investigate_regression",
                        "new_critical_cves": [
                            f.get("details", {}).get("cve_id", f.get("id"))
                            for f in new_critical
                        ],
                        "suggestion": "Review recent dependency updates and code changes",
                    },
                    effort="medium",
                )
            )
        elif finding_delta > 10:
            recommendations.append(
                Recommendation(
                    type=RecommendationType.REGRESSION_DETECTED,
                    priority=Priority.LOW,
                    title=f"Finding count increased by {finding_delta}",
                    description="The total number of security findings has increased significantly since the last scan.",
                    impact={
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": finding_delta,
                        "total": finding_delta,
                    },
                    affected_components=[],
                    action={"type": "review_changes", "delta": finding_delta},
                    effort="low",
                )
            )

        return recommendations

    def _analyze_recurring_issues(
        self, current_findings: List[Dict[str, Any]], scan_history: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """
        Identify issues that keep appearing across multiple scans.
        These are candidates for waivers or architectural fixes.
        """
        recommendations = []

        if not scan_history:
            return recommendations

        # Count how often each CVE/finding appears across scans
        finding_frequency = defaultdict(
            lambda: {"count": 0, "scans": set(), "info": None}
        )

        for scan in scan_history:
            scan_id = scan.get("_id") or scan.get("id")
            findings_summary = scan.get("findings_summary", [])

            for f in findings_summary:
                if f.get("type") == "vulnerability":
                    details = f.get("details", {})
                    cve = details.get("cve_id") or f.get("id")
                    if cve:
                        finding_frequency[cve]["count"] += 1
                        finding_frequency[cve]["scans"].add(scan_id)
                        if not finding_frequency[cve]["info"]:
                            finding_frequency[cve]["info"] = {
                                "severity": f.get("severity"),
                                "component": f.get("component"),
                                "description": f.get("description", "")[:100],
                            }

        # Find truly recurring issues (appear in 3+ scans)
        recurring = [
            {"cve": cve, **data}
            for cve, data in finding_frequency.items()
            if data["count"] >= 3
        ]

        if recurring:
            # Sort by frequency and severity
            recurring.sort(
                key=lambda x: (
                    x["count"],
                    {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
                        x.get("info", {}).get("severity", ""), 0
                    ),
                ),
                reverse=True,
            )

            critical_recurring = [
                r for r in recurring if r.get("info", {}).get("severity") == "CRITICAL"
            ]

            recommendations.append(
                Recommendation(
                    type=RecommendationType.RECURRING_VULNERABILITY,
                    priority=Priority.MEDIUM if critical_recurring else Priority.LOW,
                    title=f"{len(recurring)} vulnerabilities keep recurring across scans",
                    description="These vulnerabilities have appeared in 3 or more scans without being fixed. Consider creating waivers with justification, or addressing the root cause architecturally.",
                    impact={
                        "critical": len(critical_recurring),
                        "high": len(
                            [
                                r
                                for r in recurring
                                if r.get("info", {}).get("severity") == "HIGH"
                            ]
                        ),
                        "medium": len(
                            [
                                r
                                for r in recurring
                                if r.get("info", {}).get("severity") == "MEDIUM"
                            ]
                        ),
                        "low": len(
                            [
                                r
                                for r in recurring
                                if r.get("info", {}).get("severity") == "LOW"
                            ]
                        ),
                        "total": len(recurring),
                    },
                    affected_components=[
                        f"{r['cve']} ({r.get('info', {}).get('component', 'unknown')}) - {r['count']} scans"
                        for r in recurring[:10]
                    ],
                    action={
                        "type": "address_recurring",
                        "cves": [r["cve"] for r in recurring[:10]],
                        "suggestions": [
                            "Create waivers with documented justification for accepted risks",
                            "Look for alternative packages without these vulnerabilities",
                            "Consider if the affected functionality can be removed",
                            "Check if upgrading to a different major version resolves the issues",
                        ],
                    },
                    effort="high",
                )
            )

        return recommendations

    # ========================================================================
    # DEPENDENCY GRAPH OPTIMIZATION
    # ========================================================================

    def _analyze_deep_dependency_chains(
        self, dependencies: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """
        Identify dependencies with very deep transitive chains.
        Deep chains increase supply chain risk and make updates harder.
        """
        recommendations = []

        # Build a simple depth map based on parent_components
        depth_map = {}  # purl/name -> estimated depth

        # First pass: direct deps have depth 1
        for dep in dependencies:
            key = dep.get("purl") or f"{dep.get('name')}@{dep.get('version')}"
            if dep.get("direct", False):
                depth_map[key] = 1

        # Iterative depth calculation
        for _ in range(10):  # Max iterations
            changed = False
            for dep in dependencies:
                key = dep.get("purl") or f"{dep.get('name')}@{dep.get('version')}"
                parents = dep.get("parent_components", [])

                if key in depth_map:
                    continue

                # Calculate depth from parents
                parent_depths = []
                for parent in parents:
                    if parent in depth_map:
                        parent_depths.append(depth_map[parent])

                if parent_depths:
                    depth_map[key] = max(parent_depths) + 1
                    changed = True

            if not changed:
                break

        # Find deeply nested deps
        deep_deps = []
        for dep in dependencies:
            key = dep.get("purl") or f"{dep.get('name')}@{dep.get('version')}"
            depth = depth_map.get(key, 0)

            if depth > self.max_dependency_depth:
                deep_deps.append(
                    {
                        "name": dep.get("name"),
                        "version": dep.get("version"),
                        "depth": depth,
                        "parents": dep.get("parent_components", [])[:3],
                    }
                )

        if deep_deps:
            # Sort by depth
            deep_deps.sort(key=lambda x: x["depth"], reverse=True)
            max_depth = deep_deps[0]["depth"] if deep_deps else 0

            recommendations.append(
                Recommendation(
                    type=RecommendationType.DEEP_DEPENDENCY_CHAIN,
                    priority=Priority.LOW,
                    title=f"Deep dependency chains detected (max depth: {max_depth})",
                    description=f"{len(deep_deps)} dependencies are nested more than {self.max_dependency_depth} levels deep. Deep chains increase supply chain attack surface and make dependency updates more complex.",
                    impact={
                        "critical": 0,
                        "high": 0,
                        "medium": len([d for d in deep_deps if d["depth"] > 7]),
                        "low": len([d for d in deep_deps if d["depth"] <= 7]),
                        "total": len(deep_deps),
                    },
                    affected_components=[
                        f"{d['name']}@{d['version']} (depth: {d['depth']})"
                        for d in deep_deps[:10]
                    ],
                    action={
                        "type": "reduce_chain_depth",
                        "suggestions": [
                            "Consider using packages with fewer transitive dependencies",
                            "Evaluate if some functionality can be implemented directly",
                            "Look for alternative packages with shallower dependency trees",
                        ],
                        "deepest_chains": [
                            {
                                "package": d["name"],
                                "depth": d["depth"],
                                "chain_preview": " → ".join(d["parents"][:3]),
                            }
                            for d in deep_deps[:5]
                        ],
                    },
                    effort="high",
                )
            )

        return recommendations

    def _analyze_duplicate_packages(
        self, dependencies: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """
        Detect packages that likely provide similar/duplicate functionality.
        """
        recommendations = []

        # Groups of packages that often duplicate functionality
        similar_packages = [
            {
                "category": "HTTP Clients",
                "packages": [
                    "axios",
                    "node-fetch",
                    "got",
                    "request",
                    "superagent",
                    "ky",
                ],
                "suggestion": "Consider standardizing on one HTTP client (axios or node-fetch recommended)",
            },
            {
                "category": "Date/Time Libraries",
                "packages": ["moment", "dayjs", "date-fns", "luxon"],
                "suggestion": "Consider using only one date library (dayjs or date-fns recommended)",
            },
            {
                "category": "Utility Libraries",
                "packages": ["lodash", "underscore", "ramda"],
                "suggestion": "Modern JavaScript often doesn't need these - consider native methods",
            },
            {
                "category": "State Management",
                "packages": ["redux", "mobx", "recoil", "zustand", "jotai", "valtio"],
                "suggestion": "Multiple state management libraries may indicate architecture issues",
            },
            {
                "category": "CSS-in-JS",
                "packages": [
                    "styled-components",
                    "emotion",
                    "@emotion/react",
                    "@emotion/styled",
                    "glamor",
                ],
                "suggestion": "Standardize on one CSS-in-JS solution",
            },
            {
                "category": "Form Libraries",
                "packages": ["formik", "react-hook-form", "final-form"],
                "suggestion": "Consider using only one form library (react-hook-form recommended)",
            },
            {
                "category": "Testing Assertion",
                "packages": ["chai", "expect", "should", "assert"],
                "suggestion": "Use Jest's built-in expect or standardize on one assertion library",
            },
        ]

        dep_names = {dep.get("name", "").lower() for dep in dependencies}

        duplicates_found = []
        for group in similar_packages:
            matches = [p for p in group["packages"] if p.lower() in dep_names]
            if len(matches) >= 2:
                duplicates_found.append(
                    {
                        "category": group["category"],
                        "found": matches,
                        "suggestion": group["suggestion"],
                    }
                )

        if duplicates_found:
            recommendations.append(
                Recommendation(
                    type=RecommendationType.DUPLICATE_FUNCTIONALITY,
                    priority=Priority.LOW,
                    title=f"Potential duplicate packages in {len(duplicates_found)} categories",
                    description="Multiple packages providing similar functionality were detected. Consolidating to one package per category can reduce bundle size and maintenance burden.",
                    impact={
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": len(duplicates_found),
                        "total": len(duplicates_found),
                    },
                    affected_components=[
                        f"{d['category']}: {', '.join(d['found'])}"
                        for d in duplicates_found
                    ],
                    action={
                        "type": "consolidate_packages",
                        "duplicates": duplicates_found,
                    },
                    effort="medium",
                )
            )

        return recommendations

    # ========================================================================
    # CROSS-PROJECT INSIGHTS (Respects user permissions)
    # ========================================================================

    def _correlate_scorecard_with_vulnerabilities(
        self,
        vulnerability_findings: List[Dict[str, Any]],
        quality_findings: List[Dict[str, Any]],
    ) -> List[Recommendation]:
        """
        Correlate vulnerability findings with OpenSSF Scorecard quality data.

        Identifies high-risk situations where vulnerabilities exist in packages
        that also have poor maintenance or quality scores.
        """
        recommendations = []

        if not vulnerability_findings or not quality_findings:
            return recommendations

        # Build scorecard lookup by component
        scorecard_by_component = {}
        for qf in quality_findings:
            component = qf.get("component", "")
            if not component:
                continue
            scorecard_by_component[component] = {
                "overall_score": qf.get("details", {}).get("overall_score", 10),
                "critical_issues": qf.get("details", {}).get("critical_issues", []),
                "project_url": qf.get("details", {}).get("project_url"),
                "failed_checks": qf.get("details", {}).get("failed_checks", []),
            }

        # Find vulnerabilities in poorly maintained packages
        high_risk_vulns = []

        for vf in vulnerability_findings:
            component = vf.get("component", "")
            severity = vf.get("severity", "").upper()

            # Check if this component has scorecard data
            scorecard = scorecard_by_component.get(component)
            if not scorecard:
                continue

            score = scorecard.get("overall_score", 10)
            critical_issues = scorecard.get("critical_issues", [])
            is_unmaintained = "Maintained" in critical_issues

            # High risk: Critical/High vuln in unmaintained or low-score package
            if severity in ["CRITICAL", "HIGH"] and (is_unmaintained or score < 5.0):
                high_risk_vulns.append(
                    {
                        "component": component,
                        "version": vf.get("version"),
                        "vuln_severity": severity,
                        "scorecard_score": score,
                        "unmaintained": is_unmaintained,
                        "cves": [
                            v.get("id")
                            for v in vf.get("details", {}).get("vulnerabilities", [])[
                                :3
                            ]
                        ],
                        "project_url": scorecard.get("project_url"),
                    }
                )

        if high_risk_vulns:
            # Sort by risk (unmaintained first, then by score)
            high_risk_vulns.sort(
                key=lambda x: (not x["unmaintained"], x["scorecard_score"])
            )

            unmaintained_count = sum(1 for v in high_risk_vulns if v["unmaintained"])
            low_score_count = len(high_risk_vulns) - unmaintained_count

            recommendations.append(
                Recommendation(
                    type=RecommendationType.CRITICAL_RISK,
                    priority=Priority.CRITICAL,
                    title="Critical Vulnerabilities in Poorly Maintained Packages",
                    description=(
                        f"Found {len(high_risk_vulns)} critical/high vulnerabilities in packages "
                        f"with concerning OpenSSF Scorecard ratings. "
                        f"{unmaintained_count} are in unmaintained packages, "
                        f"{low_score_count} are in packages with scores below 5.0/10. "
                        "These vulnerabilities may never receive fixes."
                    ),
                    impact={
                        "critical": sum(
                            1
                            for v in high_risk_vulns
                            if v["vuln_severity"] == "CRITICAL"
                        ),
                        "high": sum(
                            1 for v in high_risk_vulns if v["vuln_severity"] == "HIGH"
                        ),
                        "medium": 0,
                        "low": 0,
                        "total": len(high_risk_vulns),
                        "unmaintained_count": unmaintained_count,
                    },
                    affected_components=[
                        f"{v['component']}@{v['version']} (score: {v['scorecard_score']:.1f}/10{', UNMAINTAINED' if v['unmaintained'] else ''})"
                        for v in high_risk_vulns[:10]
                    ],
                    action={
                        "type": "replace_risky_packages",
                        "packages": [
                            {
                                "name": v["component"],
                                "version": v["version"],
                                "scorecard_score": v["scorecard_score"],
                                "unmaintained": v["unmaintained"],
                                "cves": v["cves"],
                                "project_url": v["project_url"],
                            }
                            for v in high_risk_vulns[:10]
                        ],
                        "steps": [
                            "1. PRIORITY: Find and migrate to actively maintained alternatives",
                            "2. If no alternative exists, evaluate forking the package",
                            "3. Implement additional security controls around these packages",
                            "4. Consider removing functionality that depends on these packages",
                            "5. Monitor for community forks that may have applied security fixes",
                        ],
                    },
                    effort="high",
                )
            )

        return recommendations

    def _analyze_cross_project_patterns(
        self,
        current_findings: List[Dict[str, Any]],
        dependencies: List[Dict[str, Any]],
        cross_project_data: Dict[str, Any],
    ) -> List[Recommendation]:
        """
        Analyze patterns across multiple projects owned by the same user/team.

        cross_project_data structure:
        {
            "projects": [
                {
                    "project_id": "...",
                    "project_name": "...",
                    "cves": ["CVE-2023-..."],
                    "packages": [{"name": "lodash", "version": "4.17.20"}],
                    "total_critical": 5,
                    "total_high": 10
                },
                ...
            ],
            "total_projects": 5
        }
        """
        recommendations = []

        if not cross_project_data or not cross_project_data.get("projects"):
            return recommendations

        projects = cross_project_data["projects"]
        total_projects = cross_project_data.get("total_projects", len(projects))

        # ----------------------------------------------------------------
        # 1. Find CVEs that appear across multiple projects
        # ----------------------------------------------------------------
        cve_project_map = defaultdict(list)  # CVE -> list of project names

        for proj in projects:
            for cve in proj.get("cves", []):
                cve_project_map[cve].append(
                    proj.get("project_name", proj.get("project_id"))
                )

        # CVEs affecting multiple projects
        widespread_cves = [
            {"cve": cve, "projects": proj_list, "count": len(proj_list)}
            for cve, proj_list in cve_project_map.items()
            if len(proj_list) >= 2
        ]

        if widespread_cves:
            widespread_cves.sort(key=lambda x: x["count"], reverse=True)

            recommendations.append(
                Recommendation(
                    type=RecommendationType.SHARED_VULNERABILITY,
                    priority=(
                        Priority.HIGH if len(widespread_cves) > 5 else Priority.MEDIUM
                    ),
                    title=f"{len(widespread_cves)} vulnerabilities affect multiple projects",
                    description=f"These CVEs appear in {len(widespread_cves)} or more of your projects. Fixing them once (e.g., in a shared package or template) could benefit all affected projects.",
                    impact={
                        "critical": 0,
                        "high": len(widespread_cves),
                        "medium": 0,
                        "low": 0,
                        "total": len(widespread_cves),
                    },
                    affected_components=[
                        f"{c['cve']} ({c['count']}/{total_projects} projects)"
                        for c in widespread_cves[:10]
                    ],
                    action={
                        "type": "fix_cross_project_vuln",
                        "cves": [
                            {
                                "cve": c["cve"],
                                "affected_projects": c["projects"][:5],
                                "total_affected": c["count"],
                            }
                            for c in widespread_cves[:5]
                        ],
                        "suggestion": "Consider creating a shared fix or updating your project templates",
                    },
                    effort="medium",
                )
            )

        # ----------------------------------------------------------------
        # 2. Find packages used across many projects (standardization candidates)
        # ----------------------------------------------------------------
        package_usage = defaultdict(lambda: {"versions": set(), "projects": []})

        for proj in projects:
            for pkg in proj.get("packages", []):
                name = pkg.get("name", "").lower()
                if name:
                    package_usage[name]["versions"].add(pkg.get("version", "unknown"))
                    package_usage[name]["projects"].append(proj.get("project_name"))

        # Packages with multiple versions across projects
        inconsistent_packages = [
            {
                "name": name,
                "versions": list(data["versions"]),
                "project_count": len(set(data["projects"])),
                "version_count": len(data["versions"]),
            }
            for name, data in package_usage.items()
            if len(data["versions"]) > 1 and len(set(data["projects"])) >= 2
        ]

        if inconsistent_packages:
            # Sort by spread (how many different versions)
            inconsistent_packages.sort(key=lambda x: x["version_count"], reverse=True)

            recommendations.append(
                Recommendation(
                    type=RecommendationType.CROSS_PROJECT_PATTERN,
                    priority=Priority.LOW,
                    title=f"Version inconsistency across {len(inconsistent_packages)} shared packages",
                    description="These packages are used across multiple projects but with different versions. Standardizing versions can simplify maintenance and reduce security gaps.",
                    impact={
                        "critical": 0,
                        "high": 0,
                        "medium": len(
                            [p for p in inconsistent_packages if p["version_count"] > 2]
                        ),
                        "low": len(
                            [
                                p
                                for p in inconsistent_packages
                                if p["version_count"] <= 2
                            ]
                        ),
                        "total": len(inconsistent_packages),
                    },
                    affected_components=[
                        f"{p['name']}: {len(p['versions'])} versions across {p['project_count']} projects"
                        for p in inconsistent_packages[:10]
                    ],
                    action={
                        "type": "standardize_versions",
                        "packages": [
                            {
                                "name": p["name"],
                                "versions": p["versions"][:5],
                                "suggestion": max(
                                    p["versions"],
                                    key=lambda v: self._parse_version_tuple(v),
                                ),
                                "project_count": p["project_count"],
                            }
                            for p in inconsistent_packages[:10]
                        ],
                        "suggestions": [
                            "Create a shared package.json or requirements.txt template",
                            "Use a monorepo with shared dependencies",
                            "Implement a dependency bot to keep versions aligned",
                        ],
                    },
                    effort="medium",
                )
            )

        # ----------------------------------------------------------------
        # 3. Identify organizational patterns (most problematic projects)
        # ----------------------------------------------------------------
        projects_by_severity = sorted(
            projects,
            key=lambda p: (p.get("total_critical", 0) * 10 + p.get("total_high", 0)),
            reverse=True,
        )

        if len(projects_by_severity) >= 3:
            top_problematic = projects_by_severity[:3]
            if any(p.get("total_critical", 0) > 5 for p in top_problematic):
                recommendations.append(
                    Recommendation(
                        type=RecommendationType.CROSS_PROJECT_PATTERN,
                        priority=Priority.MEDIUM,
                        title="Prioritize security fixes in most affected projects",
                        description="Some projects have significantly more security findings than others. Consider prioritizing remediation efforts on these projects.",
                        impact={
                            "critical": sum(
                                p.get("total_critical", 0) for p in top_problematic
                            ),
                            "high": sum(
                                p.get("total_high", 0) for p in top_problematic
                            ),
                            "medium": 0,
                            "low": 0,
                            "total": sum(
                                p.get("total_critical", 0) + p.get("total_high", 0)
                                for p in top_problematic
                            ),
                        },
                        affected_components=[
                            f"{p.get('project_name', 'Unknown')}: {p.get('total_critical', 0)} critical, {p.get('total_high', 0)} high"
                            for p in top_problematic
                        ],
                        action={
                            "type": "prioritize_projects",
                            "priority_projects": [
                                {
                                    "name": p.get("project_name"),
                                    "id": p.get("project_id"),
                                    "critical": p.get("total_critical", 0),
                                    "high": p.get("total_high", 0),
                                }
                                for p in top_problematic
                            ],
                        },
                        effort="medium",
                    )
                )

        return recommendations

    # ========================================================================
    # HOTSPOT DETECTION & CRITICAL RECOMMENDATIONS
    # ========================================================================

    def _detect_critical_hotspots(
        self,
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
                if details.get("epss_score") and details.get("epss_score") >= 0.1:
                    pkg_data["high_epss_count"] += 1
                if f.get("reachable") is True:
                    pkg_data["reachable_count"] += 1
                pkg_data["total_risk_score"] += details.get(
                    "risk_score", 0
                ) or self.severity_weights.get(severity, 0)
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
                        "steps": self._get_hotspot_remediation_steps(hotspot),
                    },
                    effort="low" if hotspot["fixed_versions"] else "high",
                )
            )

        return recommendations

    def _get_hotspot_remediation_steps(self, hotspot: Dict[str, Any]) -> List[str]:
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

    def _detect_known_exploits(
        self, vuln_findings: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """
        Detect vulnerabilities with known exploits (KEV, ransomware, high EPSS).
        These require immediate action.
        """
        recommendations = []

        # Group by exploit type
        kev_vulns = []
        ransomware_vulns = []
        high_epss_vulns = []

        for f in vuln_findings:
            details = f.get("details", {})
            if details.get("is_kev"):
                if details.get("kev_ransomware"):
                    ransomware_vulns.append(f)
                else:
                    kev_vulns.append(f)
            elif details.get("epss_score") and details.get("epss_score") >= 0.5:
                # Very high EPSS (>50%) - almost certainly will be exploited
                high_epss_vulns.append(f)

        # Ransomware recommendation (highest priority)
        if ransomware_vulns:
            affected_packages = list(
                set(f.get("component", "") for f in ransomware_vulns)
            )
            cves = list(
                set(
                    f.get("finding_id", "")
                    for f in ransomware_vulns
                    if f.get("finding_id", "").startswith("CVE-")
                )
            )

            recommendations.append(
                Recommendation(
                    type=RecommendationType.RANSOMWARE_RISK,
                    priority=Priority.CRITICAL,
                    title="URGENT: Ransomware Campaign Vulnerabilities",
                    description=(
                        f"Found {len(ransomware_vulns)} vulnerabilities known to be used in ransomware campaigns. "
                        f"These CVEs are actively targeted by ransomware groups and require immediate remediation. "
                        f"Affected: {', '.join(cves[:5])}"
                    ),
                    impact={
                        "critical": len(ransomware_vulns),
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "total": len(ransomware_vulns),
                        "kev_ransomware_count": len(ransomware_vulns),
                    },
                    affected_components=affected_packages[:20],
                    action={
                        "type": "fix_ransomware_vulns",
                        "cves": cves,
                        "packages": affected_packages,
                        "urgency": "immediate",
                        "steps": [
                            "This is a CRITICAL security issue - act within hours, not days",
                            "1. Identify all systems running affected packages",
                            "2. Apply patches or updates immediately",
                            "3. If patches unavailable, take affected systems offline",
                            "4. Implement network segmentation to limit blast radius",
                            "5. Enable enhanced logging and monitoring",
                            "6. Brief your security team and management",
                        ],
                    },
                    effort="low",
                )
            )

        # KEV recommendation
        if kev_vulns:
            affected_packages = list(set(f.get("component", "") for f in kev_vulns))
            cves = list(
                set(
                    f.get("finding_id", "")
                    for f in kev_vulns
                    if f.get("finding_id", "").startswith("CVE-")
                )
            )

            recommendations.append(
                Recommendation(
                    type=RecommendationType.KNOWN_EXPLOIT,
                    priority=Priority.CRITICAL,
                    title="CISA KEV: Actively Exploited Vulnerabilities",
                    description=(
                        f"Found {len(kev_vulns)} vulnerabilities in CISA's Known Exploited Vulnerabilities catalog. "
                        f"These are being actively exploited in real-world attacks. "
                        f"Federal agencies are required to patch these within specific timeframes."
                    ),
                    impact={
                        "critical": len(
                            [v for v in kev_vulns if v.get("severity") == "CRITICAL"]
                        ),
                        "high": len(
                            [v for v in kev_vulns if v.get("severity") == "HIGH"]
                        ),
                        "medium": len(
                            [v for v in kev_vulns if v.get("severity") == "MEDIUM"]
                        ),
                        "low": 0,
                        "total": len(kev_vulns),
                        "kev_count": len(kev_vulns),
                    },
                    affected_components=affected_packages[:20],
                    action={
                        "type": "fix_kev_vulns",
                        "cves": cves,
                        "packages": affected_packages,
                        "steps": [
                            "1. Prioritize patching these vulnerabilities above all others",
                            "2. Check CISA KEV catalog for remediation deadlines",
                            "3. Update affected packages to fixed versions",
                            "4. If no fix available, implement compensating controls",
                            "5. Document remediation efforts for compliance",
                        ],
                    },
                    effort="low",
                )
            )

        # High EPSS recommendation
        if high_epss_vulns:
            affected_packages = list(
                set(f.get("component", "") for f in high_epss_vulns)
            )
            cves = list(
                set(
                    f.get("finding_id", "")
                    for f in high_epss_vulns
                    if f.get("finding_id", "").startswith("CVE-")
                )
            )

            # Get max EPSS score
            max_epss = max(
                f.get("details", {}).get("epss_score", 0) for f in high_epss_vulns
            )

            recommendations.append(
                Recommendation(
                    type=RecommendationType.ACTIVELY_EXPLOITED,
                    priority=Priority.CRITICAL,
                    title="Very High Exploitation Probability",
                    description=(
                        f"Found {len(high_epss_vulns)} vulnerabilities with EPSS score > 50%. "
                        f"These have a very high probability of being exploited in the next 30 days. "
                        f"Highest EPSS: {max_epss*100:.1f}%"
                    ),
                    impact={
                        "critical": len(
                            [
                                v
                                for v in high_epss_vulns
                                if v.get("severity") == "CRITICAL"
                            ]
                        ),
                        "high": len(
                            [v for v in high_epss_vulns if v.get("severity") == "HIGH"]
                        ),
                        "medium": len(
                            [
                                v
                                for v in high_epss_vulns
                                if v.get("severity") == "MEDIUM"
                            ]
                        ),
                        "low": 0,
                        "total": len(high_epss_vulns),
                        "high_epss_count": len(high_epss_vulns),
                        "max_epss": max_epss,
                    },
                    affected_components=affected_packages[:20],
                    action={
                        "type": "fix_high_epss_vulns",
                        "cves": cves,
                        "packages": affected_packages,
                        "max_epss_percent": f"{max_epss*100:.1f}%",
                        "steps": [
                            "1. These vulnerabilities are likely to be exploited soon",
                            "2. Prioritize remediation before exploit code becomes public",
                            "3. Update affected packages to fixed versions",
                            "4. Monitor threat intelligence for exploit activity",
                        ],
                    },
                    effort="low",
                )
            )

        return recommendations

    def _process_malware(
        self, malware_findings: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """Process malware detection findings."""
        if not malware_findings:
            return []

        affected_packages = list(set(f.get("component", "") for f in malware_findings))

        return [
            Recommendation(
                type=RecommendationType.MALWARE_DETECTED,
                priority=Priority.CRITICAL,
                title="CRITICAL: Malware Detected in Dependencies",
                description=(
                    f"Found {len(malware_findings)} packages containing known malware. "
                    f"These packages may steal credentials, install backdoors, or cause other harm. "
                    f"Remove immediately!"
                ),
                impact={
                    "critical": len(malware_findings),
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "total": len(malware_findings),
                },
                affected_components=affected_packages,
                action={
                    "type": "remove_malware",
                    "packages": affected_packages,
                    "urgency": "immediate",
                    "steps": [
                        "STOP - This is a critical security incident",
                        "1. Immediately remove the malicious package(s)",
                        "2. Check if npm install/pip install scripts ran malicious code",
                        "3. Rotate any credentials that may have been exposed",
                        "4. Audit your systems for signs of compromise",
                        "5. Report to your security team",
                        "6. Consider incident response procedures",
                    ],
                },
                effort="low",
            )
        ]

    def _process_typosquatting(
        self, typosquat_findings: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """Process potential typosquatting package findings."""
        if not typosquat_findings:
            return []

        affected_packages = []
        for f in typosquat_findings:
            pkg = f.get("component", "")
            similar_to = f.get("details", {}).get("similar_to", "")
            if pkg and similar_to:
                affected_packages.append(f"{pkg} (looks like: {similar_to})")
            elif pkg:
                affected_packages.append(pkg)

        return [
            Recommendation(
                type=RecommendationType.TYPOSQUAT_DETECTED,
                priority=Priority.HIGH,
                title="Potential Typosquatting Packages Detected",
                description=(
                    f"Found {len(typosquat_findings)} packages that may be typosquatting attempts. "
                    f"Typosquatting packages mimic popular packages to trick developers into installing malware. "
                    f"Verify these are the intended packages."
                ),
                impact={
                    "critical": 0,
                    "high": len(typosquat_findings),
                    "medium": 0,
                    "low": 0,
                    "total": len(typosquat_findings),
                },
                affected_components=affected_packages,
                action={
                    "type": "verify_packages",
                    "packages": affected_packages,
                    "steps": [
                        "1. Verify each flagged package is the intended package",
                        "2. Check the package source repository",
                        "3. Compare with the legitimate package name",
                        "4. If typosquat, replace with the correct package",
                        "5. Audit for any malicious activity",
                    ],
                },
                effort="low",
            )
        ]

    def _process_end_of_life(
        self, eol_findings: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """Process end-of-life dependency findings."""
        if not eol_findings:
            return []

        affected_packages = []
        for f in eol_findings:
            pkg = f.get("component", "")
            version = f.get("version", "")
            eol_date = f.get("details", {}).get("eol_date", "")
            if eol_date:
                affected_packages.append(f"{pkg}@{version} (EOL: {eol_date})")
            else:
                affected_packages.append(f"{pkg}@{version}")

        # Check severity based on how long ago EOL was
        critical_count = len(
            [f for f in eol_findings if f.get("severity") == "CRITICAL"]
        )
        high_count = len([f for f in eol_findings if f.get("severity") == "HIGH"])

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
                    "medium": len(
                        [f for f in eol_findings if f.get("severity") == "MEDIUM"]
                    ),
                    "low": len([f for f in eol_findings if f.get("severity") == "LOW"]),
                    "total": len(eol_findings),
                },
                affected_components=affected_packages[:20],
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

    def _identify_quick_wins(
        self,
        vuln_findings: List[Dict[str, Any]],
        dependencies: List[Dict[str, Any]],
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
            component = f.get("component", "")
            if component and f.get("details", {}).get("fixed_version"):
                vulns_by_package[component].append(f)

        # Create a set of direct dependencies
        direct_deps = set()
        for dep in dependencies:
            if dep.get("direct", False):
                direct_deps.add(dep.get("name", ""))

        # Find packages where one update fixes multiple issues
        quick_wins = []
        for pkg, vulns in vulns_by_package.items():
            if len(vulns) < 2:
                continue

            # Get all fixed versions
            fixed_versions = list(
                set(
                    v.get("details", {}).get("fixed_version")
                    for v in vulns
                    if v.get("details", {}).get("fixed_version")
                )
            )

            if not fixed_versions:
                continue

            # Calculate impact
            critical_count = len([v for v in vulns if v.get("severity") == "CRITICAL"])
            high_count = len([v for v in vulns if v.get("severity") == "HIGH"])
            kev_count = len([v for v in vulns if v.get("details", {}).get("is_kev")])

            is_direct = pkg in direct_deps

            # Score the quick win
            score = (
                len(vulns) * 10  # More vulns fixed = better
                + critical_count * 50
                + high_count * 20
                + kev_count * 100
                + (50 if is_direct else 0)  # Direct deps are easier to update
            )

            quick_wins.append(
                {
                    "package": pkg,
                    "version": vulns[0].get("version", "unknown"),
                    "fixed_version": self._calculate_best_fix_version(fixed_versions),
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

            dep_type = (
                "direct dependency" if qw["is_direct"] else "transitive dependency"
            )

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

    def _detect_toxic_dependencies(
        self,
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
                critical = len(
                    [v for v in pkg["vulns"] if v.get("severity") == "CRITICAL"]
                )
                high = len([v for v in pkg["vulns"] if v.get("severity") == "HIGH"])
                kev = len(
                    [v for v in pkg["vulns"] if v.get("details", {}).get("is_kev")]
                )

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
                pkg["total_score"] += (
                    critical * 50 + high * 20 + vuln_count * 5 + kev * 100
                )

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

    def _analyze_attack_surface(
        self,
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
                        "parent": dep.get(
                            "introduced_by", dep.get("parent", "unknown")
                        ),
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


# Singleton instance
recommendation_engine = RecommendationEngine()
