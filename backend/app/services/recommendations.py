"""
Recommendation Engine for Security Findings

Analyzes vulnerabilities, secrets, SAST, IAC, and other findings
to generate actionable remediation recommendations.
"""

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class RecommendationType(str, Enum):
    """Types of remediation recommendations."""

    # Vulnerability-related
    BASE_IMAGE_UPDATE = "base_image_update"
    DIRECT_DEPENDENCY_UPDATE = "direct_dependency_update"
    TRANSITIVE_FIX_VIA_PARENT = "transitive_fix_via_parent"
    NO_FIX_AVAILABLE = "no_fix_available"
    CONSIDER_WAIVER = "consider_waiver"
    # Secret-related
    ROTATE_SECRETS = "rotate_secrets"
    REMOVE_SECRETS = "remove_secrets"
    # SAST-related
    FIX_CODE_SECURITY = "fix_code_security"
    # IAC-related
    FIX_INFRASTRUCTURE = "fix_infrastructure"
    # License-related
    LICENSE_COMPLIANCE = "license_compliance"
    # Quality-related
    SUPPLY_CHAIN_RISK = "supply_chain_risk"
    CRITICAL_RISK = "critical_risk"  # Combined vuln + scorecard risk
    # Dependency Health & Hygiene
    OUTDATED_DEPENDENCY = "outdated_dependency"
    VERSION_FRAGMENTATION = "version_fragmentation"
    DEV_IN_PRODUCTION = "dev_in_production"
    UNMAINTAINED_PACKAGE = "unmaintained_package"
    # Trend-based
    RECURRING_VULNERABILITY = "recurring_vulnerability"
    REGRESSION_DETECTED = "regression_detected"
    # Dependency Graph
    DEEP_DEPENDENCY_CHAIN = "deep_dependency_chain"
    DUPLICATE_FUNCTIONALITY = "duplicate_functionality"
    # Cross-Project
    CROSS_PROJECT_PATTERN = "cross_project_pattern"
    SHARED_VULNERABILITY = "shared_vulnerability"


class Priority(str, Enum):
    """Recommendation priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class FindingInfo:
    """Generic information about any finding."""

    finding_id: str
    finding_type: str  # vulnerability, secret, sast, iac, license, quality
    severity: str
    component: str  # package name or file path
    version: Optional[str] = None
    description: Optional[str] = None
    fixed_version: Optional[str] = None
    cve_id: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    rule_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityInfo:
    """Specific information about a vulnerability finding."""

    finding_id: str
    cve_id: str
    severity: str
    package_name: str
    current_version: str
    fixed_version: Optional[str]
    description: Optional[str] = None
    source_type: str = "unknown"  # image or application

    @property
    def is_fixable(self) -> bool:
        return self.fixed_version is not None


@dataclass
class Recommendation:
    """A remediation recommendation."""

    type: RecommendationType
    priority: Priority
    title: str
    description: str
    impact: Dict[str, int]  # {critical: X, high: Y, ...}
    affected_components: List[str]
    action: Dict[str, Any]  # Specific action details
    effort: str = "medium"  # low, medium, high

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "priority": self.priority.value,
            "title": self.title,
            "description": self.description,
            "impact": self.impact,
            "affected_components": self.affected_components,
            "action": self.action,
            "effort": self.effort,
        }


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

        # ============================================================
        # NEW: Dependency Health & Hygiene Analysis
        # ============================================================

        # 7. Check for outdated dependencies
        outdated_recs = self._analyze_outdated_dependencies(dependencies)
        recommendations.extend(outdated_recs)

        # 8. Check for version fragmentation (multiple versions of same package)
        fragmentation_recs = self._analyze_version_fragmentation(dependencies)
        recommendations.extend(fragmentation_recs)

        # 9. Check for dev dependencies in production scope
        dev_prod_recs = self._analyze_dev_in_production(dependencies)
        recommendations.extend(dev_prod_recs)

        # ============================================================
        # NEW: Trend-based Analysis (requires historical data)
        # ============================================================

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

        # ============================================================
        # NEW: Dependency Graph Optimization
        # ============================================================

        # 12. Analyze deep dependency chains
        deep_chain_recs = self._analyze_deep_dependency_chains(dependencies)
        recommendations.extend(deep_chain_recs)

        # 13. Detect duplicate functionality (similar packages)
        duplicate_recs = self._analyze_duplicate_packages(dependencies)
        recommendations.extend(duplicate_recs)

        # ============================================================
        # NEW: Cross-Project Insights (respects user permissions)
        # ============================================================

        if cross_project_data:
            # 14. Find patterns across user's projects
            cross_project_recs = self._analyze_cross_project_patterns(
                findings, dependencies, cross_project_data
            )
            recommendations.extend(cross_project_recs)

        # ============================================================
        # NEW: Scorecard-Vulnerability Correlation
        # ============================================================

        # 15. Identify high-risk vulnerabilities in poorly maintained packages
        scorecard_vuln_recs = self._correlate_scorecard_with_vulnerabilities(
            vuln_findings, quality_findings
        )
        recommendations.extend(scorecard_vuln_recs)

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

            vuln_info = VulnerabilityInfo(
                finding_id=f.get("id", ""),
                cve_id=cve_id,
                severity=f.get("severity", "UNKNOWN"),
                package_name=component,
                current_version=version,
                fixed_version=fixed_version,
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
            affected_packages.add(v.component)

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

        # Extract image name and tag
        image_tag = "latest"
        if source_target and ":" in source_target:
            parts = source_target.rsplit(":", 1)
            image_name = parts[0]
            image_tag = parts[1]

        return Recommendation(
            type=RecommendationType.BASE_IMAGE_UPDATE,
            priority=priority,
            title=f"Update Base Image",
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
                    f"# Check for available tags:",
                    f"docker pull {image_name}:latest",
                    f"# Or use a specific newer version:",
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
        """Analyze direct dependency updates."""

        recommendations = []

        # Group vulns by component
        vulns_by_component = defaultdict(list)
        for v in vulns:
            vulns_by_component[v.component].append(v)

        for component, component_vulns in vulns_by_component.items():
            # Find the best fix version (one that fixes all vulns)
            fixed_versions = [
                v.fixed_version for v in component_vulns if v.fixed_version
            ]

            if not fixed_versions:
                continue

            # Get current version
            current_version = (
                component_vulns[0].version if component_vulns else "unknown"
            )

            # Calculate best fixed version
            best_fix = self._calculate_best_fix_version(fixed_versions)

            # Count severities
            severity_counts = defaultdict(int)
            cves = []
            for v in component_vulns:
                severity_counts[v.severity] += 1
                if v.cve_id:
                    cves.append(v.cve_id)

            # Determine priority
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
                    type=RecommendationType.DIRECT_DEPENDENCY_UPDATE,
                    priority=priority,
                    title=f"Update {component}",
                    description=(
                        f"Update {component} from {current_version} to {best_fix} "
                        f"to fix {len(component_vulns)} vulnerabilities."
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
                        "type": "update_dependency",
                        "package": component,
                        "current_version": current_version,
                        "target_version": best_fix,
                        "cves": cves[:10],  # Limit CVEs shown
                    },
                    effort="low",
                )
            )

        return recommendations

    def _analyze_transitive_dependencies(
        self, vulns: List[VulnerabilityInfo], dependencies: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """Analyze transitive dependency vulnerabilities."""

        recommendations = []

        # Group by component
        vulns_by_component = defaultdict(list)
        for v in vulns:
            vulns_by_component[v.component].append(v)

        for component, component_vulns in vulns_by_component.items():
            fixed_versions = [
                v.fixed_version for v in component_vulns if v.fixed_version
            ]

            if not fixed_versions:
                continue

            current_version = (
                component_vulns[0].version if component_vulns else "unknown"
            )
            best_fix = self._calculate_best_fix_version(fixed_versions)

            severity_counts = defaultdict(int)
            for v in component_vulns:
                severity_counts[v.severity] += 1

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
                    type=RecommendationType.TRANSITIVE_FIX_VIA_PARENT,
                    priority=priority,
                    title=f"Update transitive dependency {component}",
                    description=(
                        f"Transitive dependency {component}@{current_version} has "
                        f"{len(component_vulns)} vulnerabilities. "
                        f"Update a parent dependency that includes a fixed version ({best_fix}), "
                        f"or override the transitive version directly."
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

    def _analyze_no_fix_vulns(
        self, vulns: List[VulnerabilityInfo]
    ) -> List[Recommendation]:
        """Analyze vulnerabilities with no known fix."""

        if not vulns:
            return []

        # Group by component
        vulns_by_component = defaultdict(list)
        for v in vulns:
            vulns_by_component[v.component].append(v)

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
                component_vulns[0].version if component_vulns else "unknown"
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
        """Calculate a score for sorting recommendations."""
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

        # Prefer lower effort
        effort_bonus = {"low": 50, "medium": 20, "high": 0}.get(rec.effort, 0)

        # Prefer base image updates (more bang for buck)
        type_bonus = {
            RecommendationType.BASE_IMAGE_UPDATE: 100,
            RecommendationType.DIRECT_DEPENDENCY_UPDATE: 50,
            RecommendationType.TRANSITIVE_FIX_VIA_PARENT: 20,
        }.get(rec.type, 0)

        return base_score + impact_score + effort_bonus + type_bonus

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
        # Format: package_pattern -> (min_recommended_major, message)
        known_outdated = {
            "react": (
                18,
                "React 18+ offers concurrent features and better performance",
            ),
            "vue": (3, "Vue 3 offers Composition API and improved TypeScript support"),
            "angular": (15, "Consider upgrading to Angular 15+ for better performance"),
            "django": (4, "Django 4+ offers async support and improved security"),
            "flask": (2, "Flask 2+ has async support and improved CLI"),
            "express": (4, "Express 4+ is the stable maintained version"),
            "lodash": (4, "Lodash 4+ is the current stable release"),
            "jquery": (3, "Consider migrating away from jQuery to modern frameworks"),
            "moment": (
                2,
                "Consider migrating to date-fns or dayjs - moment is in maintenance mode",
            ),
            "request": (
                2,
                "The 'request' package is deprecated - use axios or node-fetch",
            ),
            "python": (3, "Python 2.x is end-of-life"),
            "node": (18, "Node.js 16 and below are end-of-life"),
        }

        outdated_deps = []

        for dep in dependencies:
            name = dep.get("name", "").lower()
            version = dep.get("version", "")

            # Check against known patterns
            for pattern, (min_major, message) in known_outdated.items():
                if pattern in name:
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

        if fragmented:
            # High priority if many packages are fragmented
            priority = Priority.MEDIUM if len(fragmented) > 5 else Priority.LOW

            recommendations.append(
                Recommendation(
                    type=RecommendationType.VERSION_FRAGMENTATION,
                    priority=priority,
                    title=f"Version fragmentation detected in {len(fragmented)} packages",
                    description="Multiple versions of the same package exist in your dependency tree. This increases bundle size and can cause subtle bugs due to version mismatches.",
                    impact={
                        "critical": 0,
                        "high": 0,
                        "medium": len([f for f in fragmented if f["count"] > 2]),
                        "low": len([f for f in fragmented if f["count"] <= 2]),
                        "total": len(fragmented),
                    },
                    affected_components=[
                        f"{f['name']} ({', '.join(f['versions'][:3])}{'...' if len(f['versions']) > 3 else ''})"
                        for f in fragmented[:10]
                    ],
                    action={
                        "type": "deduplicate_versions",
                        "packages": [
                            {
                                "name": f["name"],
                                "versions": f["versions"],
                                "suggestion": f"Pin to version {max(f['versions'], key=lambda v: self._parse_version_tuple(v))}",
                            }
                            for f in fragmented[:10]
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
            name = dep.get("name", "").lower()
            scope = dep.get("scope", "").lower()

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

        current_keys = {finding_key(f) for f in current_findings}
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
                    description=f"These packages are used across multiple projects but with different versions. Standardizing versions can simplify maintenance and reduce security gaps.",
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
                                "versions_found": p["versions"][:5],
                                "recommended": max(
                                    p["versions"],
                                    key=lambda v: self._parse_version_tuple(v),
                                ),
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


# Singleton instance
recommendation_engine = RecommendationEngine()
