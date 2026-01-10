"""
Recommendation Engine for Security Findings

Analyzes vulnerabilities, secrets, SAST, IAC, and other findings
to generate actionable remediation recommendations.
"""

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

from app.schemas.recommendation import Recommendation, Priority, RecommendationType

from app.services.recommendation import (
    vulnerabilities,
    secrets,
    sast,
    iac,
    licenses,
    quality,
    dependencies as dep_analysis,
    trends,
    graph,
    insights,
    risks,
    incidents,
    optimization,
    common,
)

logger = logging.getLogger(__name__)


class RecommendationEngine:
    """
    Generates remediation recommendations based on all finding types.
    Delegates analysis to specialized modules in app.services.recommendation.
    """

    def __init__(self):
        # Configuration kept for compatibility or future use
        self.outdated_threshold_days = 365 * 2  # 2 years
        self.max_dependency_depth = 5

    async def generate_recommendations(
        self,
        findings: List[Dict[str, Any]],
        dependencies: List[Dict[str, Any]],
        source_target: Optional[str] = None,
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
            previous_scan_findings: Findings from previous scan for regression analysis
            scan_history: History of scans for recurring issue analysis
            cross_project_data: Data from other projects for cross-project analysis

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
        recommendations.extend(
            vulnerabilities.process_vulnerabilities(
                findings_by_type.get("vulnerability", []),
                dep_by_purl,
                dep_by_name_version,
                dependencies,
                source_target,
            )
        )

        # 2. Process SECRETS
        recommendations.extend(
            secrets.process_secrets(findings_by_type.get("secret", []))
        )

        # 3. Process SAST (code security)
        recommendations.extend(
            sast.process_sast(findings_by_type.get("sast", []))
        )

        # 4. Process IAC (infrastructure as code)
        recommendations.extend(
            iac.process_iac(findings_by_type.get("iac", []))
        )

        # 5. Process LICENSE issues
        recommendations.extend(
            licenses.process_licenses(findings_by_type.get("license", []))
        )

        # 6. Process QUALITY issues (maintainer risk, etc.)
        recommendations.extend(
            quality.process_quality(findings_by_type.get("quality", []))
        )

        # 7. Dependency Hygiene (Outdated, Fragmentation, Dev-in-Prod)
        # Assuming analyze_outdated_dependencies returns list
        recommendations.extend(
            dep_analysis.analyze_outdated_dependencies(dependencies)
        )
        recommendations.extend(
            dep_analysis.analyze_version_fragmentation(dependencies)
        )
        recommendations.extend(
            dep_analysis.analyze_dev_in_production(dependencies)
        )

        # 8. Trends & Regressions
        if previous_scan_findings is not None:
            recommendations.extend(
                trends.analyze_regressions(findings, previous_scan_findings)
            )
        
        if scan_history:
            recommendations.extend(
                trends.analyze_recurring_issues(scan_history)
            )

        # 9. Graph Analysis (Deep chains, Duplicates)
        recommendations.extend(
            graph.analyze_deep_dependency_chains(
                dependencies, max_dependency_depth=self.max_dependency_depth
            )
        )
        recommendations.extend(
            graph.analyze_duplicate_packages(dependencies)
        )

        # 10. Cross Project Insights & Scorecard Correlation
        if cross_project_data:
            recommendations.extend(
                insights.analyze_cross_project_patterns(
                    findings, dependencies, cross_project_data
                )
            )
        
        recommendations.extend(
            insights.correlate_scorecard_with_vulnerabilities(
                findings_by_type.get("vulnerability", []),
                findings_by_type.get("quality", [])
            )
        )

        # 11. Risks & Hotspots
        recommendations.extend(
            risks.detect_critical_hotspots(
                findings, dependencies, dep_by_purl, dep_by_name_version
            )
        )
        
        recommendations.extend(
            risks.detect_toxic_dependencies(
                findings, dependencies, dep_by_purl, dep_by_name_version
            )
        )

        recommendations.extend(
            risks.analyze_attack_surface(dependencies, findings)
        )

        # 12. Incidents (Malware, Exploits, Typosquatting)
        recommendations.extend(
            incidents.process_malware(findings_by_type.get("malware", []))
        )

        recommendations.extend(
            incidents.detect_known_exploits(findings_by_type.get("vulnerability", []))
        )
        
        # Typosquatting
        typosquat_findings = [
            f
            for f in findings_by_type.get("quality", [])
            if "typosquat" in f.get("details", {}).get("risk_type", "").lower()
        ]
        if typosquat_findings:
            recommendations.extend(
                incidents.process_typosquatting(typosquat_findings)
            )
        if findings_by_type.get("typosquatting"):
             recommendations.extend(
                incidents.process_typosquatting(findings_by_type["typosquatting"])
            )

        # 13. End-of-Life Dependencies
        recommendations.extend(
            dep_analysis.analyze_end_of_life(findings_by_type.get("eol", []))
        )

        # 14. Optimization (Quick Wins)
        recommendations.extend(
            optimization.identify_quick_wins(
                findings_by_type.get("vulnerability", []), dependencies
            )
        )

        # Sort by priority and impact using common scoring logic
        recommendations.sort(
            key=lambda r: common.calculate_score(r), reverse=True
        )

        return recommendations


# Singleton instance
recommendation_engine = RecommendationEngine()
