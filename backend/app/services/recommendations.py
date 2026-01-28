"""
Recommendation Engine for Security Findings

Analyzes vulnerabilities, secrets, SAST, IAC, and other findings
to generate actionable remediation recommendations.
"""

import logging
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.core.constants import MAX_DEPENDENCY_DEPTH, OUTDATED_DEPENDENCY_THRESHOLD_DAYS
from app.schemas.recommendation import Recommendation

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


def _safe_extend(
    recommendations: List[Recommendation],
    generator: Callable[[], List[Recommendation]],
    module_name: str,
) -> None:
    """
    Safely extend recommendations list with error handling.

    Catches exceptions from individual recommendation generators
    to prevent one failing module from stopping the entire process.
    """
    try:
        result = generator()
        if result:
            recommendations.extend(result)
            logger.debug(f"{module_name}: generated {len(result)} recommendations")
    except Exception as e:
        logger.error(f"Error in {module_name}: {e}", exc_info=True)


def _deduplicate_recommendations(
    recommendations: List[Recommendation],
) -> List[Recommendation]:
    """
    Remove duplicate recommendations based on type and affected components.

    Keeps the recommendation with the highest score when duplicates are found.
    """
    seen: Dict[Tuple[str, str, str], Recommendation] = {}

    for rec in recommendations:
        # Find first valid (non-empty, non-None) component for the key
        primary_component = ""
        for comp in rec.affected_components:
            if comp and isinstance(comp, str) and comp.strip():
                primary_component = comp.strip()
                break

        # Include title in key to avoid incorrectly merging different recommendations
        # with empty/same components but different contexts
        key = (
            rec.type.value,
            primary_component,
            rec.title if not primary_component else "",
        )

        if key not in seen:
            seen[key] = rec
        else:
            # Keep the one with higher score
            existing_score = common.calculate_score(seen[key])
            new_score = common.calculate_score(rec)
            if new_score > existing_score:
                seen[key] = rec

    return list(seen.values())


class RecommendationEngine:
    """
    Generates remediation recommendations based on all finding types.
    Delegates analysis to specialized modules in app.services.recommendation.
    """

    def __init__(self):
        # Configuration from constants (instance vars for compatibility)
        self.outdated_threshold_days = OUTDATED_DEPENDENCY_THRESHOLD_DAYS
        self.max_dependency_depth = MAX_DEPENDENCY_DEPTH

    async def generate_recommendations(
        self,
        findings: Optional[List[Dict[str, Any]]] = None,
        dependencies: Optional[List[Dict[str, Any]]] = None,
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
        # Input validation - use empty lists if None
        findings = findings or []
        dependencies = dependencies or []

        logger.debug(
            f"Generating recommendations for {len(findings)} findings, "
            f"{len(dependencies)} dependencies"
        )

        recommendations: List[Recommendation] = []

        # Separate findings by type
        findings_by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in findings:
            finding_type = f.get("type", "other")
            findings_by_type[finding_type].append(f)

        # Build lookup maps for dependencies
        dep_by_purl = {d.get("purl"): d for d in dependencies if d.get("purl")}
        dep_by_name_version = {
            f"{d.get('name')}@{d.get('version')}": d for d in dependencies
        }

        # 1. Process VULNERABILITIES
        _safe_extend(
            recommendations,
            lambda: vulnerabilities.process_vulnerabilities(
                findings_by_type.get("vulnerability", []),
                dep_by_purl,
                dep_by_name_version,
                dependencies,
                source_target,
            ),
            "vulnerabilities",
        )

        # 2. Process SECRETS
        _safe_extend(
            recommendations,
            lambda: secrets.process_secrets(findings_by_type.get("secret", [])),
            "secrets",
        )

        # 3. Process SAST (code security)
        _safe_extend(
            recommendations,
            lambda: sast.process_sast(findings_by_type.get("sast", [])),
            "sast",
        )

        # 4. Process IAC (infrastructure as code)
        _safe_extend(
            recommendations,
            lambda: iac.process_iac(findings_by_type.get("iac", [])),
            "iac",
        )

        # 5. Process LICENSE issues
        _safe_extend(
            recommendations,
            lambda: licenses.process_licenses(findings_by_type.get("license", [])),
            "licenses",
        )

        # 6. Process QUALITY issues (maintainer risk, etc.)
        _safe_extend(
            recommendations,
            lambda: quality.process_quality(findings_by_type.get("quality", [])),
            "quality",
        )

        # 7. Dependency Hygiene (Outdated, Fragmentation, Dev-in-Prod)
        _safe_extend(
            recommendations,
            lambda: dep_analysis.analyze_outdated_dependencies(dependencies),
            "outdated_dependencies",
        )
        _safe_extend(
            recommendations,
            lambda: dep_analysis.analyze_version_fragmentation(dependencies),
            "version_fragmentation",
        )
        _safe_extend(
            recommendations,
            lambda: dep_analysis.analyze_dev_in_production(dependencies),
            "dev_in_production",
        )

        # 8. Trends & Regressions
        if previous_scan_findings is not None:
            _safe_extend(
                recommendations,
                lambda: trends.analyze_regressions(findings, previous_scan_findings),
                "regressions",
            )

        if scan_history:
            _safe_extend(
                recommendations,
                lambda: trends.analyze_recurring_issues(scan_history),
                "recurring_issues",
            )

        # 9. Graph Analysis (Deep chains, Duplicates)
        _safe_extend(
            recommendations,
            lambda: graph.analyze_deep_dependency_chains(
                dependencies, max_dependency_depth=self.max_dependency_depth
            ),
            "deep_dependency_chains",
        )
        _safe_extend(
            recommendations,
            lambda: graph.analyze_duplicate_packages(dependencies),
            "duplicate_packages",
        )

        # 10. Cross Project Insights & Scorecard Correlation
        if cross_project_data:
            _safe_extend(
                recommendations,
                lambda: insights.analyze_cross_project_patterns(
                    findings, dependencies, cross_project_data
                ),
                "cross_project_patterns",
            )

        _safe_extend(
            recommendations,
            lambda: insights.correlate_scorecard_with_vulnerabilities(
                findings_by_type.get("vulnerability", []),
                findings_by_type.get("quality", []),
            ),
            "scorecard_correlation",
        )

        # 11. Risks & Hotspots
        _safe_extend(
            recommendations,
            lambda: risks.detect_critical_hotspots(
                findings, dependencies, dep_by_purl, dep_by_name_version
            ),
            "critical_hotspots",
        )

        _safe_extend(
            recommendations,
            lambda: risks.detect_toxic_dependencies(
                findings, dependencies, dep_by_purl, dep_by_name_version
            ),
            "toxic_dependencies",
        )

        _safe_extend(
            recommendations,
            lambda: risks.analyze_attack_surface(dependencies, findings),
            "attack_surface",
        )

        # 12. Incidents (Malware, Exploits, Typosquatting)
        _safe_extend(
            recommendations,
            lambda: incidents.process_malware(findings_by_type.get("malware", [])),
            "malware",
        )

        _safe_extend(
            recommendations,
            lambda: incidents.detect_known_exploits(
                findings_by_type.get("vulnerability", [])
            ),
            "known_exploits",
        )

        # Typosquatting
        typosquat_findings = [
            f
            for f in findings_by_type.get("quality", [])
            if "typosquat" in f.get("details", {}).get("risk_type", "").lower()
        ]
        if typosquat_findings:
            _safe_extend(
                recommendations,
                lambda: incidents.process_typosquatting(typosquat_findings),
                "typosquatting_quality",
            )
        if findings_by_type.get("typosquatting"):
            _safe_extend(
                recommendations,
                lambda: incidents.process_typosquatting(
                    findings_by_type["typosquatting"]
                ),
                "typosquatting",
            )

        # 13. End-of-Life Dependencies
        _safe_extend(
            recommendations,
            lambda: dep_analysis.analyze_end_of_life(findings_by_type.get("eol", [])),
            "end_of_life",
        )

        # 14. Optimization (Quick Wins)
        _safe_extend(
            recommendations,
            lambda: optimization.identify_quick_wins(
                findings_by_type.get("vulnerability", []), dependencies
            ),
            "quick_wins",
        )

        # Deduplicate recommendations (keep highest scoring for each type+component)
        before_dedup = len(recommendations)
        recommendations = _deduplicate_recommendations(recommendations)
        if before_dedup != len(recommendations):
            logger.debug(
                f"Deduplicated {before_dedup - len(recommendations)} duplicate recommendations"
            )

        # Sort by priority and impact using common scoring logic
        recommendations.sort(key=lambda r: common.calculate_score(r), reverse=True)

        logger.debug(f"Generated {len(recommendations)} total recommendations")

        return recommendations


# Singleton instance
recommendation_engine = RecommendationEngine()
