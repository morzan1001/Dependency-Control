"""Generate actionable remediation recommendations from all finding types."""

import functools
import logging
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from app.models.finding import CRYPTO_FINDING_TYPES
from app.schemas.enrichment import VulnerabilityEnrichment
from app.schemas.recommendation import Recommendation
from app.services.recommendation import (
    common,
    graph,
    iac,
    incidents,
    insights,
    licenses,
    optimization,
    quality,
    risks,
    sast,
    secrets,
    trends,
    vulnerabilities,
)
from app.services.recommendation import (
    crypto as crypto_recs,
)
from app.services.recommendation import (
    dependencies as dep_analysis,
)
from app.services.recommendation.common import ModelOrDict, get_attr

logger = logging.getLogger(__name__)


def _safe_extend(
    recommendations: list[Recommendation],
    generator: Callable[[], list[Recommendation]],
    module_name: str,
) -> None:
    """Extend recommendations from ``generator``, swallowing its exceptions so one module can't abort the rest."""
    try:
        result = generator()
        if result:
            recommendations.extend(result)
            logger.debug(f"{module_name}: generated {len(result)} recommendations")
    except Exception as e:
        logger.exception("Error in %s: %s", module_name, e)


def _deduplicate_recommendations(
    recommendations: list[Recommendation],
) -> list[Recommendation]:
    """Drop duplicates keyed on (type, component, title, action), keeping the highest-scoring."""
    seen: dict[tuple[str, str, str, str], Recommendation] = {}

    for rec in recommendations:
        primary_component = ""
        for comp in rec.affected_components:
            if comp and isinstance(comp, str) and comp.strip():
                primary_component = comp.strip()
                break

        # Always include the title AND an action discriminator so that only
        # genuine duplicates (same type + component + title + action variant)
        # merge. Distinct recommendations that share a type and first component
        # must be preserved, e.g.:
        #   - a cert with both a crypto_cert_expired and a crypto_cert_self_signed
        #     finding -> two ROTATE_CERTIFICATE recs with an IDENTICAL title, so
        #     the action['finding_type'] is what tells them apart;
        #   - the four SUPPLY_CHAIN_RISK recs and the per-category
        #     FIX_CODE_SECURITY recs -> distinguished by their titles.
        action = rec.action if isinstance(rec.action, dict) else {}
        action_discriminator = action.get("finding_type") or action.get("type") or ""
        key = (
            rec.type.value,
            primary_component,
            rec.title,
            str(action_discriminator),
        )

        if key not in seen:
            seen[key] = rec
        else:
            existing_score = common.calculate_score(seen[key])
            new_score = common.calculate_score(rec)
            if new_score > existing_score:
                seen[key] = rec

    return list(seen.values())


class RecommendationEngine:
    """Generates remediation recommendations, delegating to modules in app.services.recommendation."""

    def generate_recommendations(
        self,
        findings: Sequence[ModelOrDict] | None = None,
        dependencies: Sequence[ModelOrDict] | None = None,
        join_dependencies: Sequence[ModelOrDict] | None = None,
        previous_scan: trends.PreviousScan | None = None,
        previous_scan_dependencies: Sequence[ModelOrDict] | None = None,
        cve_recurrence: dict[str, trends.CveRecurrence] | None = None,
        recurrence_window_scans: int = 0,
        cross_project_data: dict[str, Any] | None = None,
        threat_intel: Mapping[str, VulnerabilityEnrichment] | None = None,
    ) -> list[Recommendation]:
        """Prioritized remediation; ``join_dependencies``: rows findings name; ``threat_intel``: per-CVE KEV/EPSS."""
        findings_list: list[ModelOrDict] = list(findings) if findings else []
        dependencies_list: list[ModelOrDict] = list(dependencies) if dependencies else []
        join_list: list[ModelOrDict] = list(join_dependencies) if join_dependencies else []

        logger.debug(
            f"Generating recommendations for {len(findings_list)} findings, {len(dependencies_list)} dependencies"
        )

        recommendations: list[Recommendation] = []

        findings_by_type: dict[str, list[ModelOrDict]] = defaultdict(list)
        for f in findings_list:
            finding_type = get_attr(f, "type", "other")
            findings_by_type[finding_type].append(f)
        vulns = findings_by_type["vulnerability"]
        quality_findings = findings_by_type["quality"]
        malware_by_kind: dict[str, list[ModelOrDict]] = defaultdict(list)
        for f in findings_by_type["malware"]:
            malware_by_kind[common.malware_kind(f)].append(f)

        _safe_extend(
            recommendations,
            lambda: vulnerabilities.process_vulnerabilities(vulns, join_list),
            "vulnerabilities",
        )
        _safe_extend(recommendations, lambda: secrets.process_secrets(findings_by_type["secret"]), "secrets")
        _safe_extend(recommendations, lambda: sast.process_sast(findings_by_type["sast"]), "sast")
        _safe_extend(recommendations, lambda: iac.process_iac(findings_by_type["iac"]), "iac")
        _safe_extend(recommendations, lambda: licenses.process_licenses(findings_by_type["license"]), "licenses")
        if previous_scan_dependencies:
            _safe_extend(
                recommendations,
                lambda: licenses.detect_license_drift(dependencies_list, previous_scan_dependencies),
                "license_drift",
            )
        _safe_extend(recommendations, lambda: quality.process_quality(quality_findings), "quality")

        crypto_findings = [f for ft, group in findings_by_type.items() if ft in CRYPTO_FINDING_TYPES for f in group]
        _safe_extend(recommendations, lambda: crypto_recs.process_crypto(crypto_findings), "crypto")

        _safe_extend(
            recommendations,
            lambda: dep_analysis.analyze_outdated_dependencies(dependencies_list),
            "outdated_dependencies",
        )
        _safe_extend(
            recommendations,
            lambda: dep_analysis.analyze_version_fragmentation(dependencies_list),
            "version_fragmentation",
        )
        _safe_extend(
            recommendations,
            lambda: dep_analysis.analyze_dev_in_production(dependencies_list),
            "dev_in_production",
        )

        if previous_scan is not None:
            _safe_extend(
                recommendations,
                lambda: trends.analyze_regressions(findings_list, previous_scan),
                "regressions",
            )
        if cve_recurrence:
            _safe_extend(
                recommendations,
                lambda: trends.analyze_recurring_issues(cve_recurrence, recurrence_window_scans),
                "recurring_issues",
            )

        _safe_extend(
            recommendations,
            lambda: graph.analyze_deep_dependency_chains(dependencies_list),
            "deep_dependency_chains",
        )
        _safe_extend(
            recommendations,
            lambda: graph.analyze_duplicate_packages(dependencies_list),
            "duplicate_packages",
        )

        if cross_project_data:
            _safe_extend(
                recommendations,
                lambda: insights.analyze_cross_project_patterns(cross_project_data),
                "cross_project_patterns",
            )
        _safe_extend(
            recommendations,
            lambda: insights.correlate_scorecard_with_vulnerabilities(vulns, quality_findings),
            "scorecard_correlation",
        )

        packages = functools.cache(functools.partial(risks.roll_up_packages, findings_list))
        _safe_extend(recommendations, lambda: risks.detect_critical_hotspots(packages()), "critical_hotspots")
        _safe_extend(recommendations, lambda: risks.detect_toxic_dependencies(packages()), "toxic_dependencies")
        _safe_extend(
            recommendations,
            lambda: risks.analyze_attack_surface(dependencies_list, findings_list),
            "attack_surface",
        )

        _safe_extend(recommendations, lambda: incidents.process_malware(malware_by_kind["malware"]), "malware")
        _safe_extend(
            recommendations, lambda: incidents.process_hash_mismatch(malware_by_kind["hash_mismatch"]), "hash_mismatch"
        )
        _safe_extend(
            recommendations, lambda: incidents.process_typosquatting(malware_by_kind["typosquat"]), "typosquatting"
        )
        _safe_extend(
            recommendations,
            lambda: incidents.detect_known_exploits(vulns, threat_intel),
            "known_exploits",
        )

        _safe_extend(
            recommendations,
            lambda: dep_analysis.analyze_end_of_life(findings_by_type["eol"]),
            "end_of_life",
        )
        _safe_extend(recommendations, lambda: optimization.identify_quick_wins(vulns, join_list), "quick_wins")

        before_dedup = len(recommendations)
        recommendations = _deduplicate_recommendations(recommendations)
        if before_dedup != len(recommendations):
            logger.debug(f"Deduplicated {before_dedup - len(recommendations)} duplicate recommendations")

        # Priority tier first, then score, so a high-volume medium never outranks a critical fix.
        recommendations.sort(key=common.sort_key, reverse=True)

        logger.debug(f"Generated {len(recommendations)} total recommendations")

        return recommendations


recommendation_engine = RecommendationEngine()
