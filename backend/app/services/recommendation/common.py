import re
from typing import List
from app.schemas.recommendation import (
    Recommendation,
    RecommendationType,
    Priority,
)
from app.core.constants import (
    RECOMMENDATION_SCORING_WEIGHTS,
    REACHABILITY_SCORING_WEIGHTS,
    REACHABILITY_MODIFIERS,
)


def parse_version_tuple(version: str) -> tuple:
    """Parse a version string into a comparable tuple."""
    # Extract numeric parts
    # This handles simplified version parsing sufficient for comparisons
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts)


def calculate_best_fix_version(versions: List[str]) -> str:
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
        parsed.sort(key=lambda x: parse_version_tuple(x), reverse=True)
        return parsed[0]
    except Exception:
        return parsed[0]


def calculate_score(rec: Recommendation) -> int:
    """
    Calculate a score for sorting recommendations.

    Incorporates EPSS/KEV/Reachability data for intelligent prioritization:
    - KEV findings get significant boost (known exploited in wild)
    - High EPSS findings get boost (likely to be exploited)
    - Reachable findings get boost (actually affect the application)
    - Unreachable findings get deprioritized
    """
    priority_scores = {
        Priority.CRITICAL: RECOMMENDATION_SCORING_WEIGHTS["priority_critical"],
        Priority.HIGH: RECOMMENDATION_SCORING_WEIGHTS["priority_high"],
        Priority.MEDIUM: RECOMMENDATION_SCORING_WEIGHTS["priority_medium"],
        Priority.LOW: RECOMMENDATION_SCORING_WEIGHTS["priority_low"],
    }

    base_score = priority_scores.get(rec.priority, 0)

    # Add impact score
    impact_score = (
        rec.impact.get("critical", 0)
        * RECOMMENDATION_SCORING_WEIGHTS["impact_critical"]
        + rec.impact.get("high", 0) * RECOMMENDATION_SCORING_WEIGHTS["impact_high"]
        + rec.impact.get("medium", 0) * RECOMMENDATION_SCORING_WEIGHTS["impact_medium"]
        + rec.impact.get("low", 0) * RECOMMENDATION_SCORING_WEIGHTS["impact_low"]
    )

    threat_intel_score = 0

    # KEV bonus: Known exploited vulnerabilities are highest priority
    kev_count = rec.impact.get("kev_count", 0)
    if kev_count > 0:
        threat_intel_score += (
            kev_count * RECOMMENDATION_SCORING_WEIGHTS["kev_bonus"]
        )  # Major boost for KEV findings

    # KEV Ransomware: Even higher priority if ransomware campaigns use it
    kev_ransomware_count = rec.impact.get("kev_ransomware_count", 0)
    if kev_ransomware_count > 0:
        threat_intel_score += (
            kev_ransomware_count
            * RECOMMENDATION_SCORING_WEIGHTS["kev_ransomware_bonus"]
        )  # Additional boost

    # High EPSS bonus: Vulnerabilities likely to be exploited soon
    high_epss_count = rec.impact.get("high_epss_count", 0)
    if high_epss_count > 0:
        threat_intel_score += (
            high_epss_count * RECOMMENDATION_SCORING_WEIGHTS["high_epss_bonus"]
        )

    # Medium EPSS: Some probability of exploitation
    medium_epss_count = rec.impact.get("medium_epss_count", 0)
    if medium_epss_count > 0:
        threat_intel_score += (
            medium_epss_count * RECOMMENDATION_SCORING_WEIGHTS["medium_epss_bonus"]
        )

    # Active exploitation: Currently being exploited in the wild
    active_exploitation = rec.impact.get("active_exploitation_count", 0)
    if active_exploitation > 0:
        threat_intel_score += (
            active_exploitation
            * RECOMMENDATION_SCORING_WEIGHTS["active_exploitation_bonus"]
        )

    reachability_modifier = 1.0

    # Reachable vulnerabilities are more important
    reachable_count = rec.impact.get("reachable_count", 0)
    reachable_critical = rec.impact.get("reachable_critical", 0)
    reachable_high = rec.impact.get("reachable_high", 0)

    if reachable_count > 0:
        # Boost for confirmed reachable vulns
        threat_intel_score += (
            reachable_critical * REACHABILITY_SCORING_WEIGHTS["critical_bonus"]
        )
        threat_intel_score += (
            reachable_high * REACHABILITY_SCORING_WEIGHTS["high_bonus"]
        )
        threat_intel_score += (
            reachable_count - reachable_critical - reachable_high
        ) * REACHABILITY_SCORING_WEIGHTS["other_bonus"]

    # Unreachable vulnerabilities should be deprioritized
    unreachable_count = rec.impact.get("unreachable_count", 0)
    if unreachable_count > 0 and rec.impact.get("total", 1) > 0:
        unreachable_ratio = unreachable_count / rec.impact.get("total", 1)
        # If mostly unreachable, reduce priority significantly
        if (
            unreachable_ratio
            > REACHABILITY_MODIFIERS["high_unreachable_ratio_threshold"]
        ):
            reachability_modifier = REACHABILITY_MODIFIERS["high_unreachable_penalty"]
        elif (
            unreachable_ratio
            > REACHABILITY_MODIFIERS["medium_unreachable_ratio_threshold"]
        ):
            reachability_modifier = REACHABILITY_MODIFIERS["medium_unreachable_penalty"]

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
