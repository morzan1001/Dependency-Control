import re
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel

from app.schemas.recommendation import Recommendation, Priority
from app.core.constants import (
    ACTIONABLE_VULN_BONUS,
    EFFORT_BONUSES,
    RECOMMENDATION_SCORING_WEIGHTS,
    RECOMMENDATION_TYPE_BONUSES,
    REACHABILITY_SCORING_WEIGHTS,
    REACHABILITY_MODIFIERS,
)

# Type alias for items that can be either Pydantic models or dicts
ModelOrDict = Union[BaseModel, Dict[str, Any]]


def get_attr(obj: ModelOrDict, key: str, default: Any = None) -> Any:
    """
    Get attribute from Pydantic model or dict in a type-safe way.

    This is the standard accessor for all recommendation modules.

    Args:
        obj: A Pydantic model instance or dictionary
        key: The attribute/key name to access
        default: Default value if not found

    Returns:
        The attribute value or default
    """
    if isinstance(obj, BaseModel):
        return getattr(obj, key, default)
    elif isinstance(obj, dict):
        return obj.get(key, default)
    return default


def extract_cve_id(finding: ModelOrDict) -> Optional[str]:
    """
    Extract CVE ID from a finding using multiple strategies.

    Supports both Pydantic FindingRecord models and legacy dicts.
    Checks finding.id, finding.details.cve_id, and aliases.
    Returns the first valid CVE-XXXX-XXXXX format ID found, or None.
    """
    # Strategy 1: Direct ID field
    finding_id = get_attr(finding, "id") or get_attr(finding, "finding_id")
    if finding_id and str(finding_id).startswith("CVE-"):
        return str(finding_id)

    # Strategy 2: Details cve_id field
    details = get_attr(finding, "details", {})
    if isinstance(details, dict):
        cve_id = details.get("cve_id")
        if cve_id and str(cve_id).startswith("CVE-"):
            return str(cve_id)

    # Strategy 3: Check aliases
    aliases = get_attr(finding, "aliases", [])
    if not aliases and isinstance(details, dict):
        aliases = details.get("aliases", [])

    for alias in aliases or []:
        if alias and str(alias).startswith("CVE-"):
            return str(alias)

    return None


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

    # Filter out empty/whitespace-only versions first
    valid_versions = [v.strip() for v in versions if v and v.strip()]
    if not valid_versions:
        return "unknown"

    if len(valid_versions) == 1:
        return valid_versions[0]

    # Parse and find the highest version
    parsed = []
    for v in valid_versions:
        # Handle comma-separated versions (multiple options)
        for part in v.split(","):
            part = part.strip()
            if part:
                parsed.append(part)

    if not parsed:
        return "unknown"

    # Sort by version (best effort)
    try:
        parsed.sort(key=lambda x: parse_version_tuple(x), reverse=True)
        return parsed[0] if parsed[0] else "unknown"
    except Exception:
        return parsed[0] if parsed[0] else "unknown"


# Pre-cache scoring weights at module level to avoid repeated dict lookups
_PRIORITY_SCORES = {
    Priority.CRITICAL: RECOMMENDATION_SCORING_WEIGHTS["priority_critical"],
    Priority.HIGH: RECOMMENDATION_SCORING_WEIGHTS["priority_high"],
    Priority.MEDIUM: RECOMMENDATION_SCORING_WEIGHTS["priority_medium"],
    Priority.LOW: RECOMMENDATION_SCORING_WEIGHTS["priority_low"],
}
_IMPACT_CRITICAL = RECOMMENDATION_SCORING_WEIGHTS["impact_critical"]
_IMPACT_HIGH = RECOMMENDATION_SCORING_WEIGHTS["impact_high"]
_IMPACT_MEDIUM = RECOMMENDATION_SCORING_WEIGHTS["impact_medium"]
_IMPACT_LOW = RECOMMENDATION_SCORING_WEIGHTS["impact_low"]
_KEV_BONUS = RECOMMENDATION_SCORING_WEIGHTS["kev_bonus"]
_KEV_RANSOMWARE_BONUS = RECOMMENDATION_SCORING_WEIGHTS["kev_ransomware_bonus"]
_HIGH_EPSS_BONUS = RECOMMENDATION_SCORING_WEIGHTS["high_epss_bonus"]
_MEDIUM_EPSS_BONUS = RECOMMENDATION_SCORING_WEIGHTS["medium_epss_bonus"]
_ACTIVE_EXPLOIT_BONUS = RECOMMENDATION_SCORING_WEIGHTS["active_exploitation_bonus"]
_REACH_CRITICAL_BONUS = REACHABILITY_SCORING_WEIGHTS["critical_bonus"]
_REACH_HIGH_BONUS = REACHABILITY_SCORING_WEIGHTS["high_bonus"]
_REACH_OTHER_BONUS = REACHABILITY_SCORING_WEIGHTS["other_bonus"]
_HIGH_UNREACH_THRESHOLD = REACHABILITY_MODIFIERS["high_unreachable_ratio_threshold"]
_HIGH_UNREACH_PENALTY = REACHABILITY_MODIFIERS["high_unreachable_penalty"]
_MED_UNREACH_THRESHOLD = REACHABILITY_MODIFIERS["medium_unreachable_ratio_threshold"]
_MED_UNREACH_PENALTY = REACHABILITY_MODIFIERS["medium_unreachable_penalty"]


def calculate_score(rec: Recommendation) -> int:
    """
    Calculate a score for sorting recommendations.

    Incorporates EPSS/KEV/Reachability data for intelligent prioritization:
    - KEV findings get significant boost (known exploited in wild)
    - High EPSS findings get boost (likely to be exploited)
    - Reachable findings get boost (actually affect the application)
    - Unreachable findings get deprioritized
    """
    # Use pre-cached weights for performance
    impact = rec.impact
    base_score = _PRIORITY_SCORES.get(rec.priority, 0)

    # Add impact score using cached weights
    impact_score = (
        impact.get("critical", 0) * _IMPACT_CRITICAL
        + impact.get("high", 0) * _IMPACT_HIGH
        + impact.get("medium", 0) * _IMPACT_MEDIUM
        + impact.get("low", 0) * _IMPACT_LOW
    )

    threat_intel_score = 0

    # KEV bonus: Known exploited vulnerabilities are highest priority
    kev_count = impact.get("kev_count", 0)
    if kev_count > 0:
        threat_intel_score += kev_count * _KEV_BONUS

    # KEV Ransomware: Even higher priority if ransomware campaigns use it
    kev_ransomware_count = impact.get("kev_ransomware_count", 0)
    if kev_ransomware_count > 0:
        threat_intel_score += kev_ransomware_count * _KEV_RANSOMWARE_BONUS

    # High EPSS bonus: Vulnerabilities likely to be exploited soon
    high_epss_count = impact.get("high_epss_count", 0)
    if high_epss_count > 0:
        threat_intel_score += high_epss_count * _HIGH_EPSS_BONUS

    # Medium EPSS: Some probability of exploitation
    medium_epss_count = impact.get("medium_epss_count", 0)
    if medium_epss_count > 0:
        threat_intel_score += medium_epss_count * _MEDIUM_EPSS_BONUS

    # Active exploitation: Currently being exploited in the wild
    active_exploitation = impact.get("active_exploitation_count", 0)
    if active_exploitation > 0:
        threat_intel_score += active_exploitation * _ACTIVE_EXPLOIT_BONUS

    reachability_modifier = 1.0

    # Reachable vulnerabilities are more important
    reachable_count = impact.get("reachable_count", 0)
    if reachable_count > 0:
        reachable_critical = impact.get("reachable_critical", 0)
        reachable_high = impact.get("reachable_high", 0)
        threat_intel_score += reachable_critical * _REACH_CRITICAL_BONUS
        threat_intel_score += reachable_high * _REACH_HIGH_BONUS
        threat_intel_score += (reachable_count - reachable_critical - reachable_high) * _REACH_OTHER_BONUS

    # Unreachable vulnerabilities should be deprioritized
    unreachable_count = impact.get("unreachable_count", 0)
    total_count = impact.get("total", 1)
    if unreachable_count > 0 and total_count > 0:
        unreachable_ratio = unreachable_count / total_count
        if unreachable_ratio > _HIGH_UNREACH_THRESHOLD:
            reachability_modifier = _HIGH_UNREACH_PENALTY
        elif unreachable_ratio > _MED_UNREACH_THRESHOLD:
            reachability_modifier = _MED_UNREACH_PENALTY

    actionable_count = impact.get("actionable_count", 0)
    if actionable_count > 0:
        threat_intel_score += actionable_count * ACTIONABLE_VULN_BONUS

    # Prefer lower effort (handle both Effort enum and string)
    effort_key = rec.effort.value if hasattr(rec.effort, "value") else rec.effort
    effort_bonus = EFFORT_BONUSES.get(effort_key, 0)

    # Type-based bonus from constants (uses enum value as key)
    type_bonus = RECOMMENDATION_TYPE_BONUSES.get(rec.type.value, 0)

    # Calculate final score with reachability modifier
    total_score = base_score + impact_score + threat_intel_score + effort_bonus + type_bonus
    return int(total_score * reachability_modifier)
