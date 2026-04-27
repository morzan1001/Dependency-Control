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

ModelOrDict = Union[BaseModel, Dict[str, Any]]


def get_attr(obj: ModelOrDict, key: str, default: Any = None) -> Any:
    """Standard model-or-dict accessor used by all recommendation modules."""
    if isinstance(obj, BaseModel):
        return getattr(obj, key, default)
    elif isinstance(obj, dict):
        return obj.get(key, default)
    return default


def group_findings_by_field(
    findings: List[ModelOrDict],
    field: str = "component",
) -> Dict[str, List[ModelOrDict]]:
    """Group findings by `field` value, returning {value: [findings]}."""
    grouped: Dict[str, List[ModelOrDict]] = {}
    for finding in findings:
        key = get_attr(finding, field, "unknown") or "unknown"
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(finding)
    return grouped


def extract_cve_id(finding: ModelOrDict) -> Optional[str]:
    """Return the first CVE-XXXX-XXXXX id found in finding.id, details.cve_id, or aliases."""
    finding_id = get_attr(finding, "id") or get_attr(finding, "finding_id")
    if finding_id and str(finding_id).startswith("CVE-"):
        return str(finding_id)

    details = get_attr(finding, "details", {})
    if isinstance(details, dict):
        cve_id = details.get("cve_id")
        if cve_id and str(cve_id).startswith("CVE-"):
            return str(cve_id)

    aliases = get_attr(finding, "aliases", [])
    if not aliases and isinstance(details, dict):
        aliases = details.get("aliases", [])

    for alias in aliases or []:
        if alias and str(alias).startswith("CVE-"):
            return str(alias)

    return None


def parse_version_tuple(version: str) -> tuple:
    """Naive numeric tuple — sufficient for picking the highest of a candidate list."""
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts)


def calculate_best_fix_version(versions: List[str]) -> str:
    """Pick the highest fix version (handles comma-separated lists)."""
    if not versions:
        return "unknown"

    valid_versions = [v.strip() for v in versions if v and v.strip()]
    if not valid_versions:
        return "unknown"

    if len(valid_versions) == 1:
        return valid_versions[0]

    parsed = []
    for v in valid_versions:
        for part in v.split(","):
            part = part.strip()
            if part:
                parsed.append(part)

    if not parsed:
        return "unknown"

    try:
        parsed.sort(key=lambda x: parse_version_tuple(x), reverse=True)
        return parsed[0] if parsed[0] else "unknown"
    except Exception:
        return parsed[0] if parsed[0] else "unknown"


# Cached at module-level to avoid repeated dict lookups in calculate_score().
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
    """Score recommendations for sorting. KEV/active-exploitation/reachable boosts
    push real exposures up; mostly-unreachable findings get a multiplicative penalty."""
    impact = rec.impact
    base_score = _PRIORITY_SCORES.get(rec.priority, 0)

    impact_score = (
        impact.get("critical", 0) * _IMPACT_CRITICAL
        + impact.get("high", 0) * _IMPACT_HIGH
        + impact.get("medium", 0) * _IMPACT_MEDIUM
        + impact.get("low", 0) * _IMPACT_LOW
    )

    threat_intel_score = 0

    kev_count = impact.get("kev_count", 0)
    if kev_count > 0:
        threat_intel_score += kev_count * _KEV_BONUS

    kev_ransomware_count = impact.get("kev_ransomware_count", 0)
    if kev_ransomware_count > 0:
        threat_intel_score += kev_ransomware_count * _KEV_RANSOMWARE_BONUS

    high_epss_count = impact.get("high_epss_count", 0)
    if high_epss_count > 0:
        threat_intel_score += high_epss_count * _HIGH_EPSS_BONUS

    medium_epss_count = impact.get("medium_epss_count", 0)
    if medium_epss_count > 0:
        threat_intel_score += medium_epss_count * _MEDIUM_EPSS_BONUS

    active_exploitation = impact.get("active_exploitation_count", 0)
    if active_exploitation > 0:
        threat_intel_score += active_exploitation * _ACTIVE_EXPLOIT_BONUS

    reachability_modifier = 1.0

    reachable_count = impact.get("reachable_count", 0)
    if reachable_count > 0:
        reachable_critical = impact.get("reachable_critical", 0)
        reachable_high = impact.get("reachable_high", 0)
        threat_intel_score += reachable_critical * _REACH_CRITICAL_BONUS
        threat_intel_score += reachable_high * _REACH_HIGH_BONUS
        threat_intel_score += (reachable_count - reachable_critical - reachable_high) * _REACH_OTHER_BONUS

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

    # Both Effort enum and raw string are accepted.
    effort_key = rec.effort.value if hasattr(rec.effort, "value") else rec.effort
    effort_bonus = EFFORT_BONUSES.get(effort_key, 0)

    type_bonus = RECOMMENDATION_TYPE_BONUSES.get(rec.type.value, 0)

    total_score = base_score + impact_score + threat_intel_score + effort_bonus + type_bonus
    return int(total_score * reachability_modifier)
