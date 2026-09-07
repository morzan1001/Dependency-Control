import re
from collections.abc import Callable, Iterable, Sequence
from typing import Any

from pydantic import BaseModel

from app.core.constants import (
    ACTIONABLE_VULN_BONUS,
    EFFORT_BONUSES,
    REACHABILITY_MODIFIERS,
    REACHABILITY_SCORING_WEIGHTS,
    RECOMMENDATION_SCORING_WEIGHTS,
    RECOMMENDATION_TYPE_BONUSES,
)
from app.schemas.recommendation import Priority, Recommendation
from app.services.enrichment import canonical_cves

ModelOrDict = BaseModel | dict[str, Any]

# Components one recommendation lists. Every generator draws its evidence through
# sample_components, so the cut is one number and the reader always gets the population.
AFFECTED_COMPONENTS_SHOWN = 20


def name_some(values: Sequence[str], shown: int) -> str:
    """Prose list of the first `shown` values, saying how many it left unnamed."""
    head = ", ".join(values[:shown])
    remaining = len(values) - shown
    return f"{head} and {remaining} more" if remaining > 0 else head


def sample_components(components: Iterable[str]) -> tuple[list[str], int]:
    """The components a recommendation lists, and how many it actually covers.

    Order is the caller's, so a ranked population keeps its ranking; pass a sorted sequence
    where the source is a set, whose iteration order changes between runs.
    """
    unique = list(dict.fromkeys(component for component in components if component))
    return unique[:AFFECTED_COMPONENTS_SHOWN], len(unique)


def sampled(name: str, values: Sequence[Any], cap: int) -> dict[str, Any]:
    """A sample of `values` under `name`, alongside how many there are under "<name>_total".

    Evidence inside an ``action`` block is read as the whole of what a card found; the population
    is what tells a reader that the list they are acting on is a sample of it.
    """
    return {name: list(values[:cap]), f"{name}_total": len(values)}


def take_top(candidates: Sequence[Any], cap: int) -> list[tuple[int, Any, int]]:
    """The highest-ranked `cap` candidates as (rank, candidate, population).

    Rank and population are both 0 while everything ranked is emitted; past the cap a generator
    passes them on so a reader who sees `cap` recommendations of one kind knows more were ranked.
    """
    cut = len(candidates) > cap
    population = len(candidates) if cut else 0
    return [(rank if cut else 0, candidate, population) for rank, candidate in enumerate(candidates[:cap], start=1)]


def get_attr(obj: ModelOrDict, key: str, default: Any = None) -> Any:
    """Standard model-or-dict accessor used by all recommendation modules."""
    if isinstance(obj, BaseModel):
        return getattr(obj, key, default)
    elif isinstance(obj, dict):
        return obj.get(key, default)
    return default


def scorecard_details(details: Any) -> dict[str, Any]:
    """Per-issue scorecard fields (critical_issues, failed_checks, project_url) live
    one level down in the aggregated shape: details.quality_issues[].details."""
    if not isinstance(details, dict):
        return {}
    for issue in details.get("quality_issues") or []:
        if isinstance(issue, dict) and issue.get("type") == "scorecard":
            nested = issue.get("details")
            if isinstance(nested, dict):
                return nested
    return {}


def group_findings_by_field(
    findings: list[ModelOrDict],
    field: str = "component",
) -> dict[str, list[ModelOrDict]]:
    """Group findings by `field` value, returning {value: [findings]}."""
    grouped: dict[str, list[ModelOrDict]] = {}
    for finding in findings:
        key = get_attr(finding, field, "unknown") or "unknown"
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(finding)
    return grouped


def finding_cve_ids(
    finding: ModelOrDict,
    advisory_filter: Callable[[dict[str, Any]], bool] | None = None,
) -> list[str]:
    """Every advisory a stored vulnerability finding names, collapsed to its CVE identity.

    Aggregation groups one record per (component, version) and its top-level ``id`` is that pair,
    so the advisory identity only ever lives in ``details.vulnerabilities`` — the same place the
    scan delta reads its identity from.

    ``advisory_filter`` narrows the list to the advisories a card is actually about, so a group of
    seven log4j CVEs is not presented as seven ransomware CVEs. Enrichment marks each advisory and
    the document, but a live refresh writes the document only, so a finding whose advisories carry
    no mark falls back to naming the whole group rather than nothing.
    """
    details = get_attr(finding, "details", {})
    if not isinstance(details, dict):
        return []
    if advisory_filter is not None:
        entries = [e for e in details.get("vulnerabilities") or [] if isinstance(e, dict) and advisory_filter(e)]
        if entries:
            return canonical_cves([{"vulnerabilities": entries}])
    return canonical_cves([details])


def parse_version_tuple(version: str) -> tuple:
    """Naive numeric tuple — sufficient for picking the highest of a candidate list."""
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts)


# Versions named per package inside an action block; version_count carries the population.
ACTION_VERSION_SAMPLE = 5


def newest_first(versions: Iterable[Any]) -> list[str]:
    """Versions ranked newest first. A set-derived list carries no order of its own, so a sample
    taken off one is a different five between runs."""
    return sorted((str(v) for v in versions), key=parse_version_tuple, reverse=True)


def calculate_best_fix_version(versions: list[str]) -> str:
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

    parsed.sort(key=parse_version_tuple, reverse=True)
    return parsed[0]


# Module-level cache to avoid repeated dict lookups on the hot scoring path.
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
    """Score a recommendation for sorting; mostly-unreachable findings get a multiplicative penalty."""
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


_PRIORITY_RANK = {Priority.CRITICAL: 3, Priority.HIGH: 2, Priority.MEDIUM: 1, Priority.LOW: 0}


def sort_key(rec: Recommendation) -> tuple[int, int]:
    """Order recommendations by priority tier first, then by score. Priority must dominate so a
    high-volume medium item (e.g. "445 recurring vulns") never outranks a critical KEV/exploit fix;
    calculate_score alone let raw counts overwhelm the priority base."""
    return (_PRIORITY_RANK.get(rec.priority, 0), calculate_score(rec))
