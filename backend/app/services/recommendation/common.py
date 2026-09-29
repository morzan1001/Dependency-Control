from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from app.core.constants import (
    ACTIONABLE_VULN_BONUS,
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
    EFFORT_BONUSES,
    REACHABILITY_MODIFIERS,
    REACHABILITY_SCORING_WEIGHTS,
    RECOMMENDATION_SCORING_WEIGHTS,
    RECOMMENDATION_TYPE_BONUSES,
)
from app.core.cve import canonical_cves
from app.core.epss import bucket_epss
from app.schemas.recommendation import Priority, Recommendation, VulnerabilityInfo
from app.services.aggregation.versions import aggregate_fixed_version, newest_first, split_fixed_versions

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
    if isinstance(obj, dict):
        return obj.get(key, default)
    return default


def dependency_label(dep: ModelOrDict) -> str:
    return f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"


def scorecard_score(details: Any) -> float | None:
    """A quality finding's OpenSSF Scorecard score; None when it carries maintainer risk only."""
    score = details.get("overall_score") if isinstance(details, dict) else None
    return None if score is None else float(score)


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


def live_advisories(details: Any) -> list[dict[str, Any]]:
    """A vulnerability finding's advisories that no per-CVE waiver covers."""
    if not isinstance(details, dict):
        return []
    return [a for a in details.get("vulnerabilities") or [] if isinstance(a, dict) and not a.get("waived")]


def live_fixed_version(finding: ModelOrDict) -> str | None:
    """The version fixing every live advisory that names a fix; None while a live CRITICAL/HIGH one names none."""
    advisories = live_advisories(get_attr(finding, "details", {}))
    if any(a.get("severity") in ("CRITICAL", "HIGH") and not a.get("fixed_version") for a in advisories):
        return None
    return aggregate_fixed_version([a for a in advisories if a.get("fixed_version")], get_attr(finding, "version"))


def max_advisory_cvss(details: dict[str, Any]) -> float | None:
    """Aggregated findings carry CVSS only per advisory in details.vulnerabilities[]."""
    scores = [
        vuln["cvss_score"]
        for vuln in details.get("vulnerabilities") or []
        if isinstance(vuln, dict) and vuln.get("cvss_score") is not None
    ]
    return max(scores) if scores else None


def live_cves(details_list: Iterable[Any]) -> list[str]:
    """Distinct CVEs across advisory lists that no per-CVE waiver covers."""
    return canonical_cves([{"vulnerabilities": live_advisories(details)} for details in details_list])


# Versions named per package inside an action block; version_count carries the population.
ACTION_VERSION_SAMPLE = 5


def calculate_best_fix_version(versions: list[str]) -> str:
    """The highest single version among stored fixed_version values."""
    parts = [part for v in versions for part in split_fixed_versions(v)]
    return newest_first(parts)[0] if parts else "unknown"


def vuln_info(f: ModelOrDict) -> VulnerabilityInfo:
    """A vulnerability finding in the shape every per-package roll-up counts, marked by its worst live advisory."""
    advisories = live_advisories(get_attr(f, "details", {}))
    epss = [a["epss_score"] for a in advisories if a.get("epss_score") is not None]
    risk = [a["risk_score"] for a in advisories if a.get("risk_score") is not None]

    return VulnerabilityInfo(
        finding_id=get_attr(f, "id", ""),
        advisories=advisories,
        severity=get_attr(f, "severity", "UNKNOWN"),
        package_name=get_attr(f, "component", ""),
        current_version=get_attr(f, "version") or "",
        fixed_version=live_fixed_version(f),
        epss_score=max(epss, default=None),
        is_kev=any(a.get(DETAILS_KEY_IN_KEV) for a in advisories),
        kev_ransomware=any(a.get(DETAILS_KEY_KEV_RANSOMWARE) for a in advisories),
        is_reachable=get_attr(f, "reachable"),
        reachability_level=get_attr(f, "reachability_level"),
        risk_score=max(risk, default=None),
    )


@dataclass(frozen=True)
class VulnStats:
    """What a set of vulnerability findings adds up to; every per-package card reads it."""

    total: int
    severity: Counter[str]
    cves: list[str]
    kev: int
    kev_ransomware: int
    high_epss: int
    medium_epss: int
    reachable: int
    unreachable: int
    reachable_critical: int
    reachable_high: int
    unreachable_critical: int
    actionable: int
    epss_scores: list[float]
    # Installed versions and distinct fixes, newest first.
    versions: list[str]
    fixed_versions: list[str]
    best_fix: str

    def impact(self) -> dict[str, Any]:
        return {
            "critical": self.severity["CRITICAL"],
            "high": self.severity["HIGH"],
            "medium": self.severity["MEDIUM"],
            "low": self.severity["LOW"],
            "total": self.total,
            "kev_count": self.kev,
            "kev_ransomware_count": self.kev_ransomware,
            "high_epss_count": self.high_epss,
            "medium_epss_count": self.medium_epss,
            "avg_epss": round(sum(self.epss_scores) / len(self.epss_scores), 4) if self.epss_scores else None,
            "reachable_count": self.reachable,
            "unreachable_count": self.unreachable,
            "reachable_critical": self.reachable_critical,
            "reachable_high": self.reachable_high,
            "actionable_count": self.actionable,
        }


def summarize_vulns(vulns: list[VulnerabilityInfo]) -> VulnStats:
    reachable = [v for v in vulns if v.is_reachable is True]
    unreachable = [v for v in vulns if v.is_reachable is False]
    epss_scores = [v.epss_score for v in vulns if v.epss_score is not None]
    epss_buckets = Counter(bucket_epss(score) for score in epss_scores)
    fixes = [v.fixed_version for v in vulns if v.fixed_version]
    return VulnStats(
        total=len(vulns),
        severity=Counter(v.severity for v in vulns),
        cves=canonical_cves([{"vulnerabilities": v.advisories} for v in vulns]),
        kev=sum(v.is_kev for v in vulns),
        kev_ransomware=sum(v.kev_ransomware for v in vulns),
        high_epss=epss_buckets["high"],
        medium_epss=epss_buckets["medium"],
        reachable=len(reachable),
        unreachable=len(unreachable),
        reachable_critical=sum(v.severity == "CRITICAL" for v in reachable),
        reachable_high=sum(v.severity == "HIGH" for v in reachable),
        unreachable_critical=sum(v.severity == "CRITICAL" for v in unreachable),
        actionable=sum(v.is_actionable for v in vulns),
        epss_scores=epss_scores,
        versions=newest_first({v.current_version for v in vulns if v.current_version}),
        fixed_versions=newest_first({part for fix in fixes for part in split_fixed_versions(fix)}),
        best_fix=calculate_best_fix_version(fixes),
    )


def vuln_priority(stats: VulnStats) -> Priority:
    """Urgency of a set of vulnerabilities: KEV or a reachable critical first; all-unreachable criticals one lower."""
    critical = stats.severity["CRITICAL"]
    if stats.kev or stats.reachable_critical:
        return Priority.CRITICAL
    if critical:
        return Priority.HIGH if stats.unreachable_critical == critical else Priority.CRITICAL
    if stats.high_epss or stats.reachable_high or stats.severity["HIGH"]:
        return Priority.HIGH
    return Priority.MEDIUM if stats.severity["MEDIUM"] else Priority.LOW


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
