from collections import Counter
from collections.abc import Callable, Iterable, Sequence
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
    max_severity,
)
from app.core.cve import canonical_cves, counted_cves
from app.core.epss import bucket_epss
from app.core.risk_scoring import is_actionable_vulnerability
from app.schemas.recommendation import Priority, Recommendation
from app.services.aggregation.versions import aggregate_fixed_version, newest_first, split_fixed_versions

ModelOrDict = BaseModel | dict[str, Any]


@dataclass
class VulnerabilityInfo:
    # The finding's unwaived advisories; every per-CVE mark and name is read off them.
    advisories: list[dict[str, Any]]
    severity: str
    package_name: str
    current_version: str
    fixed_version: str | None
    epss_score: float | None = None
    is_kev: bool = False
    kev_ransomware: bool = False
    is_reachable: bool | None = None
    risk_score: float | None = None
    # The SBOM graph does not record the dependency; the parser guessed it is direct.
    direct_inferred: bool = False


# Components one recommendation lists; drawn via sample_components/sampled so each list carries its population.
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


_IMPACT_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_PRIORITY_BY_WORST = (("critical", Priority.CRITICAL), ("high", Priority.HIGH), ("medium", Priority.MEDIUM))
# A group with no critical or high finding earns a card only from this many findings on.
MIN_FINDINGS_FOR_CARD = 3


def severity_impact(severities: Iterable[str | None]) -> dict[str, int]:
    """The impact block calculate_score reads; severities outside the four scored ones count only in total."""
    counts = Counter(severities)
    return {severity.lower(): counts[severity] for severity in _IMPACT_SEVERITIES} | {"total": counts.total()}


def priority_for(impact: dict[str, int]) -> Priority:
    return next((priority for key, priority in _PRIORITY_BY_WORST if impact[key]), Priority.LOW)


def worth_a_card(impact: dict[str, int]) -> bool:
    return impact["critical"] + impact["high"] > 0 or impact["total"] >= MIN_FINDINGS_FOR_CARD


def label_by_keywords(raw: str, table: Sequence[tuple[tuple[str, ...], str]]) -> str:
    """The label of the first row with a keyword inside `raw`; `raw` itself when no row matches."""
    lowered = raw.lower()
    return next((label for keywords, label in table if any(keyword in lowered for keyword in keywords)), raw)


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
    return obj.get(key, default)


def dependency_label(dep: ModelOrDict) -> str:
    return f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"


MALWARE_REMEDIATION_STEPS = (
    "Immediately remove the malicious package(s)",
    "Check if npm install/pip install scripts ran malicious code",
    "Rotate any credentials that may have been exposed",
    "Audit your systems for signs of compromise",
    "Report to your security team and follow your incident response procedures",
)


def malware_kind(finding: ModelOrDict) -> str:
    """Typosquat heuristics and failed hash checks are stored as MALWARE findings beside confirmed malware."""
    details = get_attr(finding, "details", {})
    if details.get("imitated_package"):
        return "typosquat"
    return "hash_mismatch" if details.get("verification_failed") else "malware"


def scorecard_score(details: dict[str, Any]) -> float | None:
    """A quality finding's OpenSSF Scorecard score; None when it carries maintainer risk only."""
    score = details.get("overall_score")
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


def cve_severities(advisories: Iterable[dict[str, Any]]) -> dict[str, str | None]:
    """Each CVE the advisories name, at the worst severity any of them gives it."""
    worst: dict[str, str | None] = {}
    for advisory in advisories:
        for cve in counted_cves(advisory):
            worst[cve] = max_severity(worst.get(cve), advisory.get("severity"))
    return worst


# Versions named per package inside an action block; version_count carries the population.
ACTION_VERSION_SAMPLE = 5


def calculate_best_fix_version(versions: list[str]) -> str:
    """The highest single version among stored fixed_version values."""
    parts = [part for v in versions for part in split_fixed_versions(v)]
    return newest_first(parts)[0] if parts else "unknown"


def vuln_info(f: ModelOrDict) -> VulnerabilityInfo:
    """A vulnerability finding in the shape every per-package roll-up counts, marked by its worst live advisory."""
    details = get_attr(f, "details", {})
    advisories = live_advisories(details)
    epss = [a["epss_score"] for a in advisories if a.get("epss_score") is not None]
    risk = [a["risk_score"] for a in advisories if a.get("risk_score") is not None]

    return VulnerabilityInfo(
        advisories=advisories,
        severity=get_attr(f, "severity", "UNKNOWN"),
        package_name=get_attr(f, "component", ""),
        current_version=get_attr(f, "version") or "",
        fixed_version=live_fixed_version(f),
        epss_score=max(epss, default=None),
        is_kev=any(a.get(DETAILS_KEY_IN_KEV) for a in advisories),
        kev_ransomware=any(a.get(DETAILS_KEY_KEV_RANSOMWARE) for a in advisories),
        is_reachable=(details.get("reachability") or {}).get("is_reachable"),
        risk_score=max(risk, default=None),
    )


def names_fix(advisory: dict[str, Any]) -> bool:
    return bool(advisory.get("fixed_version"))


@dataclass(frozen=True)
class VulnStats:
    """What the CVEs of a set of vulnerability findings add up to; every per-package card reads it."""

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
    # Installed versions and distinct fixes, newest first.
    versions: list[str]
    fixed_versions: list[str]
    best_fix: str

    def impact(self) -> dict[str, Any]:
        return {
            **severity_impact(self.severity.elements()),
            "kev_count": self.kev,
            "kev_ransomware_count": self.kev_ransomware,
            "high_epss_count": self.high_epss,
            "medium_epss_count": self.medium_epss,
            "reachable_count": self.reachable,
            "unreachable_count": self.unreachable,
            "reachable_critical": self.reachable_critical,
            "reachable_high": self.reachable_high,
            "actionable_count": self.actionable,
        }


# A CVE on several installed versions is as reachable as its most reachable copy.
_REACHABILITY_RANK = {False: 0, None: 1, True: 2}


def summarize_vulns(
    vulns: list[VulnerabilityInfo], counted: Callable[[dict[str, Any]], bool] = lambda _: True
) -> VulnStats:
    """One row per CVE of the advisories ``counted`` picks, merged across installed versions; each row takes its
    finding's reachability."""
    severity: dict[str, str] = {}
    reachability: dict[str, bool | None] = {}
    epss: dict[str, float] = {}
    kev: set[str] = set()
    ransomware: set[str] = set()
    for v in vulns:
        for advisory in filter(counted, v.advisories):
            cves = counted_cves(advisory)
            for cve in cves:
                severity[cve] = max_severity(severity.get(cve, "UNKNOWN"), advisory.get("severity") or "UNKNOWN")
                reachability[cve] = max(
                    reachability.get(cve, False), v.is_reachable, key=_REACHABILITY_RANK.__getitem__
                )
            if not cves:
                continue
            # A bundled advisory's marks hold for any one of its CVEs, so they count once.
            if advisory.get(DETAILS_KEY_IN_KEV):
                kev.add(cves[0])
            if advisory.get(DETAILS_KEY_KEV_RANSOMWARE):
                ransomware.add(cves[0])
            if (score := advisory.get("epss_score")) is not None:
                epss[cves[0]] = max(score, epss.get(cves[0], 0.0))
    reachable = [cve for cve, r in reachability.items() if r is True]
    unreachable = [cve for cve, r in reachability.items() if r is False]
    epss_buckets = Counter(bucket_epss(score) for score in epss.values())
    fixes = [v.fixed_version for v in vulns if v.fixed_version]
    return VulnStats(
        total=len(severity),
        severity=Counter(severity.values()),
        cves=list(severity),
        kev=len(kev),
        kev_ransomware=len(ransomware),
        high_epss=epss_buckets["high"],
        medium_epss=epss_buckets["medium"],
        reachable=len(reachable),
        unreachable=len(unreachable),
        reachable_critical=sum(severity[cve] == "CRITICAL" for cve in reachable),
        reachable_high=sum(severity[cve] == "HIGH" for cve in reachable),
        unreachable_critical=sum(severity[cve] == "CRITICAL" for cve in unreachable),
        actionable=sum(
            is_actionable_vulnerability(epss_score=epss.get(cve), is_kev=cve in kev, reachable=reachability[cve])
            for cve in severity
        ),
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


_W, _R = RECOMMENDATION_SCORING_WEIGHTS, REACHABILITY_SCORING_WEIGHTS
_PRIORITY_SCORES = {
    Priority.CRITICAL: _W["priority_critical"],
    Priority.HIGH: _W["priority_high"],
    Priority.MEDIUM: _W["priority_medium"],
    Priority.LOW: _W["priority_low"],
}
_IMPACT_WEIGHTS = (
    ("critical", _W["impact_critical"]),
    ("high", _W["impact_high"]),
    ("medium", _W["impact_medium"]),
    ("low", _W["impact_low"]),
    ("kev_count", _W["kev_bonus"]),
    ("kev_ransomware_count", _W["kev_ransomware_bonus"]),
    ("high_epss_count", _W["high_epss_bonus"]),
    ("medium_epss_count", _W["medium_epss_bonus"]),
    ("reachable_critical", _R["critical_bonus"]),
    ("reachable_high", _R["high_bonus"]),
    ("actionable_count", ACTIONABLE_VULN_BONUS),
)


def _reachability_modifier(impact: dict[str, Any]) -> float:
    total = impact.get("total", 1)
    unreachable_ratio = impact.get("unreachable_count", 0) / total if total > 0 else 0.0
    if unreachable_ratio > REACHABILITY_MODIFIERS["high_unreachable_ratio_threshold"]:
        return REACHABILITY_MODIFIERS["high_unreachable_penalty"]
    if unreachable_ratio > REACHABILITY_MODIFIERS["medium_unreachable_ratio_threshold"]:
        return REACHABILITY_MODIFIERS["medium_unreachable_penalty"]
    return 1.0


def calculate_score(rec: Recommendation) -> int:
    """Score a recommendation for sorting; mostly-unreachable findings get a multiplicative penalty."""
    impact = rec.impact
    reachable_other = (
        impact.get("reachable_count", 0) - impact.get("reachable_critical", 0) - impact.get("reachable_high", 0)
    )
    score = (
        _PRIORITY_SCORES[rec.priority]
        + sum(impact.get(key, 0) * weight for key, weight in _IMPACT_WEIGHTS)
        + reachable_other * _R["other_bonus"]
        + EFFORT_BONUSES[rec.effort]
        + RECOMMENDATION_TYPE_BONUSES[rec.type]
    )
    return int(score * _reachability_modifier(impact))


_PRIORITY_RANK = {Priority.CRITICAL: 3, Priority.HIGH: 2, Priority.MEDIUM: 1, Priority.LOW: 0}


def sort_key(rec: Recommendation) -> tuple[int, int]:
    """Order recommendations by priority tier first, then by score. Priority must dominate so a
    high-volume medium item (e.g. "445 recurring vulns") never outranks a critical KEV/exploit fix;
    calculate_score alone let raw counts overwhelm the priority base."""
    return (_PRIORITY_RANK.get(rec.priority, 0), calculate_score(rec))
