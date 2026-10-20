from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
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
from app.schemas.enrichment import VulnerabilityEnrichment
from app.schemas.recommendation import Effort, Priority, Recommendation, RecommendationType
from app.services.aggregation.versions import (
    aggregate_fixed_version,
    newest_first,
    normalize_version,
    split_fixed_versions,
)
from app.services.component_identity import build_component_index, lookup_component

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


# Components one recommendation lists; drawn via recommend/sampled so each list carries its population.
AFFECTED_COMPONENTS_SHOWN = 20


def name_some(values: Sequence[str], shown: int) -> str:
    head = ", ".join(values[:shown])
    remaining = len(values) - shown
    return f"{head} and {remaining} more" if remaining > 0 else head


def sampled(name: str, values: Sequence[Any], cap: int) -> dict[str, Any]:
    """Evidence in an action block reads as everything a card found unless <name>_total gives the population."""
    return {name: list(values[:cap]), f"{name}_total": len(values)}


def recommend(
    *,
    rec_type: RecommendationType,
    priority: Priority,
    title: str,
    description: str,
    impact: dict[str, Any],
    components: Iterable[str],
    action: dict[str, Any],
    effort: Effort,
    rank: int = 0,
    ranked_out_of: int = 0,
) -> Recommendation:
    """Keeps the order of components: pass a sorted sequence where the source is a set."""
    unique = list(dict.fromkeys(c for c in components if c))
    return Recommendation(
        type=rec_type,
        priority=priority,
        title=title,
        description=description,
        impact=impact,
        affected_components=unique[:AFFECTED_COMPONENTS_SHOWN],
        affected_components_total=len(unique),
        action=action,
        effort=effort,
        rank=rank,
        ranked_out_of=ranked_out_of,
    )


_IMPACT_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_PRIORITY_BY_WORST = (("critical", Priority.CRITICAL), ("high", Priority.HIGH), ("medium", Priority.MEDIUM))
# A group with no critical or high finding earns a card only from this many findings on.
MIN_FINDINGS_FOR_CARD = 3


def severity_impact(severities: Iterable[str | None]) -> dict[str, int]:
    counts = Counter(severities)
    return {severity.lower(): counts[severity] for severity in _IMPACT_SEVERITIES} | {"total": counts.total()}


def priority_for(impact: dict[str, int]) -> Priority:
    return next((priority for key, priority in _PRIORITY_BY_WORST if impact[key]), Priority.LOW)


def worth_a_card(impact: dict[str, int]) -> bool:
    return impact["critical"] + impact["high"] > 0 or impact["total"] >= MIN_FINDINGS_FOR_CARD


def label_by_keywords(raw: str, table: Sequence[tuple[tuple[str, ...], str]]) -> str:
    lowered = raw.lower()
    return next((label for keywords, label in table if any(keyword in lowered for keyword in keywords)), raw)


def take_top(candidates: Sequence[Any], cap: int) -> list[tuple[int, Any, int]]:
    """Rank and population stay 0 unless the cap cut, so a reader learns more were ranked only when they were."""
    cut = len(candidates) > cap
    population = len(candidates) if cut else 0
    return [(rank if cut else 0, candidate, population) for rank, candidate in enumerate(candidates[:cap], start=1)]


def get_attr(obj: ModelOrDict, key: str, default: Any = None) -> Any:
    if isinstance(obj, BaseModel):
        return getattr(obj, key, default)
    return obj.get(key, default)


def package_label(package: dict[str, Any]) -> str:
    return f"{package['name']} ({package['type']})" if package["type"] else package["name"]


def dependency_label(dep: ModelOrDict) -> str:
    return f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"


def installed_copy_lookup(rows: Iterable[ModelOrDict], name_field: str) -> Callable[[ModelOrDict], Any]:
    by_version: dict[str, dict[str, ModelOrDict]] = defaultdict(dict)
    for row in rows:
        by_version[normalize_version(get_attr(row, "version"))][get_attr(row, name_field)] = row
    indexes = {version: build_component_index(named) for version, named in by_version.items()}
    return lambda finding: lookup_component(
        indexes.get(normalize_version(get_attr(finding, "version")), {}), get_attr(finding, "component") or ""
    )


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
    score = details.get("overall_score")
    return None if score is None else float(score)


def scorecard_details(details: Any) -> dict[str, Any]:
    """In the aggregated shape the per-issue scorecard fields live at details.quality_issues[].details."""
    if not isinstance(details, dict):
        return {}
    for issue in details.get("quality_issues") or []:
        if isinstance(issue, dict) and issue.get("type") == "scorecard":
            nested = issue.get("details")
            if isinstance(nested, dict):
                return nested
    return {}


def live_advisories(details: Any) -> list[dict[str, Any]]:
    if not isinstance(details, dict):
        return []
    return [a for a in details.get("vulnerabilities") or [] if isinstance(a, dict) and not a.get("waived")]


def live_fixed_version(finding: ModelOrDict) -> str | None:
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
    return canonical_cves([{"vulnerabilities": live_advisories(details)} for details in details_list])


def display_vulnerability_id(details: Any) -> str | None:
    ids = live_cves([details]) or canonical_cves([details])
    return next((i for i in ids if i.startswith("CVE-")), next(iter(ids), None))


def cve_signals(
    advisories: Iterable[dict[str, Any]], threat_intel: Mapping[str, VulnerabilityEnrichment]
) -> Iterator[tuple[str, bool, bool, float]]:
    """(cve, in_kev, ransomware_use, epss_score) per CVE of each advisory."""
    for advisory in advisories:
        cves = counted_cves(advisory)
        for cve in cves:
            # A bundle's stored marks are any one CVE's; a single CVE keeps its own, which a KEV outage cannot clear.
            live = threat_intel.get(cve) if len(cves) > 1 else None
            if live is not None:
                yield cve, live.is_kev, live.kev_ransomware_use, live.epss_score or 0.0
            else:
                in_kev, ransomware = advisory.get(DETAILS_KEY_IN_KEV), advisory.get(DETAILS_KEY_KEV_RANSOMWARE)
                yield cve, bool(in_kev), bool(ransomware), advisory.get("epss_score") or 0.0


def cve_severities(advisories: Iterable[dict[str, Any]]) -> dict[str, str | None]:
    worst: dict[str, str | None] = {}
    for advisory in advisories:
        for cve in counted_cves(advisory):
            worst[cve] = max_severity(worst.get(cve), advisory.get("severity"))
    return worst


# Versions named per package inside an action block; version_count carries the population.
ACTION_VERSION_SAMPLE = 5


def vuln_info(f: ModelOrDict) -> VulnerabilityInfo:
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
    fixed_versions = newest_first({part for fix in fixes for part in split_fixed_versions(fix)})
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
        fixed_versions=fixed_versions,
        best_fix=fixed_versions[0] if fixed_versions else "unknown",
    )


def vuln_priority(stats: VulnStats) -> Priority:
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
    """Priority must dominate so a high-volume medium item never outranks a critical KEV/exploit fix."""
    return (_PRIORITY_RANK.get(rec.priority, 0), calculate_score(rec))
