"""Statistics calculation for SBOM analysis (EPSS/KEV and reachability)."""

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, ClassVar, NamedTuple, cast

from app.core.constants import (
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
    FINDINGS_SCAN_TYPE_INDEX,
    HIGH_RISK_SCORE_THRESHOLD,
    sort_by_severity,
)
from app.core.cve import canonical_cve, display_vulnerability_id
from app.core.epss import bucket_epss
from app.core.risk_scoring import (
    ACTIVELY_EXPLOITED_MATURITY,
    RISK_SEVERITY_WEIGHTS,
    calculate_exploit_maturity,
    is_actionable_secret,
    is_actionable_vulnerability,
    is_deprioritized_secret,
    is_deprioritized_vulnerability,
    reachability_display_tier,
    reachability_risk_modifier,
    saturating_risk_score,
    severity_exposure,
)
from app.models.finding import FindingType, Severity
from app.models.stats import (
    PrioritizedCounts,
    ReachabilityStats,
    SecretPrioritizedCounts,
    Stats,
    ThreatIntelligenceStats,
)
from app.schemas.projections import CallgraphMinimal
from app.services.component_identity import lookup_component
from app.services.analysis.types import (
    CallgraphInfo,
    Database,
    EPSSKEVSummary,
    EPSSScoreCounts,
    ExploitMaturityCounts,
    KEVDetail,
    ReachabilityLevelCounts,
    ReachabilitySummary,
    VulnerabilityInfo,
)
from app.services.recommendation.common import live_advisories
from app.services.reachability_enrichment import (
    ComponentLanguages,
    build_component_language_map,
    is_high_confidence_reachable,
)


def _process_finding_epss(details: dict[str, Any], summary: EPSSKEVSummary, epss_scores: list[float]) -> None:
    epss_score = _numeric(details.get("epss_score"))
    if epss_score is None:
        return
    summary["epss_enriched"] += 1
    epss_scores.append(epss_score)
    summary["epss_scores"][bucket_epss(epss_score)] += 1


def _process_finding_kev(finding: dict[str, Any], details: dict[str, Any], summary: EPSSKEVSummary) -> None:
    """Emit one row per known-exploited CVE of a finding."""
    component = finding.get("component", "")
    rows: list[KEVDetail] = [
        {
            "cve": canonical_cve(entry_details) or "",
            "component": component,
            "due_date": entry_details.get("kev_due_date"),
            "ransomware": entry_details.get(DETAILS_KEY_KEV_RANSOMWARE) is True,
        }
        for entry_details in details.get("vulnerabilities") or []
        if entry_details.get(DETAILS_KEY_IN_KEV) is True
    ]
    summary["kev_matches"] += len(rows)
    summary["kev_details"].extend(rows)
    summary["kev_ransomware"] += sum(1 for row in rows if row["ransomware"])


def _process_finding_risk(
    finding: dict[str, Any], details: dict[str, Any], risk_scores: list[float], summary: EPSSKEVSummary
) -> None:
    """Collect the finding's risk score and one high-risk row per advisory scored above the threshold."""
    risk_score = details.get("risk_score")
    if risk_score is not None:
        risk_scores.append(float(risk_score))
    for entry_details in details.get("vulnerabilities") or []:
        entry_risk = entry_details.get("risk_score")
        if entry_risk is None or entry_risk <= HIGH_RISK_SCORE_THRESHOLD:
            continue
        epss = _numeric(entry_details.get("epss_score"))
        in_kev = entry_details.get(DETAILS_KEY_IN_KEV) is True
        ransomware = entry_details.get(DETAILS_KEY_KEV_RANSOMWARE) is True
        summary["high_risk_cves"].append(
            {
                "cve": canonical_cve(entry_details) or "",
                "component": finding.get("component", ""),
                "version": finding.get("version") or "",
                "risk_score": round(entry_risk, 1),
                "epss_score": round(epss, 4) if epss is not None else None,
                "in_kev": in_kev,
                "exploit_maturity": calculate_exploit_maturity(in_kev, ransomware, epss),
            }
        )


# The high-risk list is a UI sample of the highest scores; high_risk_total carries the real count.
_HIGH_RISK_SAMPLE_CAP = 20


def build_epss_kev_summary(findings: list[dict[str, Any]]) -> EPSSKEVSummary:
    """Build a summary of EPSS/KEV enrichment for the raw data view."""
    epss_scores_counts: EPSSScoreCounts = {"high": 0, "medium": 0, "low": 0}

    exploit_maturity_counts: ExploitMaturityCounts = {
        "weaponized": 0,
        "active": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    summary: EPSSKEVSummary = {
        "total_vulnerabilities": len(findings),
        "epss_enriched": 0,
        "kev_matches": 0,
        "kev_ransomware": 0,
        "epss_scores": epss_scores_counts,
        "exploit_maturity": exploit_maturity_counts,
        "avg_epss_score": None,
        "max_epss_score": None,
        "avg_risk_score": None,
        "max_risk_score": None,
        "kev_details": [],
        "high_risk_cves": [],
        "high_risk_total": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    epss_scores: list[float] = []
    risk_scores: list[float] = []

    for finding in findings:
        details = finding.get("details", {})

        _process_finding_epss(details, summary, epss_scores)
        _process_finding_kev(finding, details, summary)

        maturity: str = details.get("exploit_maturity", "unknown")
        exploit_maturity = cast(dict[str, int], summary["exploit_maturity"])
        if maturity in exploit_maturity:
            exploit_maturity[maturity] += 1

        _process_finding_risk(finding, details, risk_scores, summary)

    if epss_scores:
        summary["avg_epss_score"] = round(sum(epss_scores) / len(epss_scores), 4)
        summary["max_epss_score"] = round(max(epss_scores), 4)

    if risk_scores:
        summary["avg_risk_score"] = round(sum(risk_scores) / len(risk_scores), 1)
        summary["max_risk_score"] = round(max(risk_scores), 1)

    summary["high_risk_cves"].sort(key=lambda x: x["risk_score"], reverse=True)
    summary["high_risk_total"] = len(summary["high_risk_cves"])
    summary["high_risk_cves"] = summary["high_risk_cves"][:_HIGH_RISK_SAMPLE_CAP]

    return summary


# The vulnerability lists are UI samples; reachable_total / unreachable_total carry the real counts.
_VULNERABILITY_SAMPLE_CAP = 30


def build_reachability_summary(
    findings: list[dict[str, Any]],
    callgraphs: Sequence[CallgraphMinimal],
) -> ReachabilitySummary:
    """Build a summary of reachability analysis for the raw data view."""
    reachability_levels: ReachabilityLevelCounts = {
        "confirmed": 0,
        "likely": 0,
        "unknown": 0,
        "unreachable": 0,
    }

    callgraph_info: list[CallgraphInfo] = [
        {
            "language": cg.language or "unknown",
            "total_modules": len(cg.module_usage or {}),
            "total_imports": cg.total_imports,
            "coverage_modules": len(cg.analyzed_modules),
            "generated_at": cg.created_at.isoformat() if cg.created_at else None,
        }
        for cg in callgraphs
    ]

    summary: ReachabilitySummary = {
        "total_vulnerabilities": len(findings),
        "analyzed": 0,
        "reachability_levels": reachability_levels,
        "callgraph_info": callgraph_info,
        "languages": [info["language"] for info in callgraph_info],
        "reachable_total": 0,
        "unreachable_total": 0,
        "reachable_vulnerabilities": [],
        "unreachable_vulnerabilities": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    for finding in findings:
        reachability_data = finding.get("details", {}).get("reachability", {})
        reachable = reachability_data.get("is_reachable")
        # Map persisted none/import/symbol level onto the confirmed/likely/unreachable/unknown buckets.
        tier = reachability_display_tier(reachable, reachability_data.get("analysis_level"))

        vuln_info: VulnerabilityInfo = {
            "cve": display_vulnerability_id(finding.get("details")) or "",
            "component": finding.get("component", ""),
            "version": finding.get("version") or "",
            "severity": finding.get("severity", "unknown"),
            "reachability_level": tier,
            "reachable_functions": reachability_data.get("matched_symbols", [])[:5],
            "is_high_confidence": is_high_confidence_reachable(reachable, reachability_data.get("confidence_score")),
        }

        reachability_counts = cast(dict[str, int], summary["reachability_levels"])
        if tier in reachability_counts:
            reachability_counts[tier] += 1

        if reachable is True:
            summary["reachable_vulnerabilities"].append(vuln_info)
        elif reachable is False:
            summary["unreachable_vulnerabilities"].append(vuln_info)

    summary["reachable_total"] = len(summary["reachable_vulnerabilities"])
    summary["unreachable_total"] = len(summary["unreachable_vulnerabilities"])
    summary["analyzed"] = summary["reachable_total"] + summary["unreachable_total"]

    for sample in ("reachable_vulnerabilities", "unreachable_vulnerabilities"):
        summary[sample] = sort_by_severity(summary[sample])[:_VULNERABILITY_SAMPLE_CAP]

    return summary


# Severities with a dedicated bucket; anything else is counted as unknown so buckets always sum to total.
_UNKNOWN_SEVERITY: str = Severity.UNKNOWN.value
_BUCKETED_SEVERITIES: tuple[str, ...] = tuple(s.value for s in Severity if s is not Severity.UNKNOWN)


def _numeric(raw: Any) -> float | None:
    """A real number, or None. bool is rejected despite subclassing int: True would score as a perfect 1.0."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    return float(raw)


def _live_threat_intel(details: Mapping[str, Any]) -> tuple[float | None, bool, bool]:
    """The finding's EPSS, KEV and ransomware marks, taken off its unwaived advisories."""
    live = live_advisories(details)
    epss = max((score for entry in live if (score := _numeric(entry.get("epss_score"))) is not None), default=None)
    in_kev = any(entry.get(DETAILS_KEY_IN_KEV) is True for entry in live)
    return epss, in_kev, any(entry.get(DETAILS_KEY_KEV_RANSOMWARE) is True for entry in live)


class StatsAccumulator:
    """Scan statistics, folded over a stream of findings."""

    # Projection of the stats cursor: add() must read no field outside this set.
    REQUIRED_PATHS: ClassVar[frozenset[str]] = frozenset(
        {
            "waived",
            "severity",
            "type",
            "reachable",
            "reachability_level",
            "component",
            "details.vulnerabilities.waived",
            "details.vulnerabilities.epss_score",
            f"details.vulnerabilities.{DETAILS_KEY_IN_KEV}",
            f"details.vulnerabilities.{DETAILS_KEY_KEV_RANSOMWARE}",
            "details.verified",
            "details.in_current_tree",
            "details.reachability.confidence_score",
        }
    )

    def __init__(self, component_languages: ComponentLanguages) -> None:
        self._component_languages = component_languages
        self._counted = 0
        self.waived_count = 0
        self._severity: dict[str, int] = dict.fromkeys((*_BUCKETED_SEVERITIES, _UNKNOWN_SEVERITY), 0)
        self._adjusted_exposure = 0.0
        self._vuln_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self._vuln_total = 0
        self._actionable_critical = 0
        self._actionable_high = 0
        self._actionable_total = 0
        self._deprioritized = 0
        self._secret_total = 0
        self._secret_verified = 0
        self._secret_in_tree = 0
        self._secret_historical = 0
        self._secret_unknown_tree = 0
        self._secret_actionable = 0
        self._secret_deprioritized = 0
        self._kev = 0
        self._kev_ransomware = 0
        self._high_epss = 0
        self._medium_epss = 0
        self._weaponized = 0
        self._active_exploitation = 0
        self._epss_sum = 0.0
        self._epss_n = 0
        self._epss_max: float | None = None
        self._analyzed = 0
        self._reachable = 0
        self._unreachable = 0
        self._confirmed = 0
        self._likely = 0
        self._reachable_critical = 0
        self._reachable_high = 0
        self._reachable_hc = 0
        self._reachable_critical_hc = 0
        self._reachable_high_hc = 0
        self._coverable = 0

    def add(self, finding: Mapping[str, Any]) -> None:
        if finding.get("waived") is True:
            self.waived_count += 1
            return
        # A scanner error is missing coverage, recorded in failed_analyzers, not a security finding.
        if finding.get("type") == FindingType.SYSTEM_WARNING:
            return
        self._counted += 1

        severity = finding.get("severity")
        bucket = severity if severity in _BUCKETED_SEVERITIES else _UNKNOWN_SEVERITY
        self._severity[bucket] += 1

        raw_details = finding.get("details")
        details: Mapping[str, Any] = raw_details if isinstance(raw_details, Mapping) else {}
        reachable = finding.get("reachable")
        level = finding.get("reachability_level")
        epss, in_kev, kev_ransomware = _live_threat_intel(details)

        # Weights are keyed on bucket, not on raw severity: a new RISK_SEVERITY_WEIGHTS key that is
        # not also in _BUCKETED_SEVERITIES collapses to UNKNOWN and silently contributes 0.
        self._adjusted_exposure += RISK_SEVERITY_WEIGHTS.get(bucket, 0.0) * reachability_risk_modifier(reachable, level)

        finding_type = finding.get("type")
        if finding_type == "vulnerability":
            self._add_vulnerability(bucket, epss, in_kev, reachable, finding.get("component"))
            self._add_reachability(bucket, reachable, level, details)
        elif finding_type == "secret":
            self._add_secret(details)
        self._add_threat_intel(epss, in_kev, kev_ransomware)

    def _add_vulnerability(self, bucket: str, epss: float | None, in_kev: bool, reachable: Any, component: Any) -> None:
        self._vuln_total += 1
        if bucket in self._vuln_severity:
            self._vuln_severity[bucket] += 1
        if is_actionable_vulnerability(epss_score=epss, is_kev=in_kev, reachable=reachable):
            self._actionable_total += 1
            if bucket == "CRITICAL":
                self._actionable_critical += 1
            elif bucket == "HIGH":
                self._actionable_high += 1
        if is_deprioritized_vulnerability(epss_score=epss, is_kev=in_kev, reachable=reachable):
            self._deprioritized += 1
        candidates = self._component_languages and component and lookup_component(self._component_languages, component)
        if candidates and any(langs for _, langs, _ in candidates):
            self._coverable += 1

    def _add_secret(self, details: Mapping[str, Any]) -> None:
        verified = details.get("verified")
        in_current_tree = details.get("in_current_tree")
        self._secret_total += 1
        if verified is True:
            self._secret_verified += 1
        if in_current_tree is True:
            self._secret_in_tree += 1
        elif in_current_tree is False:
            self._secret_historical += 1
        elif in_current_tree is None:
            self._secret_unknown_tree += 1
        if is_actionable_secret(verified):
            self._secret_actionable += 1
        if is_deprioritized_secret(verified, in_current_tree):
            self._secret_deprioritized += 1

    def _add_threat_intel(self, epss: float | None, in_kev: bool, kev_ransomware: bool) -> None:
        if in_kev:
            self._kev += 1
        if kev_ransomware:
            self._kev_ransomware += 1
        if epss is not None:
            self._epss_sum += epss
            self._epss_n += 1
            self._epss_max = epss if self._epss_max is None else max(self._epss_max, epss)
            tier = bucket_epss(epss)
            self._high_epss += tier == "high"
            self._medium_epss += tier == "medium"
        maturity = calculate_exploit_maturity(in_kev, kev_ransomware, epss)
        self._weaponized += maturity == "weaponized"
        self._active_exploitation += maturity in ACTIVELY_EXPLOITED_MATURITY

    def _add_reachability(self, bucket: str, reachable: Any, level: Any, details: Mapping[str, Any]) -> None:
        if reachable is not None:
            self._analyzed += 1
        if reachable is True:
            self._add_reachable(bucket, level, details)
        elif reachable is False:
            self._unreachable += 1

    def _add_reachable(self, bucket: str, level: Any, details: Mapping[str, Any]) -> None:
        self._reachable += 1
        tier = reachability_display_tier(True, level)
        self._confirmed += tier == "confirmed"
        self._likely += tier == "likely"
        if bucket == "CRITICAL":
            self._reachable_critical += 1
        elif bucket == "HIGH":
            self._reachable_high += 1
        raw_reach = details.get("reachability")
        confidence = raw_reach.get("confidence_score") if isinstance(raw_reach, Mapping) else None
        if is_high_confidence_reachable(True, confidence):
            self._reachable_hc += 1
            if bucket == "CRITICAL":
                self._reachable_critical_hc += 1
            elif bucket == "HIGH":
                self._reachable_high_hc += 1

    def result(self) -> Stats:
        # The four sub-models stay None on an empty or fully waived scan: the frontend's
        # threat-intelligence view distinguishes no-data from all-zero.
        if self._counted == 0:
            return Stats()

        critical = self._severity["CRITICAL"]
        high = self._severity["HIGH"]
        medium = self._severity["MEDIUM"]
        low = self._severity["LOW"]
        return Stats(
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            negligible=self._severity["NEGLIGIBLE"],
            info=self._severity["INFO"],
            unknown=self._severity[_UNKNOWN_SEVERITY],
            risk_score=saturating_risk_score(severity_exposure(critical, high, medium, low)),
            adjusted_risk_score=saturating_risk_score(self._adjusted_exposure),
            threat_intel=ThreatIntelligenceStats(
                kev_count=self._kev,
                kev_ransomware_count=self._kev_ransomware,
                high_epss_count=self._high_epss,
                medium_epss_count=self._medium_epss,
                avg_epss_score=round(self._epss_sum / self._epss_n, 4) if self._epss_n else None,
                max_epss_score=round(self._epss_max, 4) if self._epss_max is not None else None,
                weaponized_count=self._weaponized,
                active_exploitation_count=self._active_exploitation,
            ),
            prioritized=PrioritizedCounts(
                total=self._vuln_total,
                critical=self._vuln_severity["CRITICAL"],
                high=self._vuln_severity["HIGH"],
                medium=self._vuln_severity["MEDIUM"],
                low=self._vuln_severity["LOW"],
                actionable_critical=self._actionable_critical,
                actionable_high=self._actionable_high,
                actionable_total=self._actionable_total,
                deprioritized_count=self._deprioritized,
            ),
            secret_priority=SecretPrioritizedCounts(
                total=self._secret_total,
                verified_count=self._secret_verified,
                in_current_tree_count=self._secret_in_tree,
                historical_only_count=self._secret_historical,
                unknown_tree_count=self._secret_unknown_tree,
                actionable_count=self._secret_actionable,
                deprioritized_count=self._secret_deprioritized,
            ),
            reachability=ReachabilityStats(
                analyzed_count=self._analyzed,
                coverable_count=self._coverable,
                reachable_count=self._reachable,
                confirmed_reachable_count=self._confirmed,
                likely_reachable_count=self._likely,
                unreachable_count=self._unreachable,
                unknown_count=self._vuln_total - self._analyzed,
                reachable_critical=self._reachable_critical,
                reachable_high=self._reachable_high,
                reachable_count_high_confidence=self._reachable_hc,
                reachable_critical_high_confidence=self._reachable_critical_hc,
                reachable_high_high_confidence=self._reachable_high_hc,
            ),
        )


def compute_stats(
    findings: Iterable[Mapping[str, Any]],
    component_languages: ComponentLanguages,
) -> Stats:
    acc = StatsAccumulator(component_languages)
    for finding in findings:
        acc.add(finding)
    return acc.result()


def _stats_projection() -> dict[str, int]:
    """Derived from REQUIRED_PATHS, never hand-maintained: a forgotten path zeroes a counter forever."""
    projection: dict[str, int] = {"_id": 0}
    for path in sorted(StatsAccumulator.REQUIRED_PATHS):
        projection[path] = 1
    return projection


# scan_id + type is the only index pair immutable after insert; severity and waived are rewritten by
# the waiver restamp, so hinting either opens a skip window mid-cursor.
_STATS_CURSOR_HINT = FINDINGS_SCAN_TYPE_INDEX


class ScanTally(NamedTuple):
    stats: Stats
    ignored_count: int


async def calculate_comprehensive_stats(
    db: Database, scan_id: str, component_languages: ComponentLanguages | None = None
) -> ScanTally:
    """A scan's statistics and waived count from one cursor; pass ``component_languages`` when the run built it."""
    if component_languages is None:
        component_languages = await build_component_language_map(db, scan_id)
    acc = StatsAccumulator(component_languages)
    cursor = db.findings.find({"scan_id": scan_id}, _stats_projection(), hint=_STATS_CURSOR_HINT)
    try:
        async for doc in cursor:
            acc.add(doc)
    finally:
        await cursor.close()
    return ScanTally(acc.result(), acc.waived_count)
