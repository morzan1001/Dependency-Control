"""Statistics calculation for SBOM analysis (EPSS/KEV and reachability)."""

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any, ClassVar, cast

from pymongo import ASCENDING, ReadPreference

from app.core.constants import (
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
    EPSS_ACTIVE_EXPLOITATION_THRESHOLD,
    EPSS_HIGH_THRESHOLD,
    EPSS_MEDIUM_THRESHOLD,
    EPSS_VERY_HIGH_THRESHOLD,
    HIGH_RISK_SCORE_THRESHOLD,
    REACHABILITY_HIGH_CONFIDENCE_THRESHOLD,
    REACHABILITY_LEVEL_IMPORT,
    REACHABILITY_LEVEL_SYMBOL,
    sort_by_severity,
)
from app.core.epss import bucket_epss
from app.core.risk_scoring import (
    CONFIRMED_REACHABLE_RISK_MODIFIER,
    RISK_SEVERITY_WEIGHTS,
    UNREACHABLE_RISK_MODIFIER,
    is_actionable_vulnerability,
    is_deprioritized_secret,
    is_deprioritized_vulnerability,
    saturating_risk_score,
    severity_exposure,
)
from app.services.aggregation.components import lookup_component
from app.models.stats import (
    PrioritizedCounts,
    ReachabilityStats,
    SecretPrioritizedCounts,
    Stats,
    ThreatIntelligenceStats,
)
from app.services.analysis.types import (
    CallgraphInfo,
    Database,
    EPSSKEVSummary,
    EPSSScoreCounts,
    ExploitMaturityCounts,
    HighRiskCVE,
    KEVDetail,
    ReachabilityLevelCounts,
    ReachabilitySummary,
    VulnerabilityInfo,
)
from app.services.reachability_enrichment import (
    build_component_language_map,
    is_high_confidence_reachable,
    reachability_display_tier,
)


def _format_datetime(value: Any | None) -> str | None:
    """Safely format a datetime value to ISO string."""
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return cast(str, value.isoformat())
    if isinstance(value, str):
        return value if value else None
    return str(value)


def _process_finding_epss(details: dict[str, Any], summary: EPSSKEVSummary, epss_scores: list[float]) -> float | None:
    """Process EPSS data for a single finding. Returns the epss_score if present and numeric."""
    epss_score = _numeric(details.get("epss_score"))
    if epss_score is None:
        return None
    summary["epss_enriched"] += 1
    epss_scores.append(epss_score)
    summary["epss_scores"][bucket_epss(epss_score)] += 1
    return epss_score


def vulnerability_entry_cve(entry: dict[str, Any]) -> str | None:
    """CVE id of one ``details.vulnerabilities`` entry, or None when it carries no CVE."""
    for candidate in (entry.get("id"), entry.get("resolved_cve"), *(entry.get("aliases") or [])):
        if isinstance(candidate, str) and candidate.startswith("CVE-"):
            return candidate
    return None


def finding_vulnerability_id(finding: dict[str, Any]) -> str:
    """An identifier a user can look up: a CVE where one exists, else a scanner id.

    ``finding_id`` is ``component:version`` on aggregated vulnerability documents, so it must
    never reach a field labelled "CVE".
    """
    entries = [e for e in (finding.get("details") or {}).get("vulnerabilities") or [] if isinstance(e, dict)]
    for entry in entries:
        cve = vulnerability_entry_cve(entry)
        if cve:
            return cve
    for alias in finding.get("aliases") or []:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    for entry in entries:
        if entry.get("id"):
            return str(entry["id"])
    return str(finding.get("finding_id") or finding.get("id") or "")


def _process_finding_kev(finding: dict[str, Any], details: dict[str, Any], summary: EPSSKEVSummary) -> None:
    """Emit one row per known-exploited CVE of a finding."""
    if not details.get("in_kev"):
        return
    component = finding.get("component", "")
    rows: list[KEVDetail] = [
        {
            "cve": vulnerability_entry_cve(entry) or str(entry.get("id") or ""),
            "component": component,
            "due_date": entry.get("kev_due_date"),
            "ransomware": bool(entry.get("kev_ransomware_use")),
        }
        for entry in (details.get("vulnerabilities") or [])
        if isinstance(entry, dict) and entry.get("in_kev")
    ]
    if not rows:
        # The KEV CVE can come from the finding's own aliases, which match no nested entry.
        rows = [
            {
                "cve": finding_vulnerability_id(finding),
                "component": component,
                "due_date": details.get("kev_due_date"),
                "ransomware": bool(details.get("kev_ransomware_use")),
            }
        ]
    summary["kev_matches"] += len(rows)
    summary["kev_details"].extend(rows)
    summary["kev_ransomware"] += sum(1 for row in rows if row["ransomware"])


def _process_finding_risk(
    finding: dict[str, Any],
    details: dict[str, Any],
    epss_score: float | None,
    maturity: str,
    risk_scores: list[float],
    summary: EPSSKEVSummary,
) -> None:
    """Process risk score data for a single finding."""
    risk_score = details.get("risk_score")
    if risk_score is None:
        return
    risk_scores.append(float(risk_score))
    if risk_score > HIGH_RISK_SCORE_THRESHOLD:
        high_risk_cve: HighRiskCVE = {
            "cve": finding_vulnerability_id(finding),
            "component": finding.get("component", ""),
            "version": finding.get("version") or "",
            "risk_score": round(risk_score, 1),
            "epss_score": round(epss_score, 4) if epss_score is not None else None,
            "in_kev": details.get("in_kev", False),
            "exploit_maturity": maturity,
        }
        summary["high_risk_cves"].append(high_risk_cve)


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

        epss_score = _process_finding_epss(details, summary, epss_scores)
        _process_finding_kev(finding, details, summary)

        # Exploit maturity
        maturity: str = details.get("exploit_maturity", "unknown")
        exploit_maturity = cast(dict[str, int], summary["exploit_maturity"])
        if maturity in exploit_maturity:
            exploit_maturity[maturity] += 1

        _process_finding_risk(finding, details, epss_score, maturity, risk_scores, summary)

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
    callgraphs: list[dict[str, Any]],
    enriched_count: int,
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
            "language": cg.get("language", "unknown"),
            "total_modules": len(cg.get("module_usage") or {}),
            "total_imports": cg.get("total_imports", 0),
            "coverage_modules": len(cg.get("analyzed_modules") or []),
            "generated_at": _format_datetime(cg.get("created_at")),
        }
        for cg in callgraphs
    ]

    summary: ReachabilitySummary = {
        "total_vulnerabilities": len(findings),
        "analyzed": enriched_count,
        "reachability_levels": reachability_levels,
        "callgraph_info": callgraph_info,
        "languages": [cg.get("language", "unknown") for cg in callgraphs],
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
            "cve": finding_vulnerability_id(finding),
            "component": finding.get("component", ""),
            "version": finding.get("version") or "",
            "severity": finding.get("severity", "unknown"),
            "reachability_level": tier,
            "reachable_functions": reachability_data.get("matched_symbols", [])[:5],
            "is_high_confidence": is_high_confidence_reachable(reachability_data),
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

    summary["reachable_vulnerabilities"] = sort_by_severity(
        summary["reachable_vulnerabilities"], key="severity", reverse=True
    )[:_VULNERABILITY_SAMPLE_CAP]
    summary["unreachable_vulnerabilities"] = sort_by_severity(
        summary["unreachable_vulnerabilities"], key="severity", reverse=True
    )[:_VULNERABILITY_SAMPLE_CAP]

    return summary


# Severities with a dedicated bucket; anything else is counted as unknown so buckets always sum to total.
_BUCKETED_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "INFO")

_UNKNOWN_SEVERITY = "UNKNOWN"


def _numeric(raw: Any) -> float | None:
    """A real number, or None. bool is rejected despite subclassing int: True would score as a perfect 1.0."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    return float(raw)


def _reach_modifier(reachable: Any, level: Any) -> float:
    """Per-finding weight multiplier. Unreachable is tested first, so it wins over confirmed-reachable."""
    if reachable is False:
        return UNREACHABLE_RISK_MODIFIER
    if reachable is True and level == REACHABILITY_LEVEL_SYMBOL:
        return CONFIRMED_REACHABLE_RISK_MODIFIER
    return 1.0


class StatsAccumulator:
    """Scan statistics, folded over a stream of findings."""

    # Contract: these finding fields are available to downstream counter groups.
    # As each group is added, it registers the paths it will read.
    REQUIRED_PATHS: ClassVar[frozenset[str]] = frozenset(
        {
            "waived",
            "severity",
            "type",
            "reachable",
            "reachability_level",
            "component",
            "details.epss_score",
            f"details.{DETAILS_KEY_IN_KEV}",
            f"details.{DETAILS_KEY_KEV_RANSOMWARE}",
            "details.verified",
            "details.in_current_tree",
            "details.reachability.confidence_score",
        }
    )

    def __init__(self, component_languages: Mapping[str, frozenset[str]]) -> None:
        self._component_languages = component_languages
        self._counted = 0
        self._severity: dict[str, int] = {sev: 0 for sev in (*_BUCKETED_SEVERITIES, _UNKNOWN_SEVERITY)}
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
            return
        self._counted += 1

        severity = finding.get("severity")
        bucket = severity if severity in _BUCKETED_SEVERITIES else _UNKNOWN_SEVERITY
        self._severity[bucket] += 1

        raw_details = finding.get("details")
        details: Mapping[str, Any] = raw_details if isinstance(raw_details, Mapping) else {}
        reachable = finding.get("reachable")
        level = finding.get("reachability_level")
        epss = _numeric(details.get("epss_score"))
        in_kev = details.get(DETAILS_KEY_IN_KEV) is True

        # Weights are keyed on bucket, not on raw severity: a new RISK_SEVERITY_WEIGHTS key that is
        # not also in _BUCKETED_SEVERITIES collapses to UNKNOWN and silently contributes 0.
        self._adjusted_exposure += RISK_SEVERITY_WEIGHTS.get(bucket, 0.0) * _reach_modifier(reachable, level)

        if finding.get("type") == "vulnerability":
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
            component = finding.get("component")
            if self._component_languages and component and lookup_component(self._component_languages, component):
                self._coverable += 1

        if finding.get("type") == "secret":
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
            if verified is True and in_current_tree is True:
                self._secret_actionable += 1
            if is_deprioritized_secret(verified, in_current_tree):
                self._secret_deprioritized += 1

        kev_ransomware = details.get(DETAILS_KEY_KEV_RANSOMWARE) is True
        if in_kev:
            self._kev += 1
        if kev_ransomware:
            self._kev_ransomware += 1
        if epss is not None:
            self._epss_sum += epss
            self._epss_n += 1
            self._epss_max = epss if self._epss_max is None else max(self._epss_max, epss)
            if epss >= EPSS_HIGH_THRESHOLD:
                self._high_epss += 1
            elif epss >= EPSS_MEDIUM_THRESHOLD:
                self._medium_epss += 1
        if kev_ransomware or (in_kev and epss is not None and epss >= EPSS_VERY_HIGH_THRESHOLD):
            self._weaponized += 1
        if in_kev or (epss is not None and epss >= EPSS_ACTIVE_EXPLOITATION_THRESHOLD):
            self._active_exploitation += 1

        if reachable is not None:
            self._analyzed += 1
        if reachable is True:
            self._reachable += 1
            if level == REACHABILITY_LEVEL_SYMBOL:
                self._confirmed += 1
            elif level == REACHABILITY_LEVEL_IMPORT:
                self._likely += 1
            if bucket == "CRITICAL":
                self._reachable_critical += 1
            elif bucket == "HIGH":
                self._reachable_high += 1
            raw_reach = details.get("reachability")
            confidence = _numeric(raw_reach.get("confidence_score")) if isinstance(raw_reach, Mapping) else None
            if confidence is not None and confidence >= REACHABILITY_HIGH_CONFIDENCE_THRESHOLD:
                self._reachable_hc += 1
                if bucket == "CRITICAL":
                    self._reachable_critical_hc += 1
                elif bucket == "HIGH":
                    self._reachable_high_hc += 1
        elif reachable is False:
            self._unreachable += 1

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
                # vuln_total is type-gated; _analyzed is ungated. Non-vulnerabilities carrying
                # reachable drive this negative.
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
    component_languages: Mapping[str, frozenset[str]],
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


# Tautological today; it fires the moment someone hand-edits the projection, which is the one
# failure class a differential test cannot see — a typo zeroes a counter on both sides.
assert StatsAccumulator.REQUIRED_PATHS <= _stats_projection().keys(), "stats projection drops a required path"

# scan_id + type is the only index pair immutable after insert; severity and waived are rewritten by
# _rollup_vulnerability_waivers and _apply_waivers, so hinting either opens a skip window mid-cursor.
_STATS_CURSOR_HINT = [("scan_id", ASCENDING), ("type", ASCENDING)]


async def calculate_comprehensive_stats(db: Database, scan_id: str) -> Stats:
    """Comprehensive statistics for a scan, folded from a single projected cursor."""
    acc = StatsAccumulator(await build_component_language_map(db, scan_id))
    # PRIMARY: with secondaryPreferred the read can miss findings written milliseconds earlier.
    findings_primary = db.findings.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]
    cursor = findings_primary.find({"scan_id": scan_id}, _stats_projection(), hint=_STATS_CURSOR_HINT)
    try:
        async for doc in cursor:
            acc.add(doc)
    finally:
        await cursor.close()
    return acc.result()
