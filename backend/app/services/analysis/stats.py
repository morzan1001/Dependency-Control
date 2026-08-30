"""Statistics calculation for SBOM analysis (EPSS/KEV and reachability)."""

from datetime import datetime, timezone
from typing import Any, cast

from app.core.constants import (
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
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
    saturating_risk_score,
    severity_exposure,
)
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
from app.services.reachability_enrichment import is_high_confidence_reachable, reachability_display_tier


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
    """Process EPSS data for a single finding. Returns the epss_score if present."""
    epss_score = details.get("epss_score")
    if epss_score is None:
        return None
    summary["epss_enriched"] += 1
    epss_scores.append(float(epss_score))
    summary["epss_scores"][bucket_epss(float(epss_score))] += 1
    return float(epss_score)


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
    summary["high_risk_cves"] = summary["high_risk_cves"][:20]

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


_VULN_TYPE_GATE: dict[str, Any] = {"$eq": ["$type", "vulnerability"]}

# ``reachable`` is tri-state: only these predicates may gate a reachability counter, so that an
# unanalysed finding (null) can never be counted as reachable or as unreachable.
_REACHABLE_TRUE: dict[str, Any] = {"$eq": ["$reachable", True]}
_REACHABLE_FALSE: dict[str, Any] = {"$eq": ["$reachable", False]}
_REACHABLE_UNKNOWN: dict[str, Any] = {"$eq": ["$reachable", None]}
_REACHABILITY_ANALYZED: dict[str, Any] = {"$ne": ["$reachable", None]}

# Severities with a dedicated bucket; anything else is counted as unknown so buckets always sum to total.
_BUCKETED_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "INFO")


async def calculate_comprehensive_stats(db: Database, scan_id: str) -> Stats:
    """Calculate comprehensive statistics including EPSS/KEV and reachability data."""
    pipeline: list[dict[str, Any]] = [
        {"$match": {"scan_id": scan_id, "waived": {"$ne": True}}},
        {
            "$project": {
                "severity": 1,
                "type": 1,
                "epss_score": {"$ifNull": ["$details.epss_score", None]},
                "is_kev": {"$ifNull": [f"$details.{DETAILS_KEY_IN_KEV}", False]},
                "kev_ransomware": {"$ifNull": [f"$details.{DETAILS_KEY_KEV_RANSOMWARE}", False]},
                "reachable": {"$ifNull": ["$reachable", None]},
                "reachability_level": {"$ifNull": ["$reachability_level", "unknown"]},
                # Pulled up from details.reachability so the group stage can gate counts on it.
                "reachability_confidence": {"$ifNull": ["$details.reachability.confidence_score", None]},
                "verified": {"$ifNull": ["$details.verified", None]},
                "in_current_tree": {"$ifNull": ["$details.in_current_tree", None]},
                "severity_weight": {
                    "$switch": {
                        "branches": [
                            {"case": {"$eq": ["$severity", sev]}, "then": weight}
                            for sev, weight in RISK_SEVERITY_WEIGHTS.items()
                        ],
                        "default": 0.0,
                    }
                },
                "reach_modifier": {
                    "$switch": {
                        "branches": [
                            {"case": _REACHABLE_FALSE, "then": UNREACHABLE_RISK_MODIFIER},
                            {
                                "case": {
                                    "$and": [
                                        _REACHABLE_TRUE,
                                        {"$eq": ["$reachability_level", REACHABILITY_LEVEL_SYMBOL]},
                                    ]
                                },
                                "then": CONFIRMED_REACHABLE_RISK_MODIFIER,
                            },
                        ],
                        "default": 1.0,
                    }
                },
            }
        },
        {
            "$group": {
                "_id": None,
                # Traditional severity counts
                "critical": {"$sum": {"$cond": [{"$eq": ["$severity", "CRITICAL"]}, 1, 0]}},
                "high": {"$sum": {"$cond": [{"$eq": ["$severity", "HIGH"]}, 1, 0]}},
                "medium": {"$sum": {"$cond": [{"$eq": ["$severity", "MEDIUM"]}, 1, 0]}},
                "low": {"$sum": {"$cond": [{"$eq": ["$severity", "LOW"]}, 1, 0]}},
                "negligible": {"$sum": {"$cond": [{"$eq": ["$severity", "NEGLIGIBLE"]}, 1, 0]}},
                "info": {"$sum": {"$cond": [{"$eq": ["$severity", "INFO"]}, 1, 0]}},
                "unknown": {"$sum": {"$cond": [{"$in": ["$severity", list(_BUCKETED_SEVERITIES)]}, 0, 1]}},
                # Reachability is vulnerability-only, so unknown_count is measured against vulns only.
                "vuln_total": {"$sum": {"$cond": [_VULN_TYPE_GATE, 1, 0]}},
                # Vulnerability-only severity counts backing PrioritizedCounts.
                "vuln_critical": {
                    "$sum": {"$cond": [{"$and": [_VULN_TYPE_GATE, {"$eq": ["$severity", "CRITICAL"]}]}, 1, 0]}
                },
                "vuln_high": {"$sum": {"$cond": [{"$and": [_VULN_TYPE_GATE, {"$eq": ["$severity", "HIGH"]}]}, 1, 0]}},
                "vuln_medium": {
                    "$sum": {"$cond": [{"$and": [_VULN_TYPE_GATE, {"$eq": ["$severity", "MEDIUM"]}]}, 1, 0]}
                },
                "vuln_low": {"$sum": {"$cond": [{"$and": [_VULN_TYPE_GATE, {"$eq": ["$severity", "LOW"]}]}, 1, 0]}},
                # Weighted exposure with per-finding reachability modifiers; saturated into
                # adjusted_risk_score below. Base exposure is derived from the severity counts.
                "adjusted_exposure": {"$sum": {"$multiply": ["$severity_weight", "$reach_modifier"]}},
                # KEV statistics
                "kev_count": {"$sum": {"$cond": [{"$eq": ["$is_kev", True]}, 1, 0]}},
                "kev_ransomware_count": {"$sum": {"$cond": [{"$eq": ["$kev_ransomware", True]}, 1, 0]}},
                # EPSS statistics
                "epss_scores": {
                    "$push": {
                        "$cond": [
                            {"$ne": ["$epss_score", None]},
                            "$epss_score",
                            "$$REMOVE",
                        ]
                    }
                },
                "high_epss_count": {"$sum": {"$cond": [{"$gte": ["$epss_score", 0.1]}, 1, 0]}},
                "medium_epss_count": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$gte": ["$epss_score", 0.01]},
                                    {"$lt": ["$epss_score", 0.1]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Reachability statistics
                "reachability_analyzed": {"$sum": {"$cond": [_REACHABILITY_ANALYZED, 1, 0]}},
                "reachable_count": {"$sum": {"$cond": [_REACHABLE_TRUE, 1, 0]}},
                "unreachable_count": {"$sum": {"$cond": [_REACHABLE_FALSE, 1, 0]}},
                # Symbol-level reachable = confirmed tier; import-level reachable = likely tier.
                "confirmed_reachable": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    _REACHABLE_TRUE,
                                    {"$eq": ["$reachability_level", REACHABILITY_LEVEL_SYMBOL]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "likely_reachable": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    _REACHABLE_TRUE,
                                    {"$eq": ["$reachability_level", REACHABILITY_LEVEL_IMPORT]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Reachable by severity
                "reachable_critical": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    _REACHABLE_TRUE,
                                    {"$eq": ["$severity", "CRITICAL"]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "reachable_high": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    _REACHABLE_TRUE,
                                    {"$eq": ["$severity", "HIGH"]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Counts gated by confidence >= REACHABILITY_HIGH_CONFIDENCE_THRESHOLD.
                "reachable_count_high_confidence": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    _REACHABLE_TRUE,
                                    {
                                        "$gte": [
                                            "$reachability_confidence",
                                            REACHABILITY_HIGH_CONFIDENCE_THRESHOLD,
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "reachable_critical_high_confidence": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    _REACHABLE_TRUE,
                                    {"$eq": ["$severity", "CRITICAL"]},
                                    {
                                        "$gte": [
                                            "$reachability_confidence",
                                            REACHABILITY_HIGH_CONFIDENCE_THRESHOLD,
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "reachable_high_high_confidence": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    _REACHABLE_TRUE,
                                    {"$eq": ["$severity", "HIGH"]},
                                    {
                                        "$gte": [
                                            "$reachability_confidence",
                                            REACHABILITY_HIGH_CONFIDENCE_THRESHOLD,
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Actionable: vulnerability AND (KEV or high EPSS) AND reachable (or reachability unknown)
                "actionable_critical": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    _VULN_TYPE_GATE,
                                    {"$eq": ["$severity", "CRITICAL"]},
                                    {
                                        "$or": [
                                            {"$eq": ["$is_kev", True]},
                                            {"$gte": ["$epss_score", 0.1]},
                                        ]
                                    },
                                    {
                                        "$or": [
                                            _REACHABLE_TRUE,
                                            _REACHABLE_UNKNOWN,
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "actionable_high": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    _VULN_TYPE_GATE,
                                    {"$eq": ["$severity", "HIGH"]},
                                    {
                                        "$or": [
                                            {"$eq": ["$is_kev", True]},
                                            {"$gte": ["$epss_score", 0.1]},
                                        ]
                                    },
                                    {
                                        "$or": [
                                            _REACHABLE_TRUE,
                                            _REACHABLE_UNKNOWN,
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "actionable_total": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    _VULN_TYPE_GATE,
                                    {
                                        "$or": [
                                            {"$eq": ["$is_kev", True]},
                                            {"$gte": ["$epss_score", 0.1]},
                                        ]
                                    },
                                    {
                                        "$or": [
                                            _REACHABLE_TRUE,
                                            _REACHABLE_UNKNOWN,
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Deprioritized: vulnerability AND (unreachable OR (low EPSS and not KEV)).
                # Without the type gate every non-vulnerability finding qualifies via its missing EPSS.
                "deprioritized_count": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    _VULN_TYPE_GATE,
                                    {
                                        "$or": [
                                            _REACHABLE_FALSE,
                                            {
                                                "$and": [
                                                    {"$ne": ["$is_kev", True]},
                                                    {
                                                        "$or": [
                                                            {"$eq": ["$epss_score", None]},
                                                            {"$lt": ["$epss_score", 0.01]},
                                                        ]
                                                    },
                                                ]
                                            },
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Weaponized: KEV with ransomware or high EPSS with KEV
                "weaponized_count": {
                    "$sum": {
                        "$cond": [
                            {
                                "$or": [
                                    {"$eq": ["$kev_ransomware", True]},
                                    {
                                        "$and": [
                                            {"$eq": ["$is_kev", True]},
                                            {"$gte": ["$epss_score", 0.5]},
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Active exploitation: KEV or very high EPSS
                "active_exploitation_count": {
                    "$sum": {
                        "$cond": [
                            {
                                "$or": [
                                    {"$eq": ["$is_kev", True]},
                                    {"$gte": ["$epss_score", 0.7]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Secret finding priority (git-context aware)
                "secret_total": {"$sum": {"$cond": [{"$eq": ["$type", "secret"]}, 1, 0]}},
                "secret_verified_count": {
                    "$sum": {
                        "$cond": [
                            {"$and": [{"$eq": ["$type", "secret"]}, {"$eq": ["$verified", True]}]},
                            1,
                            0,
                        ]
                    }
                },
                "secret_in_current_tree_count": {
                    "$sum": {
                        "$cond": [
                            {"$and": [{"$eq": ["$type", "secret"]}, {"$eq": ["$in_current_tree", True]}]},
                            1,
                            0,
                        ]
                    }
                },
                "secret_historical_only_count": {
                    "$sum": {
                        "$cond": [
                            {"$and": [{"$eq": ["$type", "secret"]}, {"$eq": ["$in_current_tree", False]}]},
                            1,
                            0,
                        ]
                    }
                },
                "secret_unknown_tree_count": {
                    "$sum": {
                        "$cond": [
                            {"$and": [{"$eq": ["$type", "secret"]}, {"$eq": ["$in_current_tree", None]}]},
                            1,
                            0,
                        ]
                    }
                },
                "secret_actionable_count": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$eq": ["$type", "secret"]},
                                    {"$eq": ["$verified", True]},
                                    {"$eq": ["$in_current_tree", True]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "secret_deprioritized_count": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$eq": ["$type", "secret"]},
                                    {"$ne": ["$verified", True]},
                                    {"$eq": ["$in_current_tree", False]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
            }
        },
    ]

    # Read from PRIMARY to ensure read-after-write consistency.
    # With secondaryPreferred, the stats aggregation might hit a replica
    # that hasn't replicated the findings written milliseconds earlier,
    # resulting in all-zero stats.
    from pymongo import ReadPreference

    findings_primary = db.findings.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]
    stats_result: list[dict[str, Any]] = await findings_primary.aggregate(pipeline).to_list(1)

    # Initialize stats with defaults
    stats = Stats()

    if stats_result:
        res = stats_result[0]

        stats.critical = res.get("critical", 0)
        stats.high = res.get("high", 0)
        stats.medium = res.get("medium", 0)
        stats.low = res.get("low", 0)
        stats.negligible = res.get("negligible", 0)
        stats.info = res.get("info", 0)
        stats.unknown = res.get("unknown", 0)
        stats.risk_score = saturating_risk_score(severity_exposure(stats.critical, stats.high, stats.medium, stats.low))
        stats.adjusted_risk_score = saturating_risk_score(res.get("adjusted_exposure", 0.0))

        epss_scores: list[float] = [s for s in res.get("epss_scores", []) if s is not None]
        avg_epss: float | None = sum(epss_scores) / len(epss_scores) if epss_scores else None
        max_epss: float | None = max(epss_scores) if epss_scores else None

        stats.threat_intel = ThreatIntelligenceStats(
            kev_count=res.get("kev_count", 0),
            kev_ransomware_count=res.get("kev_ransomware_count", 0),
            high_epss_count=res.get("high_epss_count", 0),
            medium_epss_count=res.get("medium_epss_count", 0),
            avg_epss_score=round(avg_epss, 4) if avg_epss is not None else None,
            max_epss_score=round(max_epss, 4) if max_epss is not None else None,
            weaponized_count=res.get("weaponized_count", 0),
            active_exploitation_count=res.get("active_exploitation_count", 0),
        )

        stats.reachability = ReachabilityStats(
            analyzed_count=res.get("reachability_analyzed", 0),
            reachable_count=res.get("reachable_count", 0),
            confirmed_reachable_count=res.get("confirmed_reachable", 0),
            likely_reachable_count=res.get("likely_reachable", 0),
            unreachable_count=res.get("unreachable_count", 0),
            unknown_count=res.get("vuln_total", 0) - res.get("reachability_analyzed", 0),
            reachable_critical=res.get("reachable_critical", 0),
            reachable_high=res.get("reachable_high", 0),
            reachable_count_high_confidence=res.get("reachable_count_high_confidence", 0),
            reachable_critical_high_confidence=res.get("reachable_critical_high_confidence", 0),
            reachable_high_high_confidence=res.get("reachable_high_high_confidence", 0),
        )

        stats.prioritized = PrioritizedCounts(
            total=res.get("vuln_total", 0),
            critical=res.get("vuln_critical", 0),
            high=res.get("vuln_high", 0),
            medium=res.get("vuln_medium", 0),
            low=res.get("vuln_low", 0),
            actionable_critical=res.get("actionable_critical", 0),
            actionable_high=res.get("actionable_high", 0),
            actionable_total=res.get("actionable_total", 0),
            deprioritized_count=res.get("deprioritized_count", 0),
        )

        stats.secret_priority = SecretPrioritizedCounts(
            total=res.get("secret_total", 0),
            verified_count=res.get("secret_verified_count", 0),
            in_current_tree_count=res.get("secret_in_current_tree_count", 0),
            historical_only_count=res.get("secret_historical_only_count", 0),
            unknown_tree_count=res.get("secret_unknown_tree_count", 0),
            actionable_count=res.get("secret_actionable_count", 0),
            deprioritized_count=res.get("secret_deprioritized_count", 0),
        )

    return stats
