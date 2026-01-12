from datetime import datetime, timezone
from typing import Any, Dict, List

from app.core.constants import sort_by_severity
from app.models.stats import (
    PrioritizedCounts,
    ReachabilityStats,
    Stats,
    ThreatIntelligenceStats,
)


def build_epss_kev_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a summary of EPSS/KEV enrichment for raw data view.

    Args:
        findings: List of vulnerability findings that were enriched

    Returns:
        Summary dict with statistics and details
    """
    summary: Dict[str, Any] = {
        "total_vulnerabilities": len(findings),
        "epss_enriched": 0,
        "kev_matches": 0,
        "kev_ransomware": 0,
        "epss_scores": {
            "high": 0,  # > 0.1 (10%)
            "medium": 0,  # 0.01 - 0.1 (1-10%)
            "low": 0,  # < 0.01 (< 1%)
        },
        "exploit_maturity": {
            "weaponized": 0,
            "active": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0,
        },
        "avg_epss_score": None,
        "max_epss_score": None,
        "avg_risk_score": None,
        "max_risk_score": None,
        "kev_details": [],
        "high_risk_cves": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    epss_scores = []
    risk_scores = []

    for finding in findings:
        details = finding.get("details", {})

        # EPSS enrichment
        epss_score = details.get("epss_score")
        if epss_score is not None:
            summary["epss_enriched"] += 1
            epss_scores.append(epss_score)

            if epss_score > 0.1:
                summary["epss_scores"]["high"] += 1
            elif epss_score > 0.01:
                summary["epss_scores"]["medium"] += 1
            else:
                summary["epss_scores"]["low"] += 1

        # KEV enrichment
        if details.get("in_kev"):
            summary["kev_matches"] += 1
            kev_detail = {
                "cve": finding.get("finding_id") or finding.get("id", ""),
                "component": finding.get("component", ""),
                "due_date": details.get("kev_due_date"),
                "ransomware": details.get("kev_ransomware_use", False),
            }
            summary["kev_details"].append(kev_detail)

            if details.get("kev_ransomware_use"):
                summary["kev_ransomware"] += 1

        # Exploit maturity
        maturity = details.get("exploit_maturity", "unknown")
        if maturity in summary["exploit_maturity"]:
            summary["exploit_maturity"][maturity] += 1

        # Risk score
        risk_score = details.get("risk_score")
        if risk_score is not None:
            risk_scores.append(risk_score)

            # Track high-risk CVEs (risk_score > 70)
            if risk_score > 70:
                summary["high_risk_cves"].append(
                    {
                        "cve": finding.get("finding_id") or finding.get("id", ""),
                        "component": finding.get("component", ""),
                        "version": finding.get("version", ""),
                        "risk_score": round(risk_score, 1),
                        "epss_score": round(epss_score, 4) if epss_score else None,
                        "in_kev": details.get("in_kev", False),
                        "exploit_maturity": maturity,
                    }
                )

    # Calculate averages
    if epss_scores:
        summary["avg_epss_score"] = round(sum(epss_scores) / len(epss_scores), 4)
        summary["max_epss_score"] = round(max(epss_scores), 4)

    if risk_scores:
        summary["avg_risk_score"] = round(sum(risk_scores) / len(risk_scores), 1)
        summary["max_risk_score"] = round(max(risk_scores), 1)

    # Sort high-risk CVEs by risk score
    summary["high_risk_cves"].sort(key=lambda x: x["risk_score"], reverse=True)
    # Limit to top 20
    summary["high_risk_cves"] = summary["high_risk_cves"][:20]

    return summary


def build_reachability_summary(
    findings: List[Dict[str, Any]], callgraph: Dict[str, Any], enriched_count: int
) -> Dict[str, Any]:
    """
    Build a summary of reachability analysis for raw data view.

    Args:
        findings: List of vulnerability findings that were analyzed
        callgraph: The callgraph document used for analysis
        enriched_count: Number of findings that were enriched

    Returns:
        Summary dict with statistics and details
    """
    summary: Dict[str, Any] = {
        "total_vulnerabilities": len(findings),
        "analyzed": enriched_count,
        "reachability_levels": {
            "confirmed": 0,  # Symbol-level match
            "likely": 0,  # Import-level match
            "unknown": 0,  # Could not determine
            "unreachable": 0,  # Confirmed not used
        },
        "callgraph_info": {
            "language": callgraph.get("language", "unknown"),
            "total_modules": len(callgraph.get("module_usage", {})),
            "total_imports": len(callgraph.get("import_map", {})),
            "generated_at": (
                callgraph.get("created_at", "").isoformat()
                if hasattr(callgraph.get("created_at", ""), "isoformat")
                else str(callgraph.get("created_at", ""))
            ),
        },
        "reachable_vulnerabilities": [],
        "unreachable_vulnerabilities": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    for finding in findings:
        reachable = finding.get("reachable")
        reachability_level = finding.get("reachability_level", "unknown")

        vuln_info = {
            "cve": finding.get("finding_id") or finding.get("id", ""),
            "component": finding.get("component", ""),
            "version": finding.get("version", ""),
            "severity": finding.get("severity", "unknown"),
            "reachability_level": reachability_level,
            "reachable_functions": finding.get("reachable_functions", [])[
                :5
            ],  # Limit to 5
        }

        if reachability_level in summary["reachability_levels"]:
            summary["reachability_levels"][reachability_level] += 1

        if reachable is True:
            summary["reachable_vulnerabilities"].append(vuln_info)
        elif reachable is False:
            summary["unreachable_vulnerabilities"].append(vuln_info)

    # Sort by severity (most severe first)
    summary["reachable_vulnerabilities"] = sort_by_severity(
        summary["reachable_vulnerabilities"], key="severity", reverse=True
    )
    summary["unreachable_vulnerabilities"] = sort_by_severity(
        summary["unreachable_vulnerabilities"], key="severity", reverse=True
    )

    # Limit lists to top 30
    summary["reachable_vulnerabilities"] = summary["reachable_vulnerabilities"][:30]
    summary["unreachable_vulnerabilities"] = summary["unreachable_vulnerabilities"][:30]

    return summary


async def calculate_comprehensive_stats(db, scan_id: str) -> Stats:
    """
    Calculate comprehensive statistics including EPSS/KEV and Reachability data.

    Args:
        db: Database connection
        scan_id: The scan ID to calculate stats for

    Returns:
        Stats object with all fields populated
    """
    # Comprehensive aggregation pipeline
    pipeline = [
        {"$match": {"scan_id": scan_id, "waived": False}},
        {
            "$project": {
                "severity": 1,
                "cvss_score": {"$ifNull": ["$details.cvss_score", None]},
                "epss_score": {"$ifNull": ["$details.epss_score", None]},
                "is_kev": {"$ifNull": ["$details.is_kev", False]},
                "kev_ransomware": {"$ifNull": ["$details.kev_ransomware", False]},
                "reachable": {"$ifNull": ["$reachable", None]},
                "reachability_level": {"$ifNull": ["$reachability_level", "unknown"]},
                "risk_score": {"$ifNull": ["$details.risk_score", None]},
                # Calculate default CVSS-based score if none provided
                "calculated_score": {
                    "$switch": {
                        "branches": [
                            {"case": {"$eq": ["$severity", "CRITICAL"]}, "then": 10.0},
                            {"case": {"$eq": ["$severity", "HIGH"]}, "then": 7.5},
                            {"case": {"$eq": ["$severity", "MEDIUM"]}, "then": 4.0},
                            {"case": {"$eq": ["$severity", "LOW"]}, "then": 1.0},
                        ],
                        "default": 0.0,
                    }
                },
            }
        },
        {
            "$group": {
                "_id": None,
                # Traditional severity counts
                "critical": {
                    "$sum": {"$cond": [{"$eq": ["$severity", "CRITICAL"]}, 1, 0]}
                },
                "high": {"$sum": {"$cond": [{"$eq": ["$severity", "HIGH"]}, 1, 0]}},
                "medium": {"$sum": {"$cond": [{"$eq": ["$severity", "MEDIUM"]}, 1, 0]}},
                "low": {"$sum": {"$cond": [{"$eq": ["$severity", "LOW"]}, 1, 0]}},
                "info": {"$sum": {"$cond": [{"$eq": ["$severity", "INFO"]}, 1, 0]}},
                "unknown": {
                    "$sum": {"$cond": [{"$eq": ["$severity", "UNKNOWN"]}, 1, 0]}
                },
                "total": {"$sum": 1},
                # Traditional risk score sum
                "risk_score_sum": {
                    "$sum": {"$ifNull": ["$cvss_score", "$calculated_score"]}
                },
                # Adjusted risk scores (including enrichment data)
                "adjusted_risk_score_sum": {
                    "$sum": {"$ifNull": ["$risk_score", "$calculated_score"]}
                },
                # KEV statistics
                "kev_count": {"$sum": {"$cond": [{"$eq": ["$is_kev", True]}, 1, 0]}},
                "kev_ransomware_count": {
                    "$sum": {"$cond": [{"$eq": ["$kev_ransomware", True]}, 1, 0]}
                },
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
                "high_epss_count": {
                    "$sum": {"$cond": [{"$gte": ["$epss_score", 0.1]}, 1, 0]}
                },
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
                "reachability_analyzed": {
                    "$sum": {"$cond": [{"$ne": ["$reachable", None]}, 1, 0]}
                },
                "reachable_count": {
                    "$sum": {"$cond": [{"$eq": ["$reachable", True]}, 1, 0]}
                },
                "unreachable_count": {
                    "$sum": {"$cond": [{"$eq": ["$reachable", False]}, 1, 0]}
                },
                "confirmed_reachable": {
                    "$sum": {
                        "$cond": [{"$eq": ["$reachability_level", "confirmed"]}, 1, 0]
                    }
                },
                "likely_reachable": {
                    "$sum": {
                        "$cond": [{"$eq": ["$reachability_level", "likely"]}, 1, 0]
                    }
                },
                # Reachable by severity
                "reachable_critical": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$eq": ["$reachable", True]},
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
                                    {"$eq": ["$reachable", True]},
                                    {"$eq": ["$severity", "HIGH"]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Actionable: KEV or high EPSS AND reachable (or reachability unknown)
                "actionable_critical": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$eq": ["$severity", "CRITICAL"]},
                                    {
                                        "$or": [
                                            {"$eq": ["$is_kev", True]},
                                            {"$gte": ["$epss_score", 0.1]},
                                        ]
                                    },
                                    {
                                        "$or": [
                                            {"$eq": ["$reachable", True]},
                                            {
                                                "$eq": ["$reachable", None]
                                            },  # Unknown = assume reachable
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
                                    {"$eq": ["$severity", "HIGH"]},
                                    {
                                        "$or": [
                                            {"$eq": ["$is_kev", True]},
                                            {"$gte": ["$epss_score", 0.1]},
                                        ]
                                    },
                                    {
                                        "$or": [
                                            {"$eq": ["$reachable", True]},
                                            {"$eq": ["$reachable", None]},
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
                                    {
                                        "$or": [
                                            {"$eq": ["$is_kev", True]},
                                            {"$gte": ["$epss_score", 0.1]},
                                        ]
                                    },
                                    {
                                        "$or": [
                                            {"$eq": ["$reachable", True]},
                                            {"$eq": ["$reachable", None]},
                                        ]
                                    },
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                # Deprioritized: unreachable OR (low EPSS and not KEV)
                "deprioritized_count": {
                    "$sum": {
                        "$cond": [
                            {
                                "$or": [
                                    {"$eq": ["$reachable", False]},
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
            }
        },
    ]

    stats_result = await db.findings.aggregate(pipeline).to_list(1)

    # Initialize stats with defaults
    stats = Stats()

    if stats_result:
        res = stats_result[0]

        # Traditional severity counts
        stats.critical = res.get("critical", 0)
        stats.high = res.get("high", 0)
        stats.medium = res.get("medium", 0)
        stats.low = res.get("low", 0)
        stats.info = res.get("info", 0)
        stats.unknown = res.get("unknown", 0)
        stats.risk_score = round(res.get("risk_score_sum", 0.0), 1)
        stats.adjusted_risk_score = round(res.get("adjusted_risk_score_sum", 0.0), 1)

        # Calculate EPSS statistics
        epss_scores = [s for s in res.get("epss_scores", []) if s is not None]
        avg_epss = sum(epss_scores) / len(epss_scores) if epss_scores else None
        max_epss = max(epss_scores) if epss_scores else None

        # Threat Intelligence Stats
        stats.threat_intel = ThreatIntelligenceStats(
            kev_count=res.get("kev_count", 0),
            kev_ransomware_count=res.get("kev_ransomware_count", 0),
            high_epss_count=res.get("high_epss_count", 0),
            medium_epss_count=res.get("medium_epss_count", 0),
            avg_epss_score=round(avg_epss, 4) if avg_epss else None,
            max_epss_score=round(max_epss, 4) if max_epss else None,
            weaponized_count=res.get("weaponized_count", 0),
            active_exploitation_count=res.get("active_exploitation_count", 0),
        )

        # Reachability Stats
        stats.reachability = ReachabilityStats(
            analyzed_count=res.get("reachability_analyzed", 0),
            reachable_count=res.get("reachable_count", 0),
            likely_reachable_count=res.get("likely_reachable", 0),
            unreachable_count=res.get("unreachable_count", 0),
            unknown_count=res.get("total", 0) - res.get("reachability_analyzed", 0),
            reachable_critical=res.get("reachable_critical", 0),
            reachable_high=res.get("reachable_high", 0),
        )

        # Prioritized Counts
        stats.prioritized = PrioritizedCounts(
            total=res.get("total", 0),
            critical=res.get("critical", 0),
            high=res.get("high", 0),
            medium=res.get("medium", 0),
            low=res.get("low", 0),
            actionable_critical=res.get("actionable_critical", 0),
            actionable_high=res.get("actionable_high", 0),
            actionable_total=res.get("actionable_total", 0),
            deprioritized_count=res.get("deprioritized_count", 0),
        )

    return stats
