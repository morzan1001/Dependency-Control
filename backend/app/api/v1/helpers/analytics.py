"""
Analytics Helper Functions

Helper functions for analytics endpoints, extracted for better
code organization and reusability.
"""

from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import (
    ANALYTICS_MAX_QUERY_LIMIT,
    BLAST_RADIUS_THRESHOLD,
    DAYS_KNOWN_OVERDUE_THRESHOLD,
    EPSS_HIGH_BOOST,
    EPSS_HIGH_THRESHOLD,
    EPSS_MEDIUM_BOOST,
    EPSS_MEDIUM_THRESHOLD,
    EPSS_VERY_HIGH_BOOST,
    EPSS_VERY_HIGH_THRESHOLD,
    EXPLOIT_MATURITY_BOOST,
    EXPLOIT_MATURITY_ORDER,
    IMPACT_AGE_BOOST,
    IMPACT_FIX_AVAILABLE_BOOST,
    IMPACT_REACH_MULTIPLIER_CAP,
    KEV_DEFAULT_BOOST,
    KEV_DUE_SOON_BOOST,
    KEV_DUE_SOON_DAYS,
    KEV_OVERDUE_BOOST,
    KEV_RANSOMWARE_BOOST,
    SEVERITY_WEIGHTS,
)
from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.repositories import ProjectRepository, TeamRepository


def require_analytics_permission(user: User, permission: str):
    """Raise 403 if user doesn't have the required analytics permission."""
    # Check for the specific permission or the general analytics:read permission
    if not has_permission(user.permissions, [Permissions.ANALYTICS_READ, permission]):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Analytics permission required: {permission}. "
                f"Grant '{Permissions.ANALYTICS_READ}' for full analytics access "
                f"or '{permission}' for this specific feature."
            ),
        )


async def get_user_project_ids(user: User, db: AsyncIOMotorDatabase) -> List[str]:
    """Get list of project IDs the user has access to."""
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    if has_permission(user.permissions, Permissions.PROJECT_READ_ALL):
        projects = await project_repo.find_many(
            {}, limit=ANALYTICS_MAX_QUERY_LIMIT, projection={"_id": 1}
        )
        return [p["_id"] for p in projects]

    user_teams = await team_repo.find_by_member(str(user.id))
    user_team_ids = [str(t["_id"]) for t in user_teams]

    projects = await project_repo.find_many(
        {
            "$or": [
                {"owner_id": str(user.id)},
                {"members.user_id": str(user.id)},
                {"team_id": {"$in": user_team_ids}},
            ]
        },
        limit=ANALYTICS_MAX_QUERY_LIMIT,
        projection={"_id": 1},
    )

    return [p["_id"] for p in projects]


async def get_latest_scan_ids(
    project_ids: List[str], db: AsyncIOMotorDatabase
) -> List[str]:
    """Get latest scan IDs for given projects."""
    project_repo = ProjectRepository(db)
    projects = await project_repo.find_many(
        {"_id": {"$in": project_ids}},
        limit=ANALYTICS_MAX_QUERY_LIMIT,
        projection={"latest_scan_id": 1},
    )

    return [p["latest_scan_id"] for p in projects if p.get("latest_scan_id")]


async def get_projects_with_scans(
    project_ids: List[str], db: AsyncIOMotorDatabase
) -> Tuple[Dict[str, str], List[str]]:
    """
    Get project name mapping and scan IDs for given projects.

    Returns:
        Tuple of (project_name_map, scan_ids)
    """
    project_repo = ProjectRepository(db)
    projects = await project_repo.find_many(
        {"_id": {"$in": project_ids}},
        limit=ANALYTICS_MAX_QUERY_LIMIT,
        projection={"_id": 1, "name": 1, "latest_scan_id": 1},
    )

    project_name_map = {p["_id"]: p["name"] for p in projects}
    scan_ids = [p["latest_scan_id"] for p in projects if p.get("latest_scan_id")]

    return project_name_map, scan_ids


def calculate_days_until_due(kev_due_date: Optional[str]) -> Optional[int]:
    """Calculate days until KEV due date (negative = overdue)."""
    if not kev_due_date:
        return None
    try:
        due = datetime.strptime(kev_due_date, "%Y-%m-%d").date()
        return (due - date.today()).days
    except Exception:
        return None


def calculate_days_known(first_seen: Optional[datetime]) -> Optional[int]:
    """Calculate how many days a vulnerability has been known."""
    if not first_seen or not isinstance(first_seen, datetime):
        return None
    try:
        return (datetime.now(first_seen.tzinfo or None) - first_seen).days
    except Exception:
        return None


def extract_fix_versions(details_list: List[Any]) -> set:
    """Extract fix versions from finding details."""
    fix_versions = set()
    for details in details_list:
        if isinstance(details, dict):
            if details.get("fixed_version"):
                fix_versions.add(details["fixed_version"])
            for vuln in details.get("vulnerabilities", []):
                if vuln.get("fixed_version"):
                    fix_versions.add(vuln["fixed_version"])
    return fix_versions


def process_cve_enrichments(
    finding_ids: List[str], enrichments: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Process CVE enrichment data and extract maximum values.

    Returns dict with:
        max_epss, max_percentile, max_risk, has_kev, kev_count,
        kev_ransomware_use, kev_due_date, exploit_maturity
    """
    result = {
        "max_epss": None,
        "max_percentile": None,
        "max_risk": None,
        "has_kev": False,
        "kev_count": 0,
        "kev_ransomware_use": False,
        "kev_due_date": None,
        "exploit_maturity": "unknown",
    }

    for fid in finding_ids:
        if fid not in enrichments:
            continue

        enr = enrichments[fid]

        # EPSS scores
        if enr.epss_score is not None:
            if result["max_epss"] is None or enr.epss_score > result["max_epss"]:
                result["max_epss"] = enr.epss_score
                result["max_percentile"] = enr.epss_percentile

        # Risk score
        if enr.risk_score is not None:
            if result["max_risk"] is None or enr.risk_score > result["max_risk"]:
                result["max_risk"] = enr.risk_score

        # KEV data
        if enr.is_kev:
            result["has_kev"] = True
            result["kev_count"] += 1
            if enr.kev_ransomware_use:
                result["kev_ransomware_use"] = True
            if enr.kev_due_date:
                if (
                    result["kev_due_date"] is None
                    or enr.kev_due_date < result["kev_due_date"]
                ):
                    result["kev_due_date"] = enr.kev_due_date

        # Exploit maturity
        if EXPLOIT_MATURITY_ORDER.get(
            enr.exploit_maturity, 0
        ) > EXPLOIT_MATURITY_ORDER.get(result["exploit_maturity"], 0):
            result["exploit_maturity"] = enr.exploit_maturity

    return result


def calculate_impact_score(
    severity_counts: Dict[str, int],
    affected_projects: int,
    enrichment_data: Dict[str, Any],
    has_fix: bool,
    days_known: Optional[int],
) -> float:
    """
    Calculate fix impact score based on severity, reach, and threat intelligence.

    Factors considered (in order of importance):
    1. KEV with ransomware usage (highest priority)
    2. KEV with overdue remediation deadline
    3. Any KEV entry (actively exploited)
    4. High EPSS score (>10% exploitation probability)
    5. CVSS severity distribution
    6. Number of affected projects (blast radius)
    7. Fix availability (prefer fixable issues)
    8. Days known (older = more urgent)
    """
    # Base score from severity (weighted)
    severity_score = sum(
        severity_counts.get(sev, 0) * weight for sev, weight in SEVERITY_WEIGHTS.items()
    )

    # Reach multiplier (how many projects affected)
    reach_multiplier = min(affected_projects, IMPACT_REACH_MULTIPLIER_CAP)
    base_impact = float(severity_score * reach_multiplier)

    # KEV Boost (strongest signal - actively exploited)
    days_until_due = enrichment_data.get("days_until_due")
    if enrichment_data.get("has_kev"):
        if enrichment_data.get("kev_ransomware_use"):
            base_impact *= KEV_RANSOMWARE_BOOST
        elif days_until_due is not None and days_until_due < 0:
            base_impact *= KEV_OVERDUE_BOOST
        elif days_until_due is not None and days_until_due <= KEV_DUE_SOON_DAYS:
            base_impact *= KEV_DUE_SOON_BOOST
        else:
            base_impact *= KEV_DEFAULT_BOOST

    # EPSS Boost (probability of exploitation)
    max_epss = enrichment_data.get("max_epss")
    if max_epss:
        if max_epss >= EPSS_VERY_HIGH_THRESHOLD:
            base_impact *= EPSS_VERY_HIGH_BOOST
        elif max_epss >= EPSS_HIGH_THRESHOLD:
            base_impact *= EPSS_HIGH_BOOST
        elif max_epss >= EPSS_MEDIUM_THRESHOLD:
            base_impact *= EPSS_MEDIUM_BOOST

    # Exploit maturity boost
    exploit_maturity = enrichment_data.get("exploit_maturity", "unknown")
    base_impact *= EXPLOIT_MATURITY_BOOST.get(exploit_maturity, 1.0)

    # Fix availability boost (prioritize fixable issues)
    if has_fix:
        base_impact *= IMPACT_FIX_AVAILABLE_BOOST

    # Age factor (older vulnerabilities slightly higher priority)
    if days_known and days_known > DAYS_KNOWN_OVERDUE_THRESHOLD:
        base_impact *= IMPACT_AGE_BOOST

    return base_impact


def build_priority_reasons(
    severity_counts: Dict[str, int],
    enrichment_data: Dict[str, Any],
    affected_projects: int,
    has_fix: bool,
    days_known: Optional[int],
) -> List[str]:
    """Build human-readable priority reasons list."""
    reasons = []
    days_until_due = enrichment_data.get("days_until_due")
    max_epss = enrichment_data.get("max_epss")

    if enrichment_data.get("kev_ransomware_use"):
        reasons.append("ransomware:Used in ransomware campaigns - fix immediately")

    if days_until_due is not None and days_until_due < 0:
        reasons.append(
            f"deadline_overdue:CISA deadline overdue by {abs(days_until_due)} days"
        )
    elif days_until_due is not None and days_until_due <= KEV_DUE_SOON_DAYS:
        reasons.append(f"deadline:CISA deadline in {days_until_due} days")

    if enrichment_data.get("has_kev") and not enrichment_data.get("kev_ransomware_use"):
        reasons.append("kev:Actively exploited in the wild (CISA KEV)")

    if max_epss and max_epss >= EPSS_HIGH_THRESHOLD:
        reasons.append(
            f"epss:High exploitation probability ({max_epss * 100:.1f}% EPSS)"
        )

    if severity_counts.get("critical", 0) > 0:
        reasons.append(
            f"critical:{severity_counts['critical']} critical vulnerabilities"
        )

    if affected_projects >= BLAST_RADIUS_THRESHOLD:
        reasons.append(
            f"blast_radius:Affects {affected_projects} projects (high blast radius)"
        )

    if has_fix:
        reasons.append("fix_available:Fix available - easy to remediate")

    if days_known and days_known > DAYS_KNOWN_OVERDUE_THRESHOLD:
        reasons.append(f"overdue:Known for {days_known} days - overdue for remediation")

    return reasons


def count_severities(severities: List[Optional[str]]) -> Dict[str, int]:
    """Count severities from a list."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev in severities:
        if sev:
            sev_lower = sev.lower()
            if sev_lower in counts:
                counts[sev_lower] += 1
    return counts


def build_findings_severity_map(
    findings: List[Dict[str, Any]],
) -> Dict[str, Dict[str, int]]:
    """
    Build a map of component names to their severity counts.

    Args:
        findings: List of finding documents

    Returns:
        Dict mapping component name to severity counts:
        {
            "lodash": {"critical": 1, "high": 2, "medium": 0, "low": 0, "total": 3},
            ...
        }
    """
    findings_map: Dict[str, Dict[str, int]] = {}

    for finding in findings:
        component = finding.get("component")
        if not component:
            continue

        severity = finding.get("severity", "UNKNOWN")

        if component not in findings_map:
            findings_map[component] = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0,
            }

        sev_lower = severity.lower()
        if sev_lower in findings_map[component]:
            findings_map[component][sev_lower] += 1
        findings_map[component]["total"] += 1

    return findings_map


def build_hotspot_priority_reasons(
    enrichment_data: Dict[str, Any],
    severity_counts: Dict[str, int],
    has_fix: bool,
    days_until_due: Optional[int],
) -> List[str]:
    """
    Build priority reasons for vulnerability hotspots.

    Simplified version of build_priority_reasons() for hotspot display.

    Args:
        enrichment_data: CVE enrichment data from process_cve_enrichments()
        severity_counts: Dict with critical, high, medium, low counts
        has_fix: Whether a fix is available
        days_until_due: Days until KEV deadline (negative = overdue)

    Returns:
        List of priority reason strings
    """
    reasons = []

    if enrichment_data.get("kev_ransomware_use"):
        reasons.append("ransomware:Used in ransomware campaigns")

    if days_until_due is not None and days_until_due < 0:
        reasons.append(
            f"deadline_overdue:CISA deadline overdue by {abs(days_until_due)} days"
        )
    elif days_until_due is not None and days_until_due <= KEV_DUE_SOON_DAYS:
        reasons.append(f"deadline:CISA deadline in {days_until_due} days")

    if enrichment_data.get("has_kev") and not enrichment_data.get("kev_ransomware_use"):
        reasons.append("kev:Actively exploited (CISA KEV)")

    max_epss = enrichment_data.get("max_epss")
    if max_epss and max_epss >= EPSS_HIGH_THRESHOLD:
        reasons.append(f"epss:High EPSS ({max_epss * 100:.1f}%)")

    if severity_counts.get("critical", 0) > 0:
        reasons.append(f"critical:{severity_counts['critical']} critical vulns")

    if has_fix:
        reasons.append("fix_available:Fix available")

    return reasons


async def gather_cross_project_data(
    user_project_ids: List[str],
    current_project_id: str,
    db: AsyncIOMotorDatabase,
) -> Optional[Dict[str, Any]]:
    """
    Gather cross-project vulnerability and dependency data.

    Used for identifying shared vulnerabilities across projects.

    Args:
        user_project_ids: All project IDs the user has access to
        current_project_id: The project being analyzed (excluded from results)
        db: Database connection

    Returns:
        Dict with cross-project data or None if user has only one project:
        {
            "projects": [...],
            "total_projects": int
        }
    """
    from app.repositories import (
        DependencyRepository,
        FindingRepository,
        ProjectRepository,
        ScanRepository,
    )

    if len(user_project_ids) <= 1:
        return None

    project_repo = ProjectRepository(db)
    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
    dep_repo = DependencyRepository(db)

    cross_project_data: Dict[str, Any] = {
        "projects": [],
        "total_projects": len(user_project_ids),
    }

    # Get other projects (limit to 20 for performance)
    other_project_ids = [pid for pid in user_project_ids if pid != current_project_id][
        :20
    ]

    # Batch fetch: Get all projects info at once
    other_projects = await project_repo.find_many(
        {"_id": {"$in": other_project_ids}},
        limit=len(other_project_ids),
        projection={"_id": 1, "name": 1, "latest_scan_id": 1},
    )
    project_info_map = {p["_id"]: p for p in other_projects}

    # Collect scan IDs from projects
    scan_id_to_project: Dict[str, str] = {}
    for project in other_projects:
        if project.get("latest_scan_id"):
            scan_id_to_project[project["latest_scan_id"]] = project["_id"]

    other_scan_ids = list(scan_id_to_project.keys())

    if not other_scan_ids:
        return cross_project_data

    # Batch fetch: Get all scans at once for stats
    other_scans = await scan_repo.find_many(
        {"_id": {"$in": other_scan_ids}},
        limit=len(other_scan_ids),
        projection={"_id": 1, "stats": 1},
    )
    scan_stats_map = {s["_id"]: s.get("stats", {}) for s in other_scans}

    # Batch fetch: Get CVEs for all scans via aggregation
    cve_pipeline: List[Dict[str, Any]] = [
        {
            "$match": {
                "scan_id": {"$in": other_scan_ids},
                "type": "vulnerability",
            }
        },
        {
            "$group": {
                "_id": "$scan_id",
                "cves": {"$addToSet": "$details.cve_id"},
            }
        },
    ]
    cve_results = await finding_repo.aggregate(cve_pipeline)
    scan_cves_map = {r["_id"]: [c for c in r["cves"] if c] for r in cve_results}

    # Batch fetch: Get packages for all scans via aggregation
    pkg_pipeline: List[Dict[str, Any]] = [
        {"$match": {"scan_id": {"$in": other_scan_ids}}},
        {
            "$group": {
                "_id": "$scan_id",
                "packages": {"$push": {"name": "$name", "version": "$version"}},
            }
        },
        {"$project": {"_id": 1, "packages": {"$slice": ["$packages", 100]}}},
    ]
    pkg_results = await dep_repo.aggregate(pkg_pipeline)
    scan_pkgs_map = {r["_id"]: r["packages"] for r in pkg_results}

    # Build cross-project data from batch results
    for scan_id, proj_id in scan_id_to_project.items():
        proj_info = project_info_map.get(proj_id, {})
        stats = scan_stats_map.get(scan_id, {})
        severity_counts = stats.get("severity_counts", {})

        cross_project_data["projects"].append(
            {
                "project_id": proj_id,
                "project_name": proj_info.get("name", "Unknown"),
                "cves": scan_cves_map.get(scan_id, []),
                "packages": scan_pkgs_map.get(scan_id, []),
                "total_critical": severity_counts.get("CRITICAL", 0),
                "total_high": severity_counts.get("HIGH", 0),
            }
        )

    return cross_project_data
