"""Helper functions for analytics endpoints."""

from datetime import datetime, timezone
from typing import Any

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
    IMPACT_MAX_SCORE_BOOST,
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
from app.repositories import ProjectRepository, ScanRepository
from app.schemas.analytics import CVEEnrichmentResult
from app.services.aggregation.components import build_component_index
from app.services.recommendation.common import get_attr

MONGO_MATCH = "$match"
MONGO_GROUP = "$group"


def require_analytics_permission(user: User, permission: str) -> None:
    """Raise 403 if user doesn't have the required analytics permission."""
    if not has_permission(user.permissions, [Permissions.ANALYTICS_READ, permission]):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Analytics permission required: {permission}. "
                f"Grant '{Permissions.ANALYTICS_READ}' for full analytics access "
                f"or '{permission}' for this specific feature."
            ),
        )


async def get_user_project_ids(user: User, db: AsyncIOMotorDatabase) -> list[str]:
    """Get list of project IDs the user has access to."""
    from app.services.analytics.scopes import ScopeResolver

    resolved = await ScopeResolver(db, user).resolve(scope="user", scope_id=None)
    return resolved.project_ids or []


async def _resolve_active_scan_ids(
    projects: list[Any],
    db: AsyncIOMotorDatabase,
) -> dict[str, str]:
    """Resolve latest scan ID per project, excluding scans from deleted branches."""
    return await ScanRepository(db).get_latest_active_scan_ids(projects)


async def get_latest_scan_ids(project_ids: list[str], db: AsyncIOMotorDatabase) -> list[str]:
    """Get latest scan IDs for given projects, excluding scans from deleted branches."""
    project_repo = ProjectRepository(db)
    projects = await project_repo.find_many_with_scan_id(
        {"_id": {"$in": project_ids}},
        limit=ANALYTICS_MAX_QUERY_LIMIT,
    )

    resolved = await _resolve_active_scan_ids(projects, db)
    return list(resolved.values())


async def get_projects_with_scans(project_ids: list[str], db: AsyncIOMotorDatabase) -> tuple[dict[str, str], list[str]]:
    """Return (project_name_map, scan_ids), excluding scans from deleted branches."""
    project_repo = ProjectRepository(db)
    projects = await project_repo.find_many_with_scan_id(
        {"_id": {"$in": project_ids}},
        limit=ANALYTICS_MAX_QUERY_LIMIT,
    )

    project_name_map = {p.id: p.name for p in projects}
    resolved = await _resolve_active_scan_ids(projects, db)

    return project_name_map, list(resolved.values())


def calculate_days_until_due(kev_due_date: str | None) -> int | None:
    """Calculate days until KEV due date (negative = overdue)."""
    if not kev_due_date:
        return None
    try:
        due = datetime.strptime(kev_due_date, "%Y-%m-%d").replace(tzinfo=timezone.utc).date()
        return (due - datetime.now(timezone.utc).date()).days
    except Exception:
        return None


def calculate_days_known(first_seen: datetime | None) -> int | None:
    """Calculate how many days a vulnerability has been known."""
    if not first_seen or not isinstance(first_seen, datetime):
        return None
    try:
        return (datetime.now(first_seen.tzinfo or None) - first_seen).days
    except Exception:
        return None


def extract_fix_versions(details_list: list[Any]) -> set:
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


def process_cve_enrichments(finding_ids: list[str], enrichments: dict[str, Any]) -> CVEEnrichmentResult:
    """Process CVE enrichment data and extract the maximum/worst-case values."""
    result = CVEEnrichmentResult()

    for fid in finding_ids:
        if fid not in enrichments:
            continue

        enr = enrichments[fid]

        if enr.epss_score is not None and (result.max_epss is None or enr.epss_score > result.max_epss):
            result.max_epss = enr.epss_score
            result.max_percentile = enr.epss_percentile

        if enr.risk_score is not None and (result.max_risk is None or enr.risk_score > result.max_risk):
            result.max_risk = enr.risk_score

        if enr.is_kev:
            result.has_kev = True
            result.kev_count += 1
            if enr.kev_ransomware_use:
                result.kev_ransomware_use = True
            if enr.kev_due_date and (result.kev_due_date is None or enr.kev_due_date < result.kev_due_date):
                result.kev_due_date = enr.kev_due_date

        if EXPLOIT_MATURITY_ORDER.get(enr.exploit_maturity, 0) > EXPLOIT_MATURITY_ORDER.get(result.exploit_maturity, 0):
            result.exploit_maturity = enr.exploit_maturity

    return result


def _calculate_kev_boost(enrichment_data: CVEEnrichmentResult) -> float:
    """Calculate the KEV-based boost multiplier for impact scoring."""
    if not enrichment_data.has_kev:
        return 1.0

    if enrichment_data.kev_ransomware_use:
        return KEV_RANSOMWARE_BOOST

    days_until_due = enrichment_data.days_until_due
    if days_until_due is not None and days_until_due < 0:
        return KEV_OVERDUE_BOOST
    if days_until_due is not None and days_until_due <= KEV_DUE_SOON_DAYS:
        return KEV_DUE_SOON_BOOST

    return KEV_DEFAULT_BOOST


def _calculate_epss_boost(max_epss: float | None) -> float:
    """Calculate the EPSS-based boost multiplier for impact scoring."""
    if not max_epss:
        return 1.0

    if max_epss >= EPSS_VERY_HIGH_THRESHOLD:
        return EPSS_VERY_HIGH_BOOST
    if max_epss >= EPSS_HIGH_THRESHOLD:
        return EPSS_HIGH_BOOST
    if max_epss >= EPSS_MEDIUM_THRESHOLD:
        return EPSS_MEDIUM_BOOST

    return 1.0


def impact_pre_score(severity_counts: dict[str, int], affected_projects: int) -> float:
    """Un-boosted severity*reach base of the impact score. Every boost is >= 1.0, so this
    is a provable lower bound on the final fix_impact_score (and base * IMPACT_MAX_SCORE_BOOST
    its upper bound)."""
    # severity_counts may use lowercase or original-case keys
    severity_score = sum(
        severity_counts.get(sev.lower(), severity_counts.get(sev, 0)) * weight
        for sev, weight in SEVERITY_WEIGHTS.items()
    )
    reach_multiplier = min(affected_projects, IMPACT_REACH_MULTIPLIER_CAP)
    return float(severity_score * reach_multiplier)


_IMPACT_SEVERITY_BUCKETS = ("critical", "high", "medium", "low")


def _row_pre_score(row: dict[str, Any]) -> float:
    counts = {b: int(row.get(b) or 0) for b in _IMPACT_SEVERITY_BUCKETS}
    return impact_pre_score(counts, int(row.get("affected_projects") or 0))


def select_impact_candidates(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Group rows that can still reach the top `limit` by fix_impact_score.

    Ranking is by the final boosted score, but the boosts (KEV/EPSS/maturity) come from
    enrichment, not Mongo — so enriching every group is what made the old endpoint drop
    severe-but-narrow fixes once a blast-radius $limit truncated the set first. Instead we
    rank by the pre-score lower bound and keep every row whose boosted ceiling
    (pre_score * IMPACT_MAX_SCORE_BOOST) could still beat the limit-th pre-score. Enrichment
    then runs only on real contenders, and no true top-`limit` fix is ever excluded.
    """
    scored = sorted(((_row_pre_score(r), r) for r in rows), key=lambda t: t[0], reverse=True)
    if len(scored) <= limit:
        return [r for _, r in scored]
    p_limit = scored[limit - 1][0]
    threshold = p_limit / IMPACT_MAX_SCORE_BOOST
    return [r for score, r in scored if score >= threshold]


def calculate_impact_score(
    severity_counts: dict[str, int],
    affected_projects: int,
    enrichment_data: CVEEnrichmentResult,
    has_fix: bool,
    days_known: int | None,
) -> float:
    """Calculate fix impact score based on severity, reach, and threat intelligence."""
    base_impact = impact_pre_score(severity_counts, affected_projects)

    base_impact *= _calculate_kev_boost(enrichment_data)
    base_impact *= _calculate_epss_boost(enrichment_data.max_epss)
    base_impact *= EXPLOIT_MATURITY_BOOST.get(enrichment_data.exploit_maturity, 1.0)

    if has_fix:
        base_impact *= IMPACT_FIX_AVAILABLE_BOOST

    if days_known and days_known > DAYS_KNOWN_OVERDUE_THRESHOLD:
        base_impact *= IMPACT_AGE_BOOST

    return base_impact


def build_priority_reasons(
    severity_counts: dict[str, int],
    enrichment_data: CVEEnrichmentResult,
    affected_projects: int,
    has_fix: bool,
    days_known: int | None,
) -> list[str]:
    """Build human-readable priority reasons list."""
    reasons = []
    days_until_due = enrichment_data.days_until_due
    max_epss = enrichment_data.max_epss

    if enrichment_data.kev_ransomware_use:
        reasons.append("ransomware:Used in ransomware campaigns - fix immediately")

    if days_until_due is not None and days_until_due < 0:
        reasons.append(f"deadline_overdue:CISA deadline overdue by {abs(days_until_due)} days")
    elif days_until_due is not None and days_until_due <= KEV_DUE_SOON_DAYS:
        reasons.append(f"deadline:CISA deadline in {days_until_due} days")

    if enrichment_data.has_kev and not enrichment_data.kev_ransomware_use:
        reasons.append("kev:Actively exploited in the wild (CISA KEV)")

    if max_epss and max_epss >= EPSS_HIGH_THRESHOLD:
        reasons.append(f"epss:High exploitation probability ({max_epss * 100:.1f}% EPSS)")

    if severity_counts.get("critical", 0) > 0:
        reasons.append(f"critical:{severity_counts['critical']} critical vulnerabilities")

    if affected_projects >= BLAST_RADIUS_THRESHOLD:
        reasons.append(f"blast_radius:Affects {affected_projects} projects (high blast radius)")

    if has_fix:
        reasons.append("fix_available:Fix available - easy to remediate")

    if days_known and days_known > DAYS_KNOWN_OVERDUE_THRESHOLD:
        reasons.append(f"overdue:Known for {days_known} days - overdue for remediation")

    return reasons


def count_severities(severities: list[str | None]) -> dict[str, int]:
    """Count severities from a list."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev in severities:
        if sev:
            sev_lower = sev.lower()
            if sev_lower in counts:
                counts[sev_lower] += 1
    return counts


def build_findings_severity_map(
    findings: list[Any],
) -> dict[str, dict[str, int]]:
    """Map component names to their severity counts, plus unambiguous bare-artifact aliases."""
    findings_map: dict[str, dict[str, int]] = {}

    for finding in findings:
        component = get_attr(finding, "component")
        if not component:
            continue

        severity = get_attr(finding, "severity", "UNKNOWN")

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

    return build_component_index(findings_map)


def build_hotspot_priority_reasons(
    enrichment_data: CVEEnrichmentResult,
    severity_counts: dict[str, int],
    has_fix: bool,
    days_until_due: int | None,
) -> list[str]:
    """Build priority reasons for vulnerability hotspots."""
    reasons = []

    if enrichment_data.kev_ransomware_use:
        reasons.append("ransomware:Used in ransomware campaigns")

    if days_until_due is not None and days_until_due < 0:
        reasons.append(f"deadline_overdue:CISA deadline overdue by {abs(days_until_due)} days")
    elif days_until_due is not None and days_until_due <= KEV_DUE_SOON_DAYS:
        reasons.append(f"deadline:CISA deadline in {days_until_due} days")

    if enrichment_data.has_kev and not enrichment_data.kev_ransomware_use:
        reasons.append("kev:Actively exploited (CISA KEV)")

    max_epss = enrichment_data.max_epss
    if max_epss and max_epss >= EPSS_HIGH_THRESHOLD:
        reasons.append(f"epss:High EPSS ({max_epss * 100:.1f}%)")

    if severity_counts.get("critical", 0) > 0:
        reasons.append(f"critical:{severity_counts['critical']} critical vulns")

    if has_fix:
        reasons.append("fix_available:Fix available")

    return reasons


def cross_project_cve_pipeline(scan_ids: list[str]) -> list[dict[str, Any]]:
    """CVE ids per scan; they only exist nested in details.vulnerabilities[].id."""
    return [
        {
            MONGO_MATCH: {
                "scan_id": {"$in": scan_ids},
                "type": "vulnerability",
            }
        },
        {"$unwind": "$details.vulnerabilities"},
        {
            MONGO_GROUP: {
                "_id": "$scan_id",
                "cves": {"$addToSet": "$details.vulnerabilities.id"},
            }
        },
    ]


async def gather_cross_project_data(
    user_project_ids: list[str],
    current_project_id: str,
    db: AsyncIOMotorDatabase,
) -> dict[str, Any] | None:
    """Gather cross-project vulnerability and dependency data for shared-vuln analysis.

    Returns None if the user has one project or fewer.
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

    cross_project_data: dict[str, Any] = {
        "projects": [],
        "total_projects": len(user_project_ids),
    }

    # Cap at 20 other projects for performance
    other_project_ids = [pid for pid in user_project_ids if pid != current_project_id][:20]

    other_projects = await project_repo.find_many_with_scan_id(
        {"_id": {"$in": other_project_ids}},
        limit=len(other_project_ids),
    )
    project_info_map = {p.id: p for p in other_projects}

    resolved_scans = await _resolve_active_scan_ids(other_projects, db)

    scan_id_to_project: dict[str, str] = {}
    for proj_id, scan_id in resolved_scans.items():
        scan_id_to_project[scan_id] = proj_id

    other_scan_ids = list(scan_id_to_project.keys())

    if not other_scan_ids:
        return cross_project_data

    other_scans = await scan_repo.find_many_with_stats(
        {"_id": {"$in": other_scan_ids}},
        limit=len(other_scan_ids),
    )
    scan_stats_map = {s.id: s.stats for s in other_scans if s.stats}

    cve_results = await finding_repo.aggregate(cross_project_cve_pipeline(other_scan_ids))
    scan_cves_map = {r["_id"]: [c for c in r["cves"] if c] for r in cve_results}

    pkg_pipeline: list[dict[str, Any]] = [
        {MONGO_MATCH: {"scan_id": {"$in": other_scan_ids}}},
        {
            MONGO_GROUP: {
                "_id": "$scan_id",
                "packages": {"$push": {"name": "$name", "version": "$version"}},
            }
        },
        {"$project": {"_id": 1, "packages": {"$slice": ["$packages", 100]}}},
    ]
    pkg_results = await dep_repo.aggregate(pkg_pipeline)
    scan_pkgs_map = {r["_id"]: r["packages"] for r in pkg_results}

    for scan_id, proj_id in scan_id_to_project.items():
        proj_info = project_info_map.get(proj_id)
        stats = scan_stats_map.get(scan_id)

        cross_project_data["projects"].append(
            {
                "project_id": proj_id,
                "project_name": proj_info.name if proj_info else "Unknown",
                "cves": scan_cves_map.get(scan_id, []),
                "packages": scan_pkgs_map.get(scan_id, []),
                "total_critical": stats.critical if stats else 0,
                "total_high": stats.high if stats else 0,
            }
        )

    return cross_project_data
