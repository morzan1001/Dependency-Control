"""Analytics risk endpoints: /impact and /hotspots."""

import logging
from datetime import datetime
from typing import Annotated, Any, Dict, List

from fastapi import Query

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    build_hotspot_priority_reasons,
    build_priority_reasons,
    calculate_days_known,
    calculate_days_until_due,
    calculate_impact_score,
    count_severities,
    extract_fix_versions,
    get_projects_with_scans,
    get_user_project_ids,
    process_cve_enrichments,
    require_analytics_permission,
)
from app.api.v1.helpers.responses import RESP_AUTH
from app.core.permissions import Permissions
from app.repositories import (
    DependencyRepository,
    FindingRepository,
)
from app.schemas.analytics import (
    ImpactAnalysisResult,
    SeverityBreakdown,
    VulnerabilityHotspot,
)
from app.services.enrichment import get_cve_enrichment

logger = logging.getLogger(__name__)

router = CustomAPIRouter()


@router.get("/impact", responses=RESP_AUTH)
async def get_impact_analysis(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> List[ImpactAnalysisResult]:
    """Analyze which dependency fixes would have the highest impact across projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_IMPACT)

    finding_repo = FindingRepository(db)

    project_ids = await get_user_project_ids(current_user, db)
    if not project_ids:
        return []

    project_name_map, scan_ids = await get_projects_with_scans(project_ids, db)
    if not scan_ids:
        return []

    pipeline: List[Dict[str, Any]] = [
        {"$match": {"scan_id": {"$in": scan_ids}, "type": "vulnerability"}},
        {
            "$group": {
                "_id": {"component": "$component", "version": "$version"},
                "project_ids": {"$addToSet": "$project_id"},
                "total_findings": {"$sum": 1},
                "severities": {"$push": "$severity"},
                "finding_ids": {"$push": "$finding_id"},
                "first_seen": {"$min": "$created_at"},
                "details_list": {"$push": "$details"},
            }
        },
        {
            "$project": {
                "component": "$_id.component",
                "version": "$_id.version",
                "project_ids": 1,
                "total_findings": 1,
                "severities": 1,
                "finding_ids": 1,
                "first_seen": 1,
                "details_list": 1,
                "affected_projects": {"$size": "$project_ids"},
            }
        },
        {"$sort": {"affected_projects": -1, "total_findings": -1}},
        {"$limit": limit},
    ]

    results = await finding_repo.aggregate(pipeline)

    all_cves = [fid for r in results for fid in r.get("finding_ids", []) if fid and fid.startswith("CVE-")]

    enrichments = {}
    if all_cves:
        try:
            enrichments = await get_cve_enrichment(all_cves)
        except Exception as e:
            logger.warning(f"Failed to enrich CVEs: {e}")

    impact_results = []
    for r in results:
        severity_counts = count_severities(r.get("severities", []))
        fix_versions = extract_fix_versions(r.get("details_list", []))
        has_fix = len(fix_versions) > 0

        finding_ids = [fid for fid in r.get("finding_ids", []) if fid and fid.startswith("CVE-")]
        enrichment_data = process_cve_enrichments(finding_ids, enrichments)

        days_known = calculate_days_known(r.get("first_seen"))
        days_until_due = calculate_days_until_due(enrichment_data.kev_due_date)
        enrichment_data.days_until_due = days_until_due

        base_impact = calculate_impact_score(
            severity_counts,
            r["affected_projects"],
            enrichment_data,
            has_fix,
            days_known,
        )

        # Filter to accessible projects only — prevents leaking project names
        # the user doesn't have access to.
        accessible_impact_project_ids = [pid for pid in r["project_ids"] if pid in project_ids]

        priority_reasons = build_priority_reasons(
            severity_counts,
            enrichment_data,
            len(accessible_impact_project_ids),
            has_fix,
            days_known,
        )

        impact_results.append(
            ImpactAnalysisResult(
                component=r["component"],
                version=r.get("version") or "unknown",
                affected_projects=len(accessible_impact_project_ids),
                total_findings=r["total_findings"],
                findings_by_severity=SeverityBreakdown(**severity_counts),
                fix_impact_score=base_impact,
                affected_project_names=[
                    project_name_map.get(pid, "Unknown") for pid in accessible_impact_project_ids[:5]
                ],
                max_epss_score=enrichment_data.max_epss,
                epss_percentile=enrichment_data.max_percentile,
                has_kev=enrichment_data.has_kev,
                kev_count=enrichment_data.kev_count,
                kev_ransomware_use=enrichment_data.kev_ransomware_use,
                kev_due_date=enrichment_data.kev_due_date,
                days_until_due=days_until_due,
                exploit_maturity=enrichment_data.exploit_maturity,
                max_risk_score=enrichment_data.max_risk,
                days_known=days_known,
                has_fix=has_fix,
                fix_versions=list(fix_versions)[:3],
                priority_reasons=priority_reasons,
            )
        )

    impact_results.sort(key=lambda x: x.fix_impact_score, reverse=True)

    return impact_results


def _format_first_seen(first_seen: Any) -> str:
    if not first_seen:
        return ""
    if isinstance(first_seen, datetime):
        return first_seen.isoformat()
    return str(first_seen)


def _build_hotspot(
    r: Dict[str, Any],
    enrichments: Dict[str, Any],
    dep_type_map: Dict[str, str],
    project_name_map: Dict[str, str],
    project_ids: List[str],
) -> VulnerabilityHotspot:
    severity_counts = count_severities(r.get("severities", []))
    fix_versions = extract_fix_versions(r.get("details_list", []))
    has_fix = len(fix_versions) > 0
    dep_type = dep_type_map.get(r["_id"]["component"], "unknown")

    first_seen_str = _format_first_seen(r.get("first_seen"))
    days_known = calculate_days_known(r.get("first_seen"))

    finding_ids = r.get("finding_ids", [])
    top_cves = list(dict.fromkeys(fid for fid in finding_ids if fid and fid.startswith("CVE-")))[:5]

    cve_finding_ids = [fid for fid in finding_ids if fid and fid.startswith("CVE-")]
    enrichment_data = process_cve_enrichments(cve_finding_ids, enrichments)
    days_until_due = calculate_days_until_due(enrichment_data.kev_due_date)
    priority_reasons = build_hotspot_priority_reasons(enrichment_data, severity_counts, has_fix, days_until_due)

    accessible_affected_projects = [pid for pid in r["project_ids"] if pid in project_ids]

    return VulnerabilityHotspot(
        component=r["_id"]["component"],
        version=r["_id"].get("version") or "unknown",
        type=dep_type,
        finding_count=r["finding_count"],
        severity_breakdown=SeverityBreakdown(**severity_counts),
        affected_projects=[project_name_map.get(pid, "Unknown") for pid in accessible_affected_projects[:10]],
        first_seen=first_seen_str,
        max_epss_score=enrichment_data.max_epss,
        epss_percentile=enrichment_data.max_percentile,
        has_kev=enrichment_data.has_kev,
        kev_count=enrichment_data.kev_count,
        kev_ransomware_use=enrichment_data.kev_ransomware_use,
        kev_due_date=enrichment_data.kev_due_date,
        days_until_due=days_until_due,
        exploit_maturity=enrichment_data.exploit_maturity,
        max_risk_score=enrichment_data.max_risk,
        days_known=days_known,
        has_fix=has_fix,
        fix_versions=list(fix_versions)[:3],
        top_cves=top_cves,
        priority_reasons=priority_reasons,
    )


@router.get("/hotspots", responses=RESP_AUTH)
async def get_vulnerability_hotspots(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    skip: Annotated[int, Query(ge=0, description="Number of records to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    sort_by: Annotated[
        str,
        Query(description="Sort field: finding_count, component, first_seen, epss, risk"),
    ] = "finding_count",
    sort_order: Annotated[str, Query(description="Sort order: asc, desc")] = "desc",
) -> List[VulnerabilityHotspot]:
    """Get dependencies with the most vulnerabilities (hotspots)."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_HOTSPOTS)

    finding_repo = FindingRepository(db)
    dep_repo = DependencyRepository(db)

    project_ids = await get_user_project_ids(current_user, db)
    if not project_ids:
        return []

    project_name_map, scan_ids = await get_projects_with_scans(project_ids, db)
    if not scan_ids:
        return []

    sort_direction = -1 if sort_order == "desc" else 1
    sort_field_map = {
        "finding_count": "finding_count",
        "component": "_id.component",
        "first_seen": "first_seen",
    }
    mongo_sort_field = sort_field_map.get(sort_by, "finding_count")
    post_sort_by = sort_by if sort_by in ["epss", "risk"] else None

    pipeline: List[Dict[str, Any]] = [
        {"$match": {"scan_id": {"$in": scan_ids}, "type": "vulnerability"}},
        {
            "$group": {
                "_id": {"component": "$component", "version": "$version"},
                "project_ids": {"$addToSet": "$project_id"},
                "finding_count": {"$sum": 1},
                "severities": {"$push": "$severity"},
                "first_seen": {"$min": "$created_at"},
                "finding_ids": {"$push": "$finding_id"},
                "details_list": {"$push": "$details"},
            }
        },
        {"$sort": {mongo_sort_field: sort_direction}},
    ]

    if post_sort_by:
        # epss/risk live in enrichment data, so we re-sort post-fetch in Python
        # and over-fetch to keep page sizes meaningful after the re-sort.
        pipeline.append({"$limit": limit * 3})
    else:
        pipeline.append({"$skip": skip})
        pipeline.append({"$limit": limit})

    results = await finding_repo.aggregate(pipeline)

    all_cves = list({fid for r in results for fid in r.get("finding_ids", []) if fid and fid.startswith("CVE-")})

    enrichments = {}
    if all_cves:
        try:
            enrichments = await get_cve_enrichment(all_cves)
        except Exception as e:
            logger.warning(f"Failed to enrich CVEs: {e}")

    component_names = list({r["_id"]["component"] for r in results})
    type_pipeline: List[Dict[str, Any]] = [
        {"$match": {"name": {"$in": component_names}}},
        {"$group": {"_id": "$name", "type": {"$first": "$type"}}},
    ]
    type_results = await dep_repo.aggregate(type_pipeline, limit=len(component_names) + 1)
    dep_type_map = {d["_id"]: d.get("type", "unknown") for d in type_results}

    hotspots = [_build_hotspot(r, enrichments, dep_type_map, project_name_map, project_ids) for r in results]

    if post_sort_by == "epss":
        hotspots.sort(key=lambda x: x.max_epss_score or 0, reverse=(sort_order == "desc"))
        hotspots = hotspots[skip : skip + limit]
    elif post_sort_by == "risk":
        hotspots.sort(key=lambda x: x.max_risk_score or 0, reverse=(sort_order == "desc"))
        hotspots = hotspots[skip : skip + limit]

    return hotspots
