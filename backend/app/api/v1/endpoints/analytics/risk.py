"""Analytics risk endpoints: /impact and /hotspots."""

import hashlib
import logging
from datetime import datetime
from typing import Annotated, Any

from fastapi import Query

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    ReleaseEnvironmentQuery,
    build_hotspot_priority_reasons,
    build_priority_reasons,
    calculate_days_known,
    calculate_days_until_due,
    calculate_impact_score,
    extract_fix_versions,
    get_projects_with_scans,
    get_user_projects,
    historical_first_seen,
    process_cve_enrichments,
    require_analytics_permission,
    select_impact_candidates,
    severity_counts_from_details,
    SLIM_DETAILS_EXPR,
)
from app.api.v1.helpers.responses import RESP_AUTH
from app.api.v1.helpers.sorting import SortOrderQuery, parse_sort_direction
from app.core.constants import ANALYTICS_MAX_QUERY_LIMIT
from app.core.permissions import Permissions
from app.repositories.dependencies import DependencyRepository
from app.repositories.findings import FindingRepository
from app.schemas.analytics import (
    ImpactAnalysisResult,
    SeverityBreakdown,
    VulnerabilityHotspot,
)
from app.services.component_identity import (
    build_component_index,
    component_name_candidates,
    lookup_component,
)
from app.services.analytics.cache import get_analytics_cache
from app.services.aggregation.versions import newest_first
from app.services.enrichment.service import vulnerability_enrichment_service
from app.services.recommendation.common import live_cves

logger = logging.getLogger(__name__)

router = CustomAPIRouter()


def _scope_digest(project_ids: list[str], scan_ids: list[str]) -> str:
    """Stable key over the caller's accessible projects and their active scans. Keying on the
    scan set auto-invalidates on a new scan; waiver mutations flush the whole cache separately."""
    h = hashlib.sha256()
    h.update(",".join(sorted(project_ids)).encode())
    h.update(b"|")
    h.update(",".join(sorted(scan_ids)).encode())
    return h.hexdigest()[:16]


# Samples named on a card; each is returned beside the population it was drawn from, so a reader
# acting on the list knows whether it is the whole of what the row found.
_AFFECTED_PROJECTS_SHOWN = 5
_HOTSPOT_PROJECTS_SHOWN = 10
_FIX_VERSIONS_SHOWN = 3
_CVES_SHOWN = 5


@router.get("/impact", responses=RESP_AUTH)
async def get_impact_analysis(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    release_environment: ReleaseEnvironmentQuery = None,
) -> list[ImpactAnalysisResult]:
    """Analyze which dependency fixes would have the highest impact across projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_IMPACT)

    finding_repo = FindingRepository(db)

    projects = await get_user_projects(current_user, db)
    if not projects:
        return []
    project_ids = [p.id for p in projects]

    project_name_map, scan_ids = await get_projects_with_scans(projects, db, release_environment=release_environment)
    if not scan_ids:
        return []

    cache = get_analytics_cache()
    cache_key = ("impact", _scope_digest(project_ids, scan_ids), limit)
    hit, cached = cache.get(cache_key)
    if hit:
        return [ImpactAnalysisResult.model_validate(r) for r in cached]

    pipeline: list[dict[str, Any]] = [
        {"$match": {"scan_id": {"$in": scan_ids}, "type": "vulnerability", "waived": {"$ne": True}}},
        {
            "$project": {
                "component": 1,
                "version": 1,
                "project_id": 1,
                "severity": 1,
                "finding_id": 1,
                "scan_created_at": 1,
                "details": SLIM_DETAILS_EXPR,
            }
        },
        {
            "$group": {
                "_id": {"component": "$component", "version": "$version"},
                "project_ids": {"$addToSet": "$project_id"},
                "first_seen": {"$min": "$scan_created_at"},
                # $addToSet collapses the (usually identical) per-project advisory lists to the
                # distinct variants; distinct-CVE counts, severity and enrichment derive from these.
                "details_list": {"$addToSet": "$details"},
            }
        },
        {
            "$project": {
                "component": "$_id.component",
                "version": "$_id.version",
                "project_ids": 1,
                "first_seen": 1,
                "details_list": 1,
                "affected_projects": {"$size": "$project_ids"},
            }
        },
        {"$limit": ANALYTICS_MAX_QUERY_LIMIT},
    ]

    results = await finding_repo.aggregate(pipeline, allow_disk_use=True)

    # Severity/vuln counts come from the advisory lists (finding_id is only component:version).
    for r in results:
        r["_severity_counts"] = severity_counts_from_details(r.get("details_list", []))

    # Rank/limit happen in Python on fix_impact_score; enrich only the groups that can still reach
    # the top `limit` by boosted score.
    candidates = select_impact_candidates(results, limit)

    all_cves = list({cve for r in candidates for cve in live_cves(r.get("details_list", []))})

    enrichments = {}
    if all_cves:
        try:
            enrichments = await vulnerability_enrichment_service.enrich_cves(all_cves)
        except Exception as e:
            logger.warning(f"Failed to enrich CVEs: {e}")

    first_seen_map = await historical_first_seen(finding_repo, [r["component"] for r in candidates])

    impact_results = []
    for r in candidates:
        severity_counts = r["_severity_counts"]
        total_findings = sum(severity_counts.values())
        fix_versions = extract_fix_versions(r.get("details_list", []), r.get("version"))
        has_fix = len(fix_versions) > 0

        enrichment_data = process_cve_enrichments(live_cves(r.get("details_list", [])), enrichments)

        first_seen = first_seen_map.get((r["component"], r.get("version") or "unknown"), r.get("first_seen"))
        days_known = calculate_days_known(first_seen)
        days_until_due = calculate_days_until_due(enrichment_data.kev_due_date)
        enrichment_data.days_until_due = days_until_due

        base_impact = calculate_impact_score(
            severity_counts,
            r["affected_projects"],
            enrichment_data,
            has_fix,
            days_known,
        )

        # Filter to accessible projects to avoid leaking project names.
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
                total_findings=total_findings,
                findings_by_severity=SeverityBreakdown.from_counts(severity_counts),
                fix_impact_score=base_impact,
                affected_project_names=[
                    project_name_map.get(pid, "Unknown")
                    for pid in accessible_impact_project_ids[:_AFFECTED_PROJECTS_SHOWN]
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
                fix_versions=newest_first(fix_versions)[:_FIX_VERSIONS_SHOWN],
                fix_version_count=len(fix_versions),
                priority_reasons=priority_reasons,
            )
        )

    impact_results.sort(key=lambda x: x.fix_impact_score, reverse=True)

    top = impact_results[:limit]
    cache.set(cache_key, [r.model_dump() for r in top])
    return top


def _format_first_seen(first_seen: Any) -> str:
    if not first_seen:
        return ""
    if isinstance(first_seen, datetime):
        return first_seen.isoformat()
    return str(first_seen)


def _build_hotspot(
    r: dict[str, Any],
    enrichments: dict[str, Any],
    version_type_index: dict[str, set[str]],
    type_index: dict[str, set[str]],
    project_name_map: dict[str, str],
    project_ids: list[str],
) -> VulnerabilityHotspot:
    details_list = r.get("details_list", [])
    severity_counts = severity_counts_from_details(details_list)
    fix_versions = extract_fix_versions(details_list, r["_id"].get("version"))
    has_fix = len(fix_versions) > 0
    component = r["_id"]["component"]
    # One name at one version can ship in several ecosystems (a deb and an apk openssl); name them all.
    types = lookup_component(version_type_index, component) or lookup_component(type_index, component)
    dep_type = "/".join(sorted(types)) if types else "unknown"

    first_seen_str = _format_first_seen(r.get("first_seen"))
    days_known = calculate_days_known(r.get("first_seen"))

    cves = live_cves(details_list)
    top_cves = cves[:_CVES_SHOWN]

    enrichment_data = process_cve_enrichments(cves, enrichments)
    days_until_due = calculate_days_until_due(enrichment_data.kev_due_date)
    priority_reasons = build_hotspot_priority_reasons(enrichment_data, severity_counts, has_fix, days_until_due)

    accessible_affected_projects = [pid for pid in r["project_ids"] if pid in project_ids]

    return VulnerabilityHotspot(
        component=r["_id"]["component"],
        version=r["_id"].get("version") or "unknown",
        type=dep_type,
        finding_count=sum(severity_counts.values()),
        severity_breakdown=SeverityBreakdown.from_counts(severity_counts),
        affected_projects=[
            project_name_map.get(pid, "Unknown") for pid in accessible_affected_projects[:_HOTSPOT_PROJECTS_SHOWN]
        ],
        affected_project_count=len(accessible_affected_projects),
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
        fix_versions=newest_first(fix_versions)[:_FIX_VERSIONS_SHOWN],
        fix_version_count=len(fix_versions),
        top_cves=top_cves,
        cve_count=len(cves),
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
    sort_order: SortOrderQuery = "desc",
    release_environment: ReleaseEnvironmentQuery = None,
) -> list[VulnerabilityHotspot]:
    """Get dependencies with the most vulnerabilities (hotspots)."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_HOTSPOTS)

    finding_repo = FindingRepository(db)
    dep_repo = DependencyRepository(db)

    projects = await get_user_projects(current_user, db)
    if not projects:
        return []
    project_ids = [p.id for p in projects]

    project_name_map, scan_ids = await get_projects_with_scans(projects, db, release_environment=release_environment)
    if not scan_ids:
        return []

    cache = get_analytics_cache()
    cache_key = ("hotspots", _scope_digest(project_ids, scan_ids), sort_by, sort_order, skip, limit)
    hit, cached = cache.get(cache_key)
    if hit:
        return [VulnerabilityHotspot.model_validate(r) for r in cached]

    sort_direction = parse_sort_direction(sort_order)
    # finding_count/epss/risk are derived in Python (from advisories / enrichment), so they are
    # sorted and paginated in Python; only component/first_seen can be ordered in Mongo.
    mongo_sort_field = {"component": "_id.component", "first_seen": "first_seen"}.get(sort_by)
    post_sort_by = sort_by if sort_by in ("finding_count", "epss", "risk") else None

    pipeline: list[dict[str, Any]] = [
        {"$match": {"scan_id": {"$in": scan_ids}, "type": "vulnerability", "waived": {"$ne": True}}},
        {
            "$project": {
                "component": 1,
                "version": 1,
                "project_id": 1,
                "scan_created_at": 1,
                "details": SLIM_DETAILS_EXPR,
            }
        },
        {
            "$group": {
                "_id": {"component": "$component", "version": "$version"},
                "project_ids": {"$addToSet": "$project_id"},
                "first_seen": {"$min": "$scan_created_at"},
                # $addToSet collapses the (usually identical) per-project advisory lists; counts,
                # severity and enrichment derive from these in Python.
                "details_list": {"$addToSet": "$details"},
            }
        },
    ]

    if mongo_sort_field:
        pipeline.append({"$sort": {mongo_sort_field: sort_direction}})
        pipeline.append({"$skip": skip})
        pipeline.append({"$limit": limit})

    results = await finding_repo.aggregate(pipeline, allow_disk_use=True)

    all_cves = list({cve for r in results for cve in live_cves(r.get("details_list", []))})

    enrichments = {}
    if all_cves:
        try:
            enrichments = await vulnerability_enrichment_service.enrich_cves(all_cves)
        except Exception as e:
            logger.warning(f"Failed to enrich CVEs: {e}")

    # A component can be group-qualified while the inventory keeps the bare artifact name,
    # so both spellings go into the filter and the index resolves either way.
    candidates = list({name for r in results for name in component_name_candidates(r["_id"]["component"])})
    type_pipeline: list[dict[str, Any]] = [
        {"$match": {"scan_id": {"$in": scan_ids}, "name": {"$in": candidates}}},
        {
            "$group": {
                "_id": {"name": "$name", "version": {"$ifNull": ["$version", "unknown"]}},
                "types": {"$addToSet": {"$ifNull": ["$type", "unknown"]}},
            }
        },
    ]
    types_by_version: dict[str, dict[str, set[str]]] = {}
    types_by_name: dict[str, set[str]] = {}
    for row in await dep_repo.aggregate(type_pipeline):
        name, version = row["_id"]["name"], row["_id"]["version"]
        types_by_version.setdefault(version, {})[name] = set(row["types"])
        types_by_name.setdefault(name, set()).update(row["types"])
    type_index_by_version = {version: build_component_index(types) for version, types in types_by_version.items()}
    type_index = build_component_index(types_by_name)

    hotspots = [
        _build_hotspot(
            r,
            enrichments,
            type_index_by_version.get(r["_id"].get("version") or "unknown", {}),
            type_index,
            project_name_map,
            project_ids,
        )
        for r in results
    ]

    _post_sort_keys = {
        "finding_count": lambda x: x.finding_count,
        "epss": lambda x: x.max_epss_score or 0,
        "risk": lambda x: x.max_risk_score or 0,
    }
    if post_sort_by:
        hotspots.sort(key=_post_sort_keys[post_sort_by], reverse=sort_direction == -1)
        hotspots = hotspots[skip : skip + limit]

    # first_seen/days_known off the active scans is only the current scan's age; replace it on the
    # displayed page with the vulnerability's true first detection across all scans.
    first_seen_map = await historical_first_seen(finding_repo, [h.component for h in hotspots])
    for h in hotspots:
        hist = first_seen_map.get((h.component, h.version))
        if hist is not None:
            h.first_seen = _format_first_seen(hist)
            h.days_known = calculate_days_known(hist)

    cache.set(cache_key, [h.model_dump() for h in hotspots])
    return hotspots
