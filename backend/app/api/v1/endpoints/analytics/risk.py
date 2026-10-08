"""Analytics risk endpoints: /impact and /hotspots."""

import logging
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import Query
from motor.motor_asyncio import AsyncIOMotorDatabase

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
    impact_pre_score,
    process_cve_enrichments,
    require_analytics_permission,
    select_impact_candidates,
    severity_counts_from_details,
    SLIM_DETAILS_EXPR,
)
from app.api.v1.helpers.responses import RESP_AUTH
from app.api.v1.helpers.sorting import SortOrder, SortOrderQuery, parse_sort_direction
from app.core.cache import scope_digest
from app.core.constants import ANALYTICS_MAX_QUERY_LIMIT
from app.core.permissions import Permissions
from app.repositories.dependencies import DependencyRepository
from app.repositories.findings import FindingRepository
from app.schemas.analytics import (
    ImpactAnalysisResult,
    SeverityBreakdown,
    VulnerabilityHotspot,
)
from app.schemas.enrichment import VulnerabilityEnrichment
from app.schemas.projections import ProjectWithScanId
from app.services.component_identity import (
    build_component_index,
    component_name_candidates,
    lookup_component,
)
from app.services.analytics.cache import get_analytics_cache
from app.services.aggregation.versions import newest_first, normalize_version
from app.services.enrichment.service import vulnerability_enrichment_service
from app.services.recommendation.common import live_cves

logger = logging.getLogger(__name__)

router = CustomAPIRouter()


# Samples named on a card; each is returned beside the population it was drawn from, so a reader
# acting on the list knows whether it is the whole of what the row found.
_AFFECTED_PROJECTS_SHOWN = 5
_HOTSPOT_PROJECTS_SHOWN = 10
_FIX_VERSIONS_SHOWN = 3
_CVES_SHOWN = 5

# first_seen_at carries a finding's earliest detection in its project past retention; older rows lack it.
_FIRST_SEEN = {"$min": {"$ifNull": ["$first_seen_at", "$scan_created_at"]}}

HotspotSort = Literal["finding_count", "component", "first_seen", "epss", "risk"]
_MONGO_SORTS = {"component": "_id.component", "first_seen": "first_seen"}
# The other keys derive from the advisories and their enrichment, so they rank in Python.
_PYTHON_RANKS: dict[str, Callable[[dict[str, Any], Mapping[str, VulnerabilityEnrichment]], float]] = {
    "finding_count": lambda r, _enrichments: sum(severity_counts_from_details(r["details_list"]).values()),
    "epss": lambda r, enrichments: process_cve_enrichments(r["details_list"], enrichments).max_epss or 0,
    "risk": lambda r, enrichments: process_cve_enrichments(r["details_list"], enrichments).max_risk or 0,
}


def _vulnerable_groups(scan_ids: list[str]) -> list[dict[str, Any]]:
    """The live vulnerability findings of the scans, one row per component@version."""
    return [
        {"$match": {"scan_id": {"$in": scan_ids}, "type": "vulnerability", "waived": {"$ne": True}}},
        {
            "$project": {
                "component": 1,
                "version": 1,
                "project_id": 1,
                "first_seen_at": 1,
                "scan_created_at": 1,
                "details": SLIM_DETAILS_EXPR,
            }
        },
        {
            "$group": {
                "_id": {"component": "$component", "version": "$version"},
                "project_ids": {"$addToSet": "$project_id"},
                "first_seen": _FIRST_SEEN,
                # $addToSet collapses the (usually identical) per-project advisory lists to the
                # distinct variants; distinct-CVE counts, severity and enrichment derive from these.
                "details_list": {"$addToSet": "$details"},
            }
        },
    ]


async def _enrich(groups: Iterable[dict[str, Any]]) -> dict[str, VulnerabilityEnrichment]:
    """EPSS and KEV of every live CVE the groups name; supplementary, so a failure leaves them unenriched."""
    cves = list({cve for group in groups for cve in live_cves(group["details_list"])})
    if not cves:
        return {}
    try:
        return await vulnerability_enrichment_service.enrich_cves(cves)
    except Exception as e:
        logger.warning(f"Failed to enrich CVEs: {e}")
        return {}


@router.get("/impact", responses=RESP_AUTH)
async def get_impact_analysis(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    release_environment: ReleaseEnvironmentQuery = None,
) -> list[ImpactAnalysisResult]:
    """Analyze which dependency fixes would have the highest impact across projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_IMPACT)

    projects = await get_user_projects(current_user, db)
    if not projects:
        return []
    # Keyed on the scope, not its head scans: an ingest shows up once the per-pod TTL ends.
    key = ("impact", scope_digest(p.id for p in projects), release_environment, limit)
    return await get_analytics_cache().get_or_compute(key, lambda: _impact(db, projects, release_environment, limit))


async def _impact(
    db: AsyncIOMotorDatabase, projects: list[ProjectWithScanId], release_environment: str | None, limit: int
) -> list[ImpactAnalysisResult]:
    project_name_map, scan_ids = await get_projects_with_scans(projects, db, release_environment=release_environment)
    if not scan_ids:
        return []

    pipeline = [*_vulnerable_groups(scan_ids), {"$limit": ANALYTICS_MAX_QUERY_LIMIT}]
    results = await FindingRepository(db).aggregate(pipeline, allow_disk_use=True)

    # Severity/vuln counts come from the advisory lists (finding_id is only component:version).
    counted = [(r, severity_counts_from_details(r["details_list"])) for r in results]
    candidates = select_impact_candidates(
        [(impact_pre_score(counts, len(r["project_ids"])), (r, counts)) for r, counts in counted], limit
    )
    enrichments = await _enrich(r for r, _ in candidates)

    impact_results = []
    for r, severity_counts in candidates:
        version = r["_id"].get("version")
        affected_projects = len(r["project_ids"])
        fix_versions = extract_fix_versions(r["details_list"], version)
        has_fix = len(fix_versions) > 0

        enrichment_data = process_cve_enrichments(r["details_list"], enrichments)

        days_known = calculate_days_known(r["first_seen"])
        days_until_due = calculate_days_until_due(enrichment_data.kev_due_date)
        enrichment_data.days_until_due = days_until_due

        base_impact = calculate_impact_score(
            severity_counts,
            affected_projects,
            enrichment_data,
            has_fix,
            days_known,
        )

        priority_reasons = build_priority_reasons(
            severity_counts,
            enrichment_data,
            affected_projects,
            has_fix,
            days_known,
        )

        impact_results.append(
            ImpactAnalysisResult(
                component=r["_id"]["component"],
                version=version or "unknown",
                affected_projects=affected_projects,
                total_findings=sum(severity_counts.values()),
                findings_by_severity=SeverityBreakdown.from_counts(severity_counts),
                fix_impact_score=base_impact,
                affected_project_names=[
                    project_name_map.get(pid, "Unknown") for pid in r["project_ids"][:_AFFECTED_PROJECTS_SHOWN]
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
    return impact_results[:limit]


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
) -> VulnerabilityHotspot:
    details_list = r["details_list"]
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

    enrichment_data = process_cve_enrichments(details_list, enrichments)
    days_until_due = calculate_days_until_due(enrichment_data.kev_due_date)
    priority_reasons = build_hotspot_priority_reasons(enrichment_data, severity_counts, has_fix, days_until_due)

    return VulnerabilityHotspot(
        component=r["_id"]["component"],
        version=r["_id"].get("version") or "unknown",
        type=dep_type,
        finding_count=sum(severity_counts.values()),
        severity_breakdown=SeverityBreakdown.from_counts(severity_counts),
        affected_projects=[project_name_map.get(pid, "Unknown") for pid in r["project_ids"][:_HOTSPOT_PROJECTS_SHOWN]],
        affected_project_count=len(r["project_ids"]),
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
    sort_by: HotspotSort = "finding_count",
    sort_order: SortOrderQuery = "desc",
    release_environment: ReleaseEnvironmentQuery = None,
) -> list[VulnerabilityHotspot]:
    """Get dependencies with the most vulnerabilities (hotspots)."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_HOTSPOTS)

    projects = await get_user_projects(current_user, db)
    if not projects:
        return []
    key = ("hotspots", scope_digest(p.id for p in projects), release_environment, sort_by, sort_order, skip, limit)
    return await get_analytics_cache().get_or_compute(
        key, lambda: _hotspots(db, projects, release_environment, sort_by, sort_order, skip, limit)
    )


async def _hotspots(
    db: AsyncIOMotorDatabase,
    projects: list[ProjectWithScanId],
    release_environment: str | None,
    sort_by: HotspotSort,
    sort_order: SortOrder,
    skip: int,
    limit: int,
) -> list[VulnerabilityHotspot]:
    project_name_map, scan_ids = await get_projects_with_scans(projects, db, release_environment=release_environment)
    if not scan_ids:
        return []

    sort_direction = parse_sort_direction(sort_order)
    pipeline = _vulnerable_groups(scan_ids)
    if sort_by in _MONGO_SORTS:
        pipeline += [{"$sort": {_MONGO_SORTS[sort_by]: sort_direction, "_id": 1}}, {"$skip": skip}, {"$limit": limit}]
    groups = await FindingRepository(db).aggregate(pipeline, allow_disk_use=True)

    # A component can be group-qualified while the inventory keeps the bare artifact name,
    # so both spellings go into the filter and the index resolves either way.
    candidates = list({name for r in groups for name in component_name_candidates(r["_id"]["component"])})
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
    for row in await DependencyRepository(db).aggregate(type_pipeline):
        name, version = row["_id"]["name"], normalize_version(row["_id"]["version"])
        types_by_version.setdefault(version, {}).setdefault(name, set()).update(row["types"])
        types_by_name.setdefault(name, set()).update(row["types"])
    type_index_by_version = {version: build_component_index(types) for version, types in types_by_version.items()}
    type_index = build_component_index(types_by_name)

    # Only an enrichment-ranked sort needs every group enriched; the others enrich their page alone.
    enrichments = await _enrich(groups) if sort_by in ("epss", "risk") else None
    if rank := _PYTHON_RANKS.get(sort_by):
        # $group emits its rows in no fixed order, so ties need an order of their own to page through.
        groups.sort(key=lambda r: (r["_id"]["component"], r["_id"].get("version") or "unknown"))
        groups.sort(key=lambda r: rank(r, enrichments or {}), reverse=sort_direction == -1)
        groups = groups[skip : skip + limit]
    if enrichments is None:
        enrichments = await _enrich(groups)

    return [
        _build_hotspot(
            r,
            enrichments,
            type_index_by_version.get(normalize_version(r["_id"].get("version")), {}),
            type_index,
            project_name_map,
        )
        for r in groups
    ]
