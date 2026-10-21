import asyncio
import logging
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    SLIM_DETAILS_EXPR,
    CVEEnrichmentResult,
    ReleaseEnvironmentQuery,
    build_priority_reasons,
    calculate_days_known,
    calculate_impact_score,
    extract_fix_versions,
    get_projects_with_scans,
    get_user_projects,
    impact_pre_score_expr,
    process_cve_enrichments,
    require_analytics_permission,
    select_impact_candidates,
    severity_counts_from_details,
)
from app.api.v1.helpers.responses import RESP_413, RESP_AUTH
from app.api.v1.helpers.sorting import (
    SortOrder,
    SortOrderQuery,
    case_insensitive_key,
    case_insensitive_sort,
    parse_sort_direction,
)
from app.core.cache import scope_digest
from app.core.constants import ANALYTICS_MAX_QUERY_LIMIT, SEVERITY_ORDER, severity_rank_expr
from app.core.cve import counted_cves_expr
from app.core.permissions import Permissions
from app.repositories.dependencies import DependencyRepository
from app.repositories.findings import FindingRepository
from app.repositories.projections import ProjectWithScanId
from app.schemas.analytics import (
    ImpactAnalysisResult,
    SeverityBreakdown,
    VulnerabilityHotspot,
)
from app.schemas.enrichment import VulnerabilityEnrichment
from app.services.aggregation.versions import newest_first, normalize_version
from app.services.analytics.cache import get_analytics_cache
from app.services.component_identity import (
    build_component_index,
    component_name_candidates,
    lookup_component,
)
from app.services.enrichment.service import THREAT_INTEL_SOURCES, vulnerability_enrichment_service
from app.services.recommendation.common import live_cves

logger = logging.getLogger(__name__)

router = CustomAPIRouter(responses=RESP_413)


# Each sample ships beside the population it was drawn from, so a reader knows whether a list is all of it.
_AFFECTED_PROJECTS_SHOWN = 5
_HOTSPOT_PROJECTS_SHOWN = 10
_FIX_VERSIONS_SHOWN = 3
_CVES_SHOWN = 5

# first_seen_at carries a finding's earliest detection in its project past retention; older rows lack it.
_FIRST_SEEN = {"$min": {"$ifNull": ["$first_seen_at", "$scan_created_at"]}}

HotspotSort = Literal["finding_count", "component", "first_seen", "epss", "risk"]
_MONGO_SORTS = {"component": "_id.component", "first_seen": "first_seen", "finding_count": "cve_count"}
# The other keys derive from the live enrichment of every advisory, so they rank in Python.
_PYTHON_RANKS: dict[str, Callable[[dict[str, Any], Mapping[str, VulnerabilityEnrichment]], float]] = {
    "epss": lambda r, enrichments: process_cve_enrichments(r["details_list"], enrichments).max_epss or 0,
    "risk": lambda r, enrichments: process_cve_enrichments(r["details_list"], enrichments).max_risk or 0,
}

_LIVE_VULNERABILITIES = {"type": "vulnerability", "waived": {"$ne": True}}


def _counted_groups(scan_ids: list[str]) -> list[dict[str, Any]]:
    """Each (component, version) group with severity_counts_from_details' counts, but without its advisory lists."""
    live = {
        "$filter": {"input": {"$ifNull": ["$details.vulnerabilities", []]}, "cond": {"$ne": ["$$this.waived", True]}}
    }
    advisory = {"cves": counted_cves_expr("$$v"), "rank": severity_rank_expr({"$toUpper": "$$v.severity"})}
    return [
        {"$match": {"scan_id": {"$in": scan_ids}, **_LIVE_VULNERABILITIES}},
        {
            "$project": {
                "component": 1,
                "version": 1,
                "project_id": 1,
                "first_seen_at": 1,
                "scan_created_at": 1,
                "advisories": {"$map": {"input": live, "as": "v", "in": advisory}},
            }
        },
        # Preserved, so a finding whose advisories are all waived still counts its project and age.
        {"$unwind": {"path": "$advisories", "preserveNullAndEmptyArrays": True}},
        {"$unwind": {"path": "$advisories.cves", "preserveNullAndEmptyArrays": True}},
        {
            "$group": {
                "_id": {"component": "$component", "version": "$version", "cve": "$advisories.cves"},
                "rank": {"$max": "$advisories.rank"},
                "project_ids": {"$addToSet": "$project_id"},
                "first_seen": _FIRST_SEEN,
            }
        },
        {
            "$group": {
                "_id": {"component": "$_id.component", "version": "$_id.version"},
                "project_ids": {"$push": "$project_ids"},
                "first_seen": {"$min": "$first_seen"},
                "ranks": {"$push": {"$cond": [{"$eq": [{"$type": "$_id.cve"}, "string"]}, "$rank", "$$REMOVE"]}},
            }
        },
        {
            "$project": {
                "project_ids": {
                    "$reduce": {"input": "$project_ids", "initialValue": [], "in": {"$setUnion": ["$$value", "$$this"]}}
                },
                "first_seen": 1,
                "cve_count": {"$size": "$ranks"},
                "counts": {
                    label.lower(): {"$size": {"$filter": {"input": "$ranks", "cond": {"$eq": ["$$this", rank]}}}}
                    for label, rank in SEVERITY_ORDER.items()
                },
            }
        },
    ]


def _vulnerable_groups(match: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"$match": {**match, **_LIVE_VULNERABILITIES}},
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
        # No $slice after this $group: it cannot shrink the accumulator, and a cap in match order drops KEV/EPSS CVEs.
        {
            "$group": {
                "_id": {"component": "$component", "version": "$version"},
                "project_ids": {"$addToSet": "$project_id"},
                "first_seen": _FIRST_SEEN,
                # $addToSet collapses the usually identical per-project advisory lists to their distinct variants.
                "details_list": {"$addToSet": "$details"},
            }
        },
    ]


async def _with_advisories(
    repo: FindingRepository, scan_ids: list[str], groups: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """The full rows, advisory lists included, of these counted groups alone and in their order."""
    keys = [(group["_id"]["component"], group["_id"].get("version")) for group in groups]
    if not keys:
        return []
    match = {
        "scan_id": {"$in": scan_ids},
        "component": {"$in": list({component for component, _ in keys})},
        "version": {"$in": list({version for _, version in keys})},
    }
    rows = await repo.aggregate(_vulnerable_groups(match))
    by_key = {(row["_id"]["component"], row["_id"].get("version")): row for row in rows}
    return [by_key[key] for key in keys if key in by_key]


async def _enrich(groups: Iterable[dict[str, Any]]) -> tuple[dict[str, VulnerabilityEnrichment], list[str]]:
    """Enrichment is supplementary, so a failure leaves the groups unenriched and names every source unavailable."""
    cves = list({cve for group in groups for cve in live_cves(group["details_list"])})
    if not cves:
        return {}, []
    try:
        return await vulnerability_enrichment_service.enrich_cves(cves)
    except Exception as e:
        logger.warning(f"Failed to enrich CVEs: {e}")
        return {}, list(THREAT_INTEL_SOURCES)


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

    repo = FindingRepository(db)
    pipeline = [
        *_counted_groups(scan_ids),
        {"$addFields": {"pre_score": impact_pre_score_expr("$counts", "$project_ids")}},
        {"$sort": {"pre_score": -1, "_id": 1}},
        {"$limit": ANALYTICS_MAX_QUERY_LIMIT},
    ]
    counted = await repo.aggregate(pipeline)
    candidates = await _with_advisories(
        repo, scan_ids, select_impact_candidates([(group["pre_score"], group) for group in counted], limit)
    )
    enrichments, unavailable = await _enrich(candidates)

    impact_results = []
    for r in candidates:
        # Severity/vuln counts come from the advisory lists (finding_id is only component:version).
        severity_counts = severity_counts_from_details(r["details_list"])
        intel, enrichment = _threat_intel(r, severity_counts, enrichments, unavailable)
        affected_projects = len(r["project_ids"])
        impact_results.append(
            ImpactAnalysisResult(
                **intel,
                component=r["_id"]["component"],
                version=r["_id"].get("version") or "unknown",
                affected_projects=affected_projects,
                total_findings=sum(severity_counts.values()),
                findings_by_severity=SeverityBreakdown.from_counts(severity_counts),
                fix_impact_score=calculate_impact_score(
                    severity_counts, affected_projects, enrichment, intel["has_fix"], intel["days_known"]
                ),
                affected_project_names=[
                    project_name_map.get(pid, "Unknown") for pid in r["project_ids"][:_AFFECTED_PROJECTS_SHOWN]
                ],
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


def _threat_intel(
    r: dict[str, Any],
    severity_counts: dict[str, int],
    enrichments: Mapping[str, VulnerabilityEnrichment],
    unavailable: list[str],
) -> tuple[dict[str, Any], CVEEnrichmentResult]:
    details_list = r["details_list"]
    fix_versions = extract_fix_versions(details_list, r["_id"].get("version"))
    days_known = calculate_days_known(r.get("first_seen"))
    enrichment = process_cve_enrichments(details_list, enrichments)
    intel = {
        "max_epss_score": enrichment.max_epss,
        "epss_percentile": enrichment.max_percentile,
        "has_kev": enrichment.has_kev,
        "kev_count": enrichment.kev_count,
        "kev_ransomware_use": enrichment.kev_ransomware_use,
        "kev_due_date": enrichment.kev_due_date,
        "days_until_due": enrichment.days_until_due,
        "exploit_maturity": enrichment.exploit_maturity,
        "max_risk_score": enrichment.max_risk,
        "days_known": days_known,
        "has_fix": bool(fix_versions),
        "fix_versions": newest_first(fix_versions)[:_FIX_VERSIONS_SHOWN],
        "fix_version_count": len(fix_versions),
        "priority_reasons": build_priority_reasons(
            severity_counts, enrichment, len(r["project_ids"]), bool(fix_versions), days_known
        ),
        "threat_intel_unavailable": unavailable,
    }
    return intel, enrichment


def _build_hotspot(
    r: dict[str, Any],
    enrichments: Mapping[str, VulnerabilityEnrichment],
    unavailable: list[str],
    version_type_index: dict[str, set[str]],
    type_index: dict[str, set[str]],
    project_name_map: dict[str, str],
) -> VulnerabilityHotspot:
    severity_counts = severity_counts_from_details(r["details_list"])
    component = r["_id"]["component"]
    # One name at one version can ship in several ecosystems (a deb and an apk openssl); name them all.
    types = lookup_component(version_type_index, component) or lookup_component(type_index, component)
    cves = live_cves(r["details_list"])
    intel, _ = _threat_intel(r, severity_counts, enrichments, unavailable)

    return VulnerabilityHotspot(
        **intel,
        component=component,
        version=r["_id"].get("version") or "unknown",
        type="/".join(sorted(types)) if types else "unknown",
        finding_count=sum(severity_counts.values()),
        severity_breakdown=SeverityBreakdown.from_counts(severity_counts),
        affected_projects=[project_name_map.get(pid, "Unknown") for pid in r["project_ids"][:_HOTSPOT_PROJECTS_SHOWN]],
        affected_project_count=len(r["project_ids"]),
        first_seen=_format_first_seen(r.get("first_seen")),
        top_cves=cves[:_CVES_SHOWN],
        cve_count=len(cves),
    )


@router.get("/hotspots", responses=RESP_AUTH)
async def get_vulnerability_hotspots(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    skip: Annotated[int, Query(ge=0, description="Number of records to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    sort_by: HotspotSort = "risk",
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


def _ranked_page(
    groups: list[dict[str, Any]],
    rank: Callable[[dict[str, Any], Mapping[str, VulnerabilityEnrichment]], float],
    enrichments: Mapping[str, VulnerabilityEnrichment],
    descending: bool,
    skip: int,
    limit: int,
) -> list[dict[str, Any]]:
    # $group emits its rows in no fixed order, so ties need an order of their own to page through.
    ordered = sorted(
        groups, key=lambda r: (case_insensitive_key(r["_id"]["component"]), r["_id"].get("version") or "unknown")
    )
    ordered.sort(key=lambda r: rank(r, enrichments), reverse=descending)
    return ordered[skip : skip + limit]


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
    repo = FindingRepository(db)
    rank = _PYTHON_RANKS.get(sort_by)
    if rank:
        groups = await repo.aggregate(_vulnerable_groups({"scan_id": {"$in": scan_ids}}))
    else:
        order = [(_MONGO_SORTS[sort_by], sort_direction), ("_id.component", 1), ("_id", 1)]
        page = [*case_insensitive_sort(order, {"_id.component"}), {"$skip": skip}, {"$limit": limit}]
        counted = await repo.aggregate([*_counted_groups(scan_ids), *page])
        groups = await _with_advisories(repo, scan_ids, counted)

    # A component may be group-qualified while the inventory keeps the bare artifact name, so both spellings match.
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
    # Only an enrichment-ranked sort needs every group enriched; the others enrich their page alone.
    type_rows, (enrichments, unavailable) = await asyncio.gather(
        DependencyRepository(db).aggregate(type_pipeline), _enrich(groups)
    )
    if rank:
        groups = _ranked_page(groups, rank, enrichments, sort_direction == -1, skip, limit)

    types_by_version: dict[str, dict[str, set[str]]] = {}
    types_by_name: dict[str, set[str]] = {}
    for row in type_rows:
        name, version = row["_id"]["name"], normalize_version(row["_id"]["version"])
        types_by_version.setdefault(version, {}).setdefault(name, set()).update(row["types"])
        types_by_name.setdefault(name, set()).update(row["types"])
    type_index_by_version = {version: build_component_index(types) for version, types in types_by_version.items()}
    type_index = build_component_index(types_by_name)

    return [
        _build_hotspot(
            r,
            enrichments,
            unavailable,
            type_index_by_version.get(normalize_version(r["_id"].get("version")), {}),
            type_index,
            project_name_map,
        )
        for r in groups
    ]
