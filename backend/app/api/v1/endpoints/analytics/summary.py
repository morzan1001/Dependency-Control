"""Analytics summary endpoints: /scope, /summary, /dependencies/top, /dependency-types."""

from typing import Annotated, Any

from fastapi import Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    ReleaseEnvironmentQuery,
    get_latest_scan_ids,
    get_user_projects,
    require_analytics_permission,
    require_any_analytics_permission,
    scope_resolution_counts,
    vuln_details_by,
)
from app.api.v1.helpers.responses import RESP_AUTH
from app.core.cache import scope_digest
from app.core.permissions import Permissions
from app.core.purl import package_identity_expr
from app.repositories.dependencies import DependencyRepository
from app.repositories.findings import FindingRepository
from app.repositories.scans import ScanRepository
from app.schemas.analytics import (
    AnalyticsScope,
    AnalyticsSummary,
    DependencyTypeStats,
    DependencyUsage,
    SeverityBreakdown,
)
from app.schemas.projections import ProjectWithScanId
from app.services.analytics.cache import get_analytics_cache
from app.services.component_identity import (
    artifact_name_expr,
    build_component_index,
    extract_artifact_name,
    lookup_component,
)
from app.services.aggregation.versions import newest_first
from app.services.recommendation.common import live_cves

router = CustomAPIRouter()

# Versions listed per component; version_count beside them carries the distinct total.
_VERSION_SAMPLE = 10


@router.get("/scope", responses=RESP_AUTH)
async def get_analytics_scope(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    release_environment: ReleaseEnvironmentQuery = None,
) -> AnalyticsScope:
    """The release environments the caller's projects deploy to, and how much of the scope the
    requested mode resolved.

    Gated on any analytics feature permission rather than one of them: the coverage counters caption
    every analytics tab, and the environments drive the mode switch that every tab obeys.
    """
    require_any_analytics_permission(current_user)

    projects = await get_user_projects(current_user, db)

    if not projects:
        return AnalyticsScope(release_environments=[], resolved_projects=0, projects_without_release=0)

    project_ids = [p.id for p in projects]
    environments: list[str] = sorted(await db.releases.distinct("environment", {"project_id": {"$in": project_ids}}))
    scan_ids = await get_latest_scan_ids(projects, db, release_environment=release_environment)
    resolved_projects, projects_without_release = scope_resolution_counts(project_ids, scan_ids)

    return AnalyticsScope(
        release_environments=environments,
        resolved_projects=resolved_projects,
        projects_without_release=projects_without_release,
        oldest_analysis_at=await ScanRepository(db).oldest_analysis_at(scan_ids),
    )


async def _heads_and_types(
    db: AsyncIOMotorDatabase, projects: list[ProjectWithScanId], release_environment: str | None
) -> tuple[list[str], list[dict[str, Any]]]:
    """The scope's resolved scans and their dependency type distribution."""

    async def compute() -> tuple[list[str], list[dict[str, Any]]]:
        scan_ids = await get_latest_scan_ids(projects, db, release_environment=release_environment)
        return scan_ids, await DependencyRepository(db).get_type_distribution(scan_ids) if scan_ids else []

    key = ("dep-types", scope_digest(p.id for p in projects), release_environment)
    return await get_analytics_cache().get_or_compute(key, compute)


@router.get("/summary", responses=RESP_AUTH)
async def get_analytics_summary(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    release_environment: ReleaseEnvironmentQuery = None,
) -> AnalyticsSummary:
    """Get analytics summary across all accessible projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_SUMMARY)

    projects = await get_user_projects(current_user, db)
    key = ("summary", scope_digest(p.id for p in projects), release_environment)
    return await get_analytics_cache().get_or_compute(key, lambda: _summary(db, projects, release_environment))


async def _summary(
    db: AsyncIOMotorDatabase, projects: list[ProjectWithScanId], release_environment: str | None
) -> AnalyticsSummary:
    scan_ids, type_results = await _heads_and_types(db, projects, release_environment)
    resolved_projects, projects_without_release = scope_resolution_counts([p.id for p in projects], scan_ids)

    if not scan_ids:
        return AnalyticsSummary(
            total_dependencies=0,
            total_vulnerabilities=0,
            unique_packages=0,
            dependency_types=[],
            severity_distribution=SeverityBreakdown(),
            resolved_projects=resolved_projects,
            projects_without_release=projects_without_release,
        )

    total_deps = sum(t["count"] for t in type_results)
    unique_packages = await DependencyRepository(db).get_unique_packages(scan_ids)

    dependency_types = [
        DependencyTypeStats(
            type=t["_id"],
            count=t["count"],
            percentage=round((t["count"] / total_deps * 100) if total_deps > 0 else 0, 1),
        )
        for t in type_results
        if t["_id"]
    ]

    severity_counts = await FindingRepository(db).get_severity_distribution(scan_ids)

    return AnalyticsSummary(
        total_dependencies=total_deps,
        total_vulnerabilities=sum(severity_counts.values()),
        unique_packages=unique_packages,
        dependency_types=dependency_types,
        severity_distribution=SeverityBreakdown.from_counts(severity_counts),
        resolved_projects=resolved_projects,
        projects_without_release=projects_without_release,
    )


@router.get("/dependencies/top", responses=RESP_AUTH)
async def get_top_dependencies(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    type: Annotated[str | None, Query(description="Filter by dependency type (npm, pypi, maven, etc.)")] = None,
    release_environment: ReleaseEnvironmentQuery = None,
) -> list[DependencyUsage]:
    """Get most frequently used dependencies across all accessible projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_DEPENDENCIES)

    projects = await get_user_projects(current_user, db)
    key = ("top-deps", scope_digest(p.id for p in projects), release_environment, limit, type)
    return await get_analytics_cache().get_or_compute(
        key, lambda: _top_dependencies(db, projects, release_environment, limit, type)
    )


async def _top_dependencies(
    db: AsyncIOMotorDatabase,
    projects: list[ProjectWithScanId],
    release_environment: str | None,
    limit: int,
    type: str | None,
) -> list[DependencyUsage]:
    project_ids = [p.id for p in projects]
    scan_ids = await get_latest_scan_ids(projects, db, release_environment=release_environment)
    if not scan_ids:
        return []

    match_stage: dict[str, Any] = {"scan_id": {"$in": scan_ids}}
    if type:
        match_stage["type"] = type

    pipeline: list[dict[str, Any]] = [
        {"$match": match_stage},
        {
            "$group": {
                "_id": package_identity_expr(),
                "name": {"$min": "$name"},
                "type": {"$min": "$type"},
                "group": {"$max": "$group"},
                "versions": {"$addToSet": "$version"},
                "project_ids": {"$addToSet": "$project_id"},
                "total_occurrences": {"$sum": 1},
            }
        },
        {
            "$project": {
                "name": 1,
                "type": 1,
                "group": 1,
                "versions": 1,
                "version_count": {"$size": "$versions"},
                "project_count": {"$size": "$project_ids"},
                "total_occurrences": 1,
            }
        },
        {"$sort": {"project_count": -1, "total_occurrences": -1}},
        {"$limit": limit},
    ]

    dep_repo = DependencyRepository(db)
    finding_repo = FindingRepository(db)

    results = await dep_repo.aggregate(pipeline)

    # Every same-artifact spelling is read, so build_component_index sees the ambiguity it guards against.
    listed_artifacts = sorted({extract_artifact_name(dep["name"]) for dep in results})
    details_by_component = await vuln_details_by(
        finding_repo,
        "component",
        {
            "scan_id": {"$in": scan_ids},
            "project_id": {"$in": project_ids},
            "$expr": {"$in": [artifact_name_expr("$component"), listed_artifacts]},
        },
    )
    vuln_count_map = build_component_index(
        {component: len(live_cves(details)) for component, details in details_by_component.items()}
    )

    enriched = []
    for dep in results:
        vuln_count = lookup_component(vuln_count_map, dep["name"]) or 0
        enriched.append(
            DependencyUsage(
                name=dep["name"],
                type=dep.get("type", "unknown"),
                group=dep.get("group"),
                # $addToSet has no order, so rank before sampling.
                versions=newest_first(dep["versions"])[:_VERSION_SAMPLE],
                version_count=dep["version_count"],
                project_count=dep["project_count"],
                total_occurrences=dep["total_occurrences"],
                has_vulnerabilities=vuln_count > 0,
                vulnerability_count=vuln_count,
            )
        )

    return enriched


@router.get("/dependency-types", responses=RESP_AUTH)
async def get_dependency_types(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    release_environment: ReleaseEnvironmentQuery = None,
) -> list[str]:
    """Get list of all dependency types used across accessible projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_SEARCH)

    projects = await get_user_projects(current_user, db)
    _, type_results = await _heads_and_types(db, projects, release_environment)
    return sorted(t["_id"] for t in type_results if t["_id"])
