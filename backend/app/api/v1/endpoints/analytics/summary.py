"""Analytics summary endpoints: /summary, /dependencies/top, /dependency-types."""

from typing import Annotated, Any, Dict, List, Optional

from fastapi import Query

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    get_latest_scan_ids,
    get_projects_with_scans,
    get_user_project_ids,
    require_analytics_permission,
)
from app.api.v1.helpers.responses import RESP_AUTH
from app.core.permissions import Permissions
from app.repositories import (
    DependencyRepository,
    FindingRepository,
)
from app.schemas.analytics import (
    AnalyticsSummary,
    DependencyTypeStats,
    DependencyUsage,
    SeverityBreakdown,
)

router = CustomAPIRouter()


@router.get("/summary", responses=RESP_AUTH)
async def get_analytics_summary(
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> AnalyticsSummary:
    """Get analytics summary across all accessible projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_SUMMARY)

    project_ids = await get_user_project_ids(current_user, db)

    if not project_ids:
        return AnalyticsSummary(
            total_dependencies=0,
            total_vulnerabilities=0,
            unique_packages=0,
            dependency_types=[],
            severity_distribution=SeverityBreakdown(),
        )

    scan_ids = await get_latest_scan_ids(project_ids, db)

    if not scan_ids:
        return AnalyticsSummary(
            total_dependencies=0,
            total_vulnerabilities=0,
            unique_packages=0,
            dependency_types=[],
            severity_distribution=SeverityBreakdown(),
        )

    dep_repo = DependencyRepository(db)
    finding_repo = FindingRepository(db)

    # Count total dependencies
    total_deps = await dep_repo.count({"scan_id": {"$in": scan_ids}})

    # Count unique packages
    unique_packages = await dep_repo.get_unique_packages(scan_ids)

    # Get dependency types distribution
    type_results = await dep_repo.get_type_distribution(scan_ids)

    dependency_types = []
    for t in type_results:
        if t["_id"]:
            dependency_types.append(
                DependencyTypeStats(
                    type=t["_id"],
                    count=t["count"],
                    percentage=round((t["count"] / total_deps * 100) if total_deps > 0 else 0, 1),
                )
            )

    # Get vulnerability counts by severity using repository method
    severity_counts = await finding_repo.get_severity_distribution(scan_ids)

    severity_dist = SeverityBreakdown(
        critical=severity_counts.get("CRITICAL", 0),
        high=severity_counts.get("HIGH", 0),
        medium=severity_counts.get("MEDIUM", 0),
        low=severity_counts.get("LOW", 0),
    )
    total_vulns = sum(severity_counts.values())

    return AnalyticsSummary(
        total_dependencies=total_deps,
        total_vulnerabilities=total_vulns,
        unique_packages=unique_packages,
        dependency_types=dependency_types,
        severity_distribution=severity_dist,
    )


@router.get("/dependencies/top", responses=RESP_AUTH)
async def get_top_dependencies(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    type: Annotated[Optional[str], Query(description="Filter by dependency type (npm, pypi, maven, etc.)")] = None,
) -> List[DependencyUsage]:
    """Get most frequently used dependencies across all accessible projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_DEPENDENCIES)

    project_ids = await get_user_project_ids(current_user, db)

    if not project_ids:
        return []

    scan_ids = await get_latest_scan_ids(project_ids, db)

    if not scan_ids:
        return []

    # Aggregate dependencies
    match_stage: Dict[str, Any] = {"scan_id": {"$in": scan_ids}}
    if type:
        match_stage["type"] = type

    pipeline: List[Dict[str, Any]] = [
        {"$match": match_stage},
        {
            "$group": {
                "_id": "$name",
                "type": {"$first": "$type"},
                "versions": {"$addToSet": "$version"},
                "project_ids": {"$addToSet": "$project_id"},
                "total_occurrences": {"$sum": 1},
            }
        },
        {
            "$project": {
                "name": "$_id",
                "type": 1,
                "versions": 1,
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

    # Batch fetch vulnerability counts using repository method
    component_names = [dep["name"] for dep in results]
    vuln_count_map = await finding_repo.get_vuln_counts_by_components(project_ids, component_names)

    # Enrich with vulnerability info
    enriched = []
    for dep in results:
        vuln_count = vuln_count_map.get(dep["name"], 0)
        enriched.append(
            DependencyUsage(
                name=dep["name"],
                type=dep.get("type", "unknown"),
                versions=dep["versions"][:10],  # Limit versions to 10
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
) -> List[str]:
    """Get list of all dependency types used across accessible projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_SEARCH)

    project_ids = await get_user_project_ids(current_user, db)

    if not project_ids:
        return []

    _, scan_ids = await get_projects_with_scans(project_ids, db)

    if not scan_ids:
        return []

    dep_repo = DependencyRepository(db)
    return await dep_repo.get_distinct_types(scan_ids)
