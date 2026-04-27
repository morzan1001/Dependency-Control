"""Analytics dependency endpoints: dependency-tree, component-findings, dependency-metadata."""

from typing import Annotated, Any, Dict, List, Optional

from fastapi import HTTPException, Query

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    build_findings_severity_map,
    get_latest_scan_ids,
    get_projects_with_scans,
    get_user_project_ids,
    require_analytics_permission,
)
from app.api.v1.helpers.responses import RESP_AUTH
from app.core.constants import ANALYTICS_MAX_QUERY_LIMIT
from app.core.permissions import Permissions
from app.repositories import (
    DependencyEnrichmentRepository,
    DependencyRepository,
    FindingRepository,
    ProjectRepository,
)
from app.schemas.analytics import (
    DependencyMetadata,
    DependencyTreeNode,
    SeverityBreakdown,
)
from app.services.recommendation.common import get_attr

from ._shared import _MSG_ACCESS_DENIED, _get_enrichment_info, _resolve_scan_id

router = CustomAPIRouter()


@router.get("/projects/{project_id}/dependency-tree", responses=RESP_AUTH)
async def get_dependency_tree(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    scan_id: Annotated[Optional[str], Query(description="Specific scan ID, defaults to latest")] = None,
) -> List[DependencyTreeNode]:
    """Get dependency tree for a project showing direct and transitive dependencies."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_TREE)

    dep_repo = DependencyRepository(db)
    finding_repo = FindingRepository(db)

    # Verify access
    project_ids = await get_user_project_ids(current_user, db)
    if project_id not in project_ids:
        raise HTTPException(status_code=403, detail=_MSG_ACCESS_DENIED)

    # Get scan ID (prefer latest scan from active branch)
    if not scan_id:
        scan_id = await _resolve_scan_id(project_id, db)

    if not scan_id:
        return []

    # Get all dependencies for this scan
    dependencies = await dep_repo.find_by_scan(scan_id)

    if not dependencies:
        return []

    # Get findings for this scan and build severity map
    findings = await finding_repo.find_many(
        {"scan_id": scan_id, "type": "vulnerability"},
        limit=ANALYTICS_MAX_QUERY_LIMIT,
    )
    findings_map = build_findings_severity_map(findings)

    def build_node(dep: Any) -> DependencyTreeNode:
        name = get_attr(dep, "name", "")
        finding_info = findings_map.get(name, {})

        return DependencyTreeNode(
            id=str(get_attr(dep, "_id") or get_attr(dep, "purl", "")),
            name=name,
            version=get_attr(dep, "version", ""),
            purl=get_attr(dep, "purl", ""),
            type=get_attr(dep, "type", "unknown"),
            direct=get_attr(dep, "direct", False),
            has_findings=finding_info.get("total", 0) > 0,
            findings_count=finding_info.get("total", 0),
            findings_severity=(
                SeverityBreakdown(
                    critical=finding_info.get("critical", 0),
                    high=finding_info.get("high", 0),
                    medium=finding_info.get("medium", 0),
                    low=finding_info.get("low", 0),
                )
                if finding_info
                else None
            ),
            source_type=get_attr(dep, "source_type"),
            source_target=get_attr(dep, "source_target"),
            layer_digest=get_attr(dep, "layer_digest"),
            locations=get_attr(dep, "locations", []),
            children=[],
        )

    # Separate direct and transitive dependencies
    direct_deps = [build_node(d) for d in dependencies if get_attr(d, "direct", False)]
    transitive_deps = [build_node(d) for d in dependencies if not get_attr(d, "direct", False)]

    # Sort by findings count (most problematic first)
    direct_deps.sort(key=lambda x: x.findings_count, reverse=True)
    transitive_deps.sort(key=lambda x: x.findings_count, reverse=True)

    return direct_deps + transitive_deps


@router.get("/component-findings", responses=RESP_AUTH)
async def get_component_findings(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    component: Annotated[str, Query(description="Component/package name")],
    version: Annotated[Optional[str], Query(description="Specific version")] = None,
) -> List[Dict[str, Any]]:
    """Get all findings for a specific component across accessible projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_SEARCH)

    project_ids = await get_user_project_ids(current_user, db)

    if not project_ids:
        return []

    project_name_map, scan_ids = await get_projects_with_scans(project_ids, db)

    if not scan_ids:
        return []

    finding_repo = FindingRepository(db)

    query = {"scan_id": {"$in": scan_ids}, "component": component}
    if version:
        query["version"] = version

    finding_records = await finding_repo.find_many(query, limit=100)

    results = []
    for fr in finding_records:
        # Convert Pydantic model to dict
        finding = fr.model_dump()
        finding["project_name"] = project_name_map.get(fr.project_id, "Unknown")
        results.append(finding)

    return results


@router.get("/dependency-metadata", responses=RESP_AUTH)
async def get_dependency_metadata_endpoint(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    component: Annotated[str, Query(description="Component/package name")],
    version: Annotated[Optional[str], Query(description="Specific version")] = None,
    type: Annotated[Optional[str], Query(description="Package type")] = None,
) -> Optional[DependencyMetadata]:
    """
    Get aggregated metadata for a dependency across all accessible projects.
    Returns dependency-specific information (not project-specific like Docker layers).
    """
    require_analytics_permission(current_user, Permissions.ANALYTICS_SEARCH)

    project_ids = await get_user_project_ids(current_user, db)

    if not project_ids:
        return None

    scan_ids = await get_latest_scan_ids(project_ids, db)

    if not scan_ids:
        return None

    dep_repo = DependencyRepository(db)
    finding_repo = FindingRepository(db)
    project_repo = ProjectRepository(db)
    enrichment_repo = DependencyEnrichmentRepository(db)

    # Build query for dependencies
    dep_query = {"scan_id": {"$in": scan_ids}, "name": component}
    if version:
        dep_query["version"] = version
    if type:
        dep_query["type"] = type

    dependencies = await dep_repo.find_many(dep_query, limit=100)

    if not dependencies:
        return None

    # Get project names for enrichment
    projects = await project_repo.find_many_minimal(
        {"_id": {"$in": project_ids}},
        limit=ANALYTICS_MAX_QUERY_LIMIT,
    )
    project_name_map = {p.id: p.name for p in projects}

    # Aggregate dependency-specific metadata (take first non-null value)
    first_dep = dependencies[0]

    # Collect affected projects (with deduplication)
    affected_projects = {}
    for dep in dependencies:
        proj_id = get_attr(dep, "project_id")
        if proj_id and proj_id not in affected_projects:
            affected_projects[proj_id] = {
                "id": proj_id,
                "name": project_name_map.get(proj_id, "Unknown"),
                "direct": get_attr(dep, "direct", False),
            }

    # Get enrichment data (deps.dev + license)
    dep_purl = get_attr(first_dep, "purl")
    enrichment_info = await _get_enrichment_info(enrichment_repo, dep_purl)

    # Helper function to get first non-null value from dependencies
    def first_value(key: str) -> Optional[Any]:
        for dep in dependencies:
            val = get_attr(dep, key)
            if val:
                return val
        return None

    # Count findings for this component
    finding_query: Dict[str, Any] = {"scan_id": {"$in": scan_ids}, "component": component}
    if version:
        finding_query["version"] = version

    finding_count = await finding_repo.count(finding_query)
    vuln_count = await finding_repo.count({**finding_query, "type": "vulnerability"})

    return DependencyMetadata(
        name=get_attr(first_dep, "name", component),
        version=get_attr(first_dep, "version", version or "unknown"),
        type=get_attr(first_dep, "type", "unknown"),
        purl=dep_purl,
        description=first_value("description"),
        author=first_value("author"),
        publisher=first_value("publisher"),
        homepage=first_value("homepage"),
        repository_url=first_value("repository_url"),
        download_url=first_value("download_url"),
        group=first_value("group"),
        license=first_value("license"),
        license_url=first_value("license_url"),
        license_category=enrichment_info["license_category"],
        license_risks=enrichment_info["license_risks"],
        license_obligations=enrichment_info["license_obligations"],
        deps_dev=enrichment_info["deps_dev_data"],
        project_count=len(affected_projects),
        affected_projects=list(affected_projects.values()),
        total_vulnerability_count=vuln_count,
        total_finding_count=finding_count,
        enrichment_sources=enrichment_info["enrichment_sources"],
    )
