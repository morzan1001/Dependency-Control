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
    DependencyGraph,
    DependencyMetadata,
    DependencyTreeNode,
    SeverityBreakdown,
)
from app.services.recommendation.common import get_attr

from ._shared import _MSG_ACCESS_DENIED, _get_enrichment_info, _resolve_scan_id

router = CustomAPIRouter()

def _dep_key(dep: Any) -> str:
    """Node identity for parent matching: PURL (parent_components hold PURLs, as in graph.py), else name@version."""
    return get_attr(dep, "purl") or f"{get_attr(dep, 'name')}@{get_attr(dep, 'version')}"


def _build_tree_node(dep: Any, findings_map: Dict[str, Dict[str, int]]) -> DependencyTreeNode:
    """Build one node without its children; the graph builder fills in child_ids."""
    name = get_attr(dep, "name", "")
    finding_info = findings_map.get(name, {})

    return DependencyTreeNode(
        # The document id (uuid) is unique per dependency; PURL only backstops dict inputs in tests.
        id=str(get_attr(dep, "id") or get_attr(dep, "purl", "")),
        name=name,
        version=get_attr(dep, "version", ""),
        purl=get_attr(dep, "purl", ""),
        type=get_attr(dep, "type", "unknown"),
        direct=get_attr(dep, "direct", False),
        direct_inferred=get_attr(dep, "direct_inferred", False),
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
        child_ids=[],
    )


def _build_dependency_graph(
    dependencies: List[Any], findings_map: Dict[str, Dict[str, int]]
) -> DependencyGraph:
    """Flatten deps into unique nodes + per-node child_ids and roots so the client nests lazily."""
    node_by_key: Dict[str, DependencyTreeNode] = {}
    order: List[str] = []
    # A purl can appear in several docs (e.g. one per container layer) with different
    # parent_components; merge every doc's parents so no parent -> child edge is lost.
    parents_by_key: Dict[str, List[str]] = {}
    for dep in dependencies:
        key = _dep_key(dep)
        if key not in node_by_key:
            node_by_key[key] = _build_tree_node(dep, findings_map)
            order.append(key)
        known = parents_by_key.setdefault(key, [])
        for parent in get_attr(dep, "parent_components", []) or []:
            if parent not in known:
                known.append(parent)

    children_by_parent: Dict[str, List[str]] = {}
    for key in order:
        for parent in parents_by_key.get(key, []):
            siblings = children_by_parent.setdefault(parent, [])
            if key not in siblings:
                siblings.append(key)

    for key in order:
        child_keys = [ck for ck in children_by_parent.get(key, []) if ck in node_by_key]
        child_keys.sort(key=lambda ck: node_by_key[ck].findings_count, reverse=True)
        node_by_key[key].child_ids = [node_by_key[ck].id for ck in child_keys]

    def _closure(start: str) -> set:
        seen: set = set()
        stack = [start]
        while stack:
            key = stack.pop()
            if key in seen:
                continue
            seen.add(key)
            stack.extend(ck for ck in children_by_parent.get(key, []) if ck in node_by_key)
        return seen

    def _has_resolvable_parent(key: str) -> bool:
        return any(p in node_by_key for p in parents_by_key.get(key, []))

    reachable: set = set()
    root_keys = [
        key for key in order if node_by_key[key].direct or not _has_resolvable_parent(key)
    ]
    for key in root_keys:
        reachable |= _closure(key)

    # Whatever is still unreachable belongs to a component with no natural entry (a fully
    # disconnected cycle). Promote one entry per component and drop any extra root its subtree
    # already covers, so a descendant seen before its component's entry is not left as a root.
    extra_roots: List[str] = []
    for key in order:
        if key not in reachable:
            component = _closure(key)
            extra_roots = [r for r in extra_roots if r not in component]
            extra_roots.append(key)
            reachable |= component

    root_keys += extra_roots
    root_keys.sort(key=lambda k: node_by_key[k].findings_count, reverse=True)
    return DependencyGraph(
        nodes=[node_by_key[key] for key in order],
        roots=[node_by_key[key].id for key in root_keys],
    )


@router.get("/projects/{project_id}/dependency-tree", responses=RESP_AUTH)
async def get_dependency_tree(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    scan_id: Annotated[Optional[str], Query(description="Specific scan ID, defaults to latest")] = None,
) -> DependencyGraph:
    """Get the dependency graph for a project as flat nodes + roots (client nests lazily)."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_TREE)

    dep_repo = DependencyRepository(db)
    finding_repo = FindingRepository(db)

    project_ids = await get_user_project_ids(current_user, db)
    if project_id not in project_ids:
        raise HTTPException(status_code=403, detail=_MSG_ACCESS_DENIED)

    if not scan_id:
        scan_id = await _resolve_scan_id(project_id, db)

    if not scan_id:
        return DependencyGraph()

    dependencies = await dep_repo.find_by_scan(scan_id)

    if not dependencies:
        return DependencyGraph()

    findings = await finding_repo.find_many(
        {"scan_id": scan_id, "type": "vulnerability"},
        limit=ANALYTICS_MAX_QUERY_LIMIT,
    )
    findings_map = build_findings_severity_map(findings)

    return _build_dependency_graph(dependencies, findings_map)


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
        finding = fr.model_dump()
        finding["project_name"] = project_name_map.get(fr.project_id, "Unknown")
        results.append(finding)

    return results


def _build_dep_query(
    scan_ids: List[str], component: str, version: Optional[str], type: Optional[str]
) -> Dict[str, Any]:
    dep_query: Dict[str, Any] = {"scan_id": {"$in": scan_ids}, "name": component}
    if version:
        dep_query["version"] = version
    if type:
        dep_query["type"] = type
    return dep_query


def _collect_affected_projects(dependencies: List[Any], project_name_map: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    affected_projects: Dict[str, Dict[str, Any]] = {}
    for dep in dependencies:
        proj_id = get_attr(dep, "project_id")
        if proj_id and proj_id not in affected_projects:
            affected_projects[proj_id] = {
                "id": proj_id,
                "name": project_name_map.get(proj_id, "Unknown"),
                "direct": get_attr(dep, "direct", False),
            }
    return affected_projects


def _first_dep_value(dependencies: List[Any], key: str) -> Optional[Any]:
    for dep in dependencies:
        val = get_attr(dep, key)
        if val:
            return val
    return None


@router.get("/dependency-metadata", responses=RESP_AUTH)
async def get_dependency_metadata_endpoint(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    component: Annotated[str, Query(description="Component/package name")],
    version: Annotated[Optional[str], Query(description="Specific version")] = None,
    type: Annotated[Optional[str], Query(description="Package type")] = None,
) -> Optional[DependencyMetadata]:
    """Aggregated dependency metadata across accessible projects."""
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

    dep_query = _build_dep_query(scan_ids, component, version, type)
    dependencies = await dep_repo.find_many(dep_query, limit=100)
    if not dependencies:
        return None

    projects = await project_repo.find_many_minimal(
        {"_id": {"$in": project_ids}},
        limit=ANALYTICS_MAX_QUERY_LIMIT,
    )
    project_name_map = {p.id: p.name for p in projects}

    first_dep = dependencies[0]
    affected_projects = _collect_affected_projects(dependencies, project_name_map)

    dep_purl = get_attr(first_dep, "purl")
    enrichment_info = await _get_enrichment_info(enrichment_repo, dep_purl)

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
        description=_first_dep_value(dependencies, "description"),
        author=_first_dep_value(dependencies, "author"),
        publisher=_first_dep_value(dependencies, "publisher"),
        homepage=_first_dep_value(dependencies, "homepage"),
        repository_url=_first_dep_value(dependencies, "repository_url"),
        download_url=_first_dep_value(dependencies, "download_url"),
        group=_first_dep_value(dependencies, "group"),
        license=_first_dep_value(dependencies, "license"),
        license_url=_first_dep_value(dependencies, "license_url"),
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
