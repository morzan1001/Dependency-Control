"""Analytics dependency endpoints: dependency-tree, component-findings, dependency-metadata."""

from typing import Annotated, Any

from fastapi import HTTPException, Query

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    ReleaseEnvironmentQuery,
    get_latest_scan_ids,
    get_projects_with_scans,
    get_user_project_ids,
    require_analytics_permission,
    severity_counts_from_details,
    vuln_details_by,
)
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_404
from app.core.constants import ANALYTICS_MAX_QUERY_LIMIT, PROJECT_ROLE_VIEWER, SCAN_DEPENDENCY_READ_LIMIT
from app.core.permissions import Permissions
from app.repositories import (
    DependencyEnrichmentRepository,
    DependencyRepository,
    FindingRepository,
    ProjectRepository,
    ScanRepository,
)
from app.schemas.analytics import (
    DependencyGraph,
    DependencyMetadata,
    DependencyTreeNode,
    SeverityBreakdown,
)
from app.core.purl import package_identity, package_identity_expr
from app.services.component_identity import (
    artifact_segment,
    build_component_index,
    cluster_by_package_identity,
    component_match_query,
    component_name_candidates,
    lookup_component,
    normalize_component,
)
from app.services.aggregation.versions import parse_version_key
from app.services.recommendation.common import get_attr, live_cves
from app.services.recommendation.graph import build_dependency_edges

from ._shared import _get_enrichment_info, _resolve_scan_id

router = CustomAPIRouter()


async def _package_finding_query(
    finding_repo: FindingRepository, scan_ids: list[str], component: str, version: str | None
) -> dict[str, Any]:
    """Finding filter for every stored spelling of ``component``'s package.

    The bare artifact and its qualified forms are collected in scope (version included) first, so
    a bare name joins its qualified package only when exactly one exists, whichever panel asks.
    """
    scope: dict[str, Any] = {"scan_id": {"$in": scan_ids}, "waived": {"$ne": True}}
    if version:
        scope["version"] = version
    names = await finding_repo.collection.distinct(
        "component", {**scope, **component_match_query(artifact_segment(component))}
    )
    representative = cluster_by_package_identity([*names, component])
    wanted = representative[normalize_component(component)]
    same = [name for name in names if representative[normalize_component(name)] == wanted]
    return {**scope, "component": {"$in": same or [component]}}


def _build_tree_node(dep: Any, findings_map: dict[str, dict[str, int]], *, direct: bool) -> DependencyTreeNode:
    """Build one node without its children; the graph builder fills in child_ids."""
    name = get_attr(dep, "name", "")
    # The bare-artifact alias keys are lowercased, dependency names are not.
    finding_info = lookup_component(findings_map, name) or {}
    findings_count = sum(finding_info.values())

    return DependencyTreeNode(
        # The document id (uuid) is unique per dependency; PURL only backstops dict inputs in tests.
        id=str(get_attr(dep, "id") or get_attr(dep, "purl", "")),
        name=name,
        version=get_attr(dep, "version", ""),
        purl=get_attr(dep, "purl", ""),
        type=get_attr(dep, "type", "unknown"),
        direct=direct,
        direct_inferred=get_attr(dep, "direct_inferred", False),
        has_findings=findings_count > 0,
        findings_count=findings_count,
        findings_severity=SeverityBreakdown(**finding_info) if finding_info else None,
        source_type=get_attr(dep, "source_type"),
        source_target=get_attr(dep, "source_target"),
        layer_digest=get_attr(dep, "layer_digest"),
        locations=get_attr(dep, "locations", []),
        child_ids=[],
    )


def _build_dependency_graph(
    dependencies: list[Any],
    findings_map: dict[str, dict[str, int]],
    dependencies_total: int,
) -> DependencyGraph:
    """Flatten deps into unique nodes + per-node child_ids and roots so the client nests lazily."""
    edges = build_dependency_edges(dependencies)
    node_by_key = {
        key: _build_tree_node(dep, findings_map, direct=key in edges.direct_keys)
        for key, dep in edges.dep_by_key.items()
    }
    for key, node in node_by_key.items():
        child_keys = sorted(
            edges.children_by_parent.get(key, []), key=lambda ck: node_by_key[ck].findings_count, reverse=True
        )
        node.child_ids = [node_by_key[ck].id for ck in child_keys]

    def _closure(start: str) -> set:
        seen: set = set()
        stack = [start]
        while stack:
            key = stack.pop()
            if key in seen:
                continue
            seen.add(key)
            stack.extend(edges.children_by_parent.get(key, []))
        return seen

    def _has_resolvable_parent(key: str) -> bool:
        return any(p in node_by_key for p in edges.parents_by_key[key])

    reachable: set = set()
    root_keys = [key for key in node_by_key if key in edges.direct_keys or not _has_resolvable_parent(key)]
    for key in root_keys:
        reachable |= _closure(key)

    # Whatever is still unreachable belongs to a component with no natural entry (a fully
    # disconnected cycle). Promote one entry per component and drop any extra root its subtree
    # already covers, so a descendant seen before its component's entry is not left as a root.
    extra_roots: list[str] = []
    for key in node_by_key:
        if key not in reachable:
            component = _closure(key)
            extra_roots = [r for r in extra_roots if r not in component]
            extra_roots.append(key)
            reachable |= component

    root_keys += extra_roots
    root_keys.sort(key=lambda k: node_by_key[k].findings_count, reverse=True)
    return DependencyGraph(
        nodes=list(node_by_key.values()),
        roots=[node_by_key[key].id for key in root_keys],
        dependencies_read=len(dependencies),
        dependencies_total=dependencies_total,
    )


@router.get("/projects/{project_id}/dependency-tree", responses=RESP_AUTH_404)
async def get_dependency_tree(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    scan_id: Annotated[str | None, Query(description="Specific scan ID, defaults to latest")] = None,
) -> DependencyGraph:
    """Get the dependency graph for a project as flat nodes + roots (client nests lazily)."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_TREE)
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_VIEWER)

    dep_repo = DependencyRepository(db)
    finding_repo = FindingRepository(db)

    if scan_id:
        if not await ScanRepository(db).count({"_id": scan_id, "project_id": project_id}, limit=1):
            raise HTTPException(status_code=404, detail="No scan found for this project")
    else:
        scan_id = await _resolve_scan_id(project_id, db)

    if not scan_id:
        return DependencyGraph()

    dependencies, dependencies_total = await dep_repo.find_by_scan(
        project_id, scan_id, limit=SCAN_DEPENDENCY_READ_LIMIT
    )

    if not dependencies:
        return DependencyGraph()

    details_by_component = await vuln_details_by(
        finding_repo, "component", {"project_id": project_id, "scan_id": scan_id}
    )
    findings_map = build_component_index(
        {component: severity_counts_from_details(details) for component, details in details_by_component.items()}
    )

    return _build_dependency_graph(dependencies, findings_map, dependencies_total)


@router.get("/component-findings", responses=RESP_AUTH)
async def get_component_findings(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    component: Annotated[str, Query(description="Component/package name")],
    version: Annotated[str | None, Query(description="Specific version")] = None,
    release_environment: ReleaseEnvironmentQuery = None,
) -> list[dict[str, Any]]:
    """Get all findings for a specific component across accessible projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_SEARCH)

    project_ids = await get_user_project_ids(current_user, db)

    if not project_ids:
        return []

    # Same scope resolution as the tables that link here, or a component the hotspot ranking
    # found in the release is looked up against the branch tip and reads as having no findings.
    project_name_map, scan_ids = await get_projects_with_scans(project_ids, db, release_environment=release_environment)

    if not scan_ids:
        return []

    finding_repo = FindingRepository(db)

    # Waived findings are excluded here as everywhere else, so this list agrees with the
    # severity tiles and the hotspot ranking for the same scan.
    query = await _package_finding_query(finding_repo, scan_ids, component, version)
    finding_records = await finding_repo.find_many(query, limit=100)

    results = []
    for fr in finding_records:
        finding = fr.model_dump()
        finding["project_name"] = project_name_map.get(fr.project_id, "Unknown")
        results.append(finding)

    return results


def _build_dep_query(scan_ids: list[str], component: str, version: str | None, type: str | None) -> dict[str, Any]:
    """Dependency filter for a component name that may arrive group-qualified.

    The Hotspots and Impact tabs hand this endpoint a finding component, which the inventory
    stores under its bare artifact name, so both spellings are candidates.
    """
    dep_query: dict[str, Any] = {"scan_id": {"$in": scan_ids}, "name": {"$in": component_name_candidates(component)}}
    if version:
        dep_query["version"] = version
    if type:
        dep_query["type"] = type
    return dep_query


async def _package_projects_by_version(
    dep_repo: DependencyRepository, dep_query: dict[str, Any], component: str
) -> tuple[tuple[str, str], dict[str, list[dict[str, Any]]]] | None:
    """The one package ``component`` names in the inventory, with the projects using each version.

    A qualified component keeps the package whose identity is ``qualifier/artifact``; a name that
    still spans several packages yields None rather than one package's data under another's name.
    """
    artifact = artifact_segment(component)
    wanted = None if artifact == component else f"{component[: -len(artifact) - 1]}/{artifact}".lower()
    rows = await dep_repo.aggregate(
        [
            {"$match": dep_query},
            {
                "$group": {
                    "_id": {"package": package_identity_expr(), "version": "$version"},
                    "projects": {"$addToSet": {"id": "$project_id", "direct": "$direct"}},
                }
            },
        ]
    )
    by_package: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = {}
    for row in rows:
        package = (row["_id"]["package"]["type"], row["_id"]["package"]["path"])
        if wanted is None or package[1].lower() == wanted:
            by_package.setdefault(package, {})[row["_id"].get("version")] = row["projects"]
    return next(iter(by_package.items())) if len(by_package) == 1 else None


def _affected_projects(
    projects_by_version: dict[str, list[dict[str, Any]]], project_name_map: dict[str, str]
) -> dict[str, dict[str, Any]]:
    affected: dict[str, dict[str, Any]] = {}
    for projects in projects_by_version.values():
        for project in projects:
            if not project.get("id"):
                continue
            entry = affected.setdefault(
                project["id"],
                {"id": project["id"], "name": project_name_map.get(project["id"], "Unknown"), "direct": False},
            )
            entry["direct"] = entry["direct"] or bool(project.get("direct"))
    return affected


def _first_dep_value(dependencies: list[Any], key: str) -> Any | None:
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
    version: Annotated[str | None, Query(description="Specific version")] = None,
    type: Annotated[str | None, Query(description="Package type")] = None,
    release_environment: ReleaseEnvironmentQuery = None,
) -> DependencyMetadata | None:
    """Aggregated dependency metadata across accessible projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_SEARCH)

    project_ids = await get_user_project_ids(current_user, db)
    if not project_ids:
        return None

    scan_ids = await get_latest_scan_ids(project_ids, db, release_environment=release_environment)
    if not scan_ids:
        return None

    dep_repo = DependencyRepository(db)
    finding_repo = FindingRepository(db)
    project_repo = ProjectRepository(db)
    enrichment_repo = DependencyEnrichmentRepository(db)

    dep_query = _build_dep_query(scan_ids, component, version, type)
    usage = await _package_projects_by_version(dep_repo, dep_query, component)
    if usage is None:
        return None
    package, projects_by_version = usage
    # Without a version, the modal describes the version most projects run.
    shown_version = version or max(
        projects_by_version,
        key=lambda v: (len({p.get("id") for p in projects_by_version[v]}), parse_version_key(v or ""), v or ""),
    )
    dependencies = [
        dep
        for dep in await dep_repo.find_many({**dep_query, "version": shown_version}, limit=100)
        if package_identity(
            get_attr(dep, "purl"), get_attr(dep, "name", ""), get_attr(dep, "type"), get_attr(dep, "group")
        )
        == package
    ]
    if not dependencies:
        return None

    projects = await project_repo.find_many_minimal(
        {"_id": {"$in": project_ids}},
        limit=ANALYTICS_MAX_QUERY_LIMIT,
    )
    project_name_map = {p.id: p.name for p in projects}

    first_dep = dependencies[0]
    affected_projects = _affected_projects(projects_by_version, project_name_map)

    dep_purl = get_attr(first_dep, "purl")
    enrichment_info = await _get_enrichment_info(enrichment_repo, dep_purl)

    finding_query = await _package_finding_query(finding_repo, scan_ids, component, version)
    finding_count = await finding_repo.count(finding_query)
    package_details = await vuln_details_by(finding_repo, "component", finding_query)
    vuln_count = len(live_cves([details for per_component in package_details.values() for details in per_component]))

    return DependencyMetadata(
        name=get_attr(first_dep, "name", component),
        version=get_attr(first_dep, "version", version or "unknown"),
        versions=sorted((v for v in projects_by_version if v), key=lambda v: (parse_version_key(v), v), reverse=True),
        type=get_attr(first_dep, "type", "unknown"),
        purl=dep_purl,
        description=_first_dep_value(dependencies, "description") or enrichment_info["description"],
        author=_first_dep_value(dependencies, "author"),
        publisher=_first_dep_value(dependencies, "publisher"),
        homepage=_first_dep_value(dependencies, "homepage") or enrichment_info["homepage"],
        repository_url=_first_dep_value(dependencies, "repository_url") or enrichment_info["repository_url"],
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
