"""Analytics dependency endpoints: dependency-tree, component-findings, dependency-metadata."""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import Query

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    ReleaseEnvironmentQuery,
    get_projects_with_scans,
    get_user_projects,
    require_analytics_permission,
    severity_counts_from_details,
    vuln_details_by,
)
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_404
from app.core.constants import SCAN_DEPENDENCY_READ_LIMIT
from app.core.permissions import Permissions
from app.models.dependency import Dependency
from app.repositories.dependencies import DependencyRepository
from app.repositories.dependency_enrichments import DependencyEnrichmentRepository
from app.repositories.findings import FindingRepository
from app.schemas.analytics import (
    DependencyGraph,
    DependencyMetadata,
    DependencyTreeNode,
    SeverityBreakdown,
)
from app.core.purl import get_purl_type, package_identity, package_identity_expr
from app.services.component_identity import (
    artifact_segment,
    build_component_index,
    cluster_by_package_identity,
    component_match_query,
    component_name_candidates,
    lookup_component,
    normalize_component,
)
from app.services.aggregation.versions import newest_first, normalize_version, parse_version_key
from app.services.recommendation.common import live_cves
from app.services.recommendation.graph import build_dependency_edges

from ._shared import resolve_project_scan_id

router = CustomAPIRouter()

# Live advisory details per component, then per normalized version.
TreeFindings = dict[str, dict[str, list[Any]]]


@dataclass(frozen=True)
class EnrichmentInfo:
    deps_dev: dict[str, Any] | None = None
    enrichment_sources: list[str] = field(default_factory=list)
    license_category: str | None = None
    license_risks: list[str] = field(default_factory=list)
    license_obligations: list[str] = field(default_factory=list)
    description: str | None = None
    homepage: str | None = None
    repository_url: str | None = None


async def _get_enrichment_info(enrichment_repo: DependencyEnrichmentRepository, purl: str | None) -> EnrichmentInfo:
    enrichment = await enrichment_repo.get_by_purl(purl) if purl else None
    if not enrichment:
        return EnrichmentInfo()
    # Dependency docs only carry parser-declared metadata; deps.dev-derived description/links live solely here.
    # DependencyEnrichment.to_mongo_dict() stores the license fields top-level, not nested under license_compliance.
    return EnrichmentInfo(
        deps_dev=enrichment.get("deps_dev"),
        enrichment_sources=enrichment.get("enrichment_sources") or [],
        license_category=enrichment.get("license_category"),
        license_risks=enrichment.get("license_risks") or [],
        license_obligations=enrichment.get("license_obligations") or [],
        description=enrichment.get("description"),
        homepage=enrichment.get("homepage"),
        repository_url=enrichment.get("repository_url"),
    )


async def _package_finding_query(
    finding_repo: FindingRepository, scan_ids: list[str], component: str, version: str | None
) -> dict[str, Any]:
    """Finding filter for every spelling of ``component``; a bare name joins a qualified package only if unique."""
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


def _tree_findings_map(details_by_package: dict[tuple[Any, ...], list[Any]]) -> TreeFindings:
    details_by_component: TreeFindings = defaultdict(lambda: defaultdict(list))
    for (component, version), details in details_by_package.items():
        details_by_component[component][normalize_version(version)] += details
    return build_component_index(details_by_component)


def _build_tree_node(dep: Dependency, findings_map: TreeFindings, *, direct: bool) -> DependencyTreeNode:
    """Build one node without its children; the graph builder fills in child_ids."""
    # The bare-artifact alias keys are lowercased, dependency names are not.
    by_version = lookup_component(findings_map, dep.name) or {}
    # A finding without a version cannot tell the package's versions apart, so it covers them all.
    details = by_version.get(normalize_version(dep.version), []) + by_version.get("unknown", [])
    finding_info = severity_counts_from_details(details) if details else {}
    findings_count = sum(finding_info.values())

    return DependencyTreeNode(
        id=dep.id,
        name=dep.name,
        version=dep.version,
        purl=dep.purl or "",
        type=dep.type,
        direct=direct,
        direct_inferred=dep.direct_inferred,
        has_findings=findings_count > 0,
        findings_count=findings_count,
        findings_severity=SeverityBreakdown.from_counts(finding_info) if finding_info else None,
        source_type=dep.source_type,
        source_target=dep.source_target,
        layer_digest=dep.layer_digest,
        locations=dep.locations,
        child_ids=[],
    )


def _build_dependency_graph(
    dependencies: list[Dependency],
    findings_map: TreeFindings,
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
    project = await check_project_access(project_id, current_user, db)

    dep_repo = DependencyRepository(db)
    finding_repo = FindingRepository(db)

    scan_id = await resolve_project_scan_id(db, project, scan_id)
    if not scan_id:
        return DependencyGraph()

    dependencies, dependencies_total = await dep_repo.find_by_scan(
        project_id, scan_id, limit=SCAN_DEPENDENCY_READ_LIMIT
    )

    if not dependencies:
        return DependencyGraph()

    details_by_package = await vuln_details_by(
        finding_repo, {"project_id": project_id, "scan_id": scan_id}, "component", "version"
    )
    return _build_dependency_graph(dependencies, _tree_findings_map(details_by_package), dependencies_total)


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

    projects = await get_user_projects(current_user, db)

    if not projects:
        return []

    # Same scope resolution as the tables that link here, or a component the hotspot ranking
    # found in the release is looked up against the branch tip and reads as having no findings.
    project_name_map, scan_ids = await get_projects_with_scans(projects, db, release_environment=release_environment)

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
) -> tuple[str, dict[str, list[dict[str, Any]]]] | None:
    """The one package path ``component`` names with its projects per version; None while the name spans several."""
    artifact = artifact_segment(component)
    wanted = None if artifact == component else f"{component[: -len(artifact) - 1]}/{artifact}".lower()
    rows = await dep_repo.aggregate(
        [
            {"$match": dep_query},
            {
                "$group": {
                    "_id": {
                        "package": package_identity_expr(),
                        "version": "$version",
                        "has_purl": {"$gt": ["$purl", ""]},
                    },
                    "projects": {"$addToSet": {"id": "$project_id", "direct": "$direct"}},
                }
            },
        ]
    )
    # Only a non-generic purl names an ecosystem: a pkg:generic row joins its npm row, npm and pypi stay apart.
    by_package: dict[str, dict[str, list[dict[str, Any]]]] = {}
    purl_types: set[str] = set()
    for row in rows:
        package = row["_id"]["package"]
        if wanted is None or package["path"].lower() == wanted:
            by_package.setdefault(package["path"], {}).setdefault(row["_id"].get("version"), []).extend(row["projects"])
            if row["_id"]["has_purl"] and package["type"] != "generic":
                purl_types.add(package["type"])
    return next(iter(by_package.items())) if len(by_package) == 1 and len(purl_types) <= 1 else None


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


def _first_dep_value(dependencies: list[Dependency], key: str) -> Any | None:
    for dep in dependencies:
        val = getattr(dep, key)
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

    projects = await get_user_projects(current_user, db)
    if not projects:
        return None

    project_name_map, scan_ids = await get_projects_with_scans(projects, db, release_environment=release_environment)
    if not scan_ids:
        return None

    dep_repo = DependencyRepository(db)
    finding_repo = FindingRepository(db)
    enrichment_repo = DependencyEnrichmentRepository(db)

    dep_query = _build_dep_query(scan_ids, component, version, type)
    usage = await _package_projects_by_version(dep_repo, dep_query, component)
    if usage is None:
        return None
    path, projects_by_version = usage
    # Without a version, the modal describes the version most projects run.
    shown_version = version or max(
        projects_by_version,
        key=lambda v: (len({p.get("id") for p in projects_by_version[v]}), parse_version_key(v or ""), v or ""),
    )
    dependencies = [
        dep
        for dep in await dep_repo.find_many({**dep_query, "version": shown_version}, limit=100)
        if package_identity(dep.purl, dep.name, dep.type, dep.group)[1] == path
    ]
    if not dependencies:
        return None

    # A purl row names the package's real type and keys its enrichment; a pkg:generic one names neither.
    first_dep = min(dependencies, key=lambda dep: (not dep.purl, get_purl_type(dep.purl) == "generic"))
    affected_projects = _affected_projects(projects_by_version, project_name_map)

    info = await _get_enrichment_info(enrichment_repo, first_dep.purl)

    finding_query = await _package_finding_query(finding_repo, scan_ids, component, version)
    finding_count = await finding_repo.count(finding_query)
    package_details = await vuln_details_by(finding_repo, finding_query, "component")
    vuln_count = len(live_cves([details for per_component in package_details.values() for details in per_component]))

    return DependencyMetadata(
        name=first_dep.name,
        version=first_dep.version,
        versions=newest_first(v for v in projects_by_version if v),
        type=first_dep.type,
        purl=first_dep.purl,
        description=_first_dep_value(dependencies, "description") or info.description,
        author=_first_dep_value(dependencies, "author"),
        publisher=_first_dep_value(dependencies, "publisher"),
        homepage=_first_dep_value(dependencies, "homepage") or info.homepage,
        repository_url=_first_dep_value(dependencies, "repository_url") or info.repository_url,
        download_url=_first_dep_value(dependencies, "download_url"),
        group=_first_dep_value(dependencies, "group"),
        license=_first_dep_value(dependencies, "license"),
        license_url=_first_dep_value(dependencies, "license_url"),
        license_category=info.license_category,
        license_risks=info.license_risks,
        license_obligations=info.license_obligations,
        deps_dev=info.deps_dev,
        project_count=len(affected_projects),
        affected_projects=list(affected_projects.values()),
        total_vulnerability_count=vuln_count,
        total_finding_count=finding_count,
        enrichment_sources=info.enrichment_sources,
    )
