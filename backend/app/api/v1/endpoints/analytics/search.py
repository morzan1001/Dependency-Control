"""Analytics search endpoints: /search and /vulnerability-search."""

import re
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    ReleaseEnvironmentQuery,
    get_projects_with_scans,
    get_user_projects,
    require_analytics_permission,
    scope_resolution_counts,
)
from app.api.v1.helpers.pagination import page_meta
from app.api.v1.helpers.responses import RESP_AUTH
from app.api.v1.helpers.sorting import SortOrderQuery, parse_sort_direction
from app.core.cve import canonical_cve
from app.core.constants import (
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
    get_severity_value,
    severity_rank_expr,
)
from app.core.permissions import Permissions
from app.models.dependency import Dependency
from app.models.finding import FindingType
from app.models.finding_record import FindingRecord
from app.models.user import User
from app.repositories.dependencies import DependencyRepository
from app.repositories.findings import FindingRepository
from app.schemas.analytics import (
    DependencySearchResponse,
    DependencySearchResult,
    VulnerabilitySearchResponse,
    VulnerabilitySearchResult,
)
from app.services.aggregation.versions import normalize_version
from app.services.component_identity import build_component_index, lookup_component
from app.services.recommendation.common import max_advisory_cvss

router = CustomAPIRouter()


async def _resolve_search_scope(
    current_user: User, db: AsyncIOMotorDatabase, project_ids: str | None, release_environment: str | None
) -> tuple[dict[str, str], list[str], dict[str, int]]:
    """(project names, scans to search, scope counters) over the caller's projects, narrowed to ``project_ids``."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_SEARCH)
    projects = await get_user_projects(current_user, db)
    if project_ids:
        requested = {pid.strip() for pid in project_ids.split(",")}
        projects = [p for p in projects if p.id in requested]
    project_name_map, scan_ids = await get_projects_with_scans(projects, db, release_environment=release_environment)
    resolved, without_release = scope_resolution_counts([p.id for p in projects], scan_ids)
    return project_name_map, scan_ids, {"resolved_projects": resolved, "projects_without_release": without_release}


async def _dependency_ids_by_vulnerability(
    db: AsyncIOMotorDatabase,
    query: dict[str, Any],
    scan_ids: list[str],
    has_vulnerabilities: bool,
    sort: dict[str, int],
) -> list[str]:
    """Ids, in ``sort`` order, of the dependencies matching ``query`` whose vulnerability status is ``has_vulnerabilities``."""
    candidates = await DependencyRepository(db).aggregate(
        [{"$match": query}, {"$sort": sort}, {"$project": {"project_id": 1, "name": 1, "version": 1}}]
    )
    # No component filter: a finding's component can be a qualified form of the
    # dependency name, which no $in list over inventory names can express.
    vuln_pipeline: list[dict[str, Any]] = [
        {
            "$match": {
                "scan_id": {"$in": scan_ids},
                "project_id": {"$in": list({dep["project_id"] for dep in candidates})},
                "type": "vulnerability",
                "waived": {"$ne": True},
            }
        },
        {
            "$group": {
                "_id": {"project_id": "$project_id", "component": "$component"},
                "versions": {"$addToSet": {"$ifNull": ["$version", ""]}},
            }
        },
    ]
    by_project: dict[str, dict[str, set[str]]] = {}
    for r in await FindingRepository(db).aggregate(vuln_pipeline):
        versions = {normalize_version(v) for v in r["versions"]}
        by_project.setdefault(r["_id"]["project_id"], {})[r["_id"]["component"]] = versions
    vuln_versions = {pid: build_component_index(components) for pid, components in by_project.items()}

    def is_vulnerable(dep: dict[str, Any]) -> bool:
        versions = lookup_component(vuln_versions.get(dep["project_id"], {}), dep["name"]) or set()
        # A finding without a version cannot tell the package's versions apart, so it covers them all.
        return "unknown" in versions or normalize_version(dep["version"]) in versions

    return [dep["_id"] for dep in candidates if is_vulnerable(dep) == has_vulnerabilities]


def _dep_to_search_result(dep: Dependency, project_name_map: dict[str, str]) -> DependencySearchResult:
    return DependencySearchResult(
        project_id=dep.project_id,
        project_name=project_name_map.get(dep.project_id, "Unknown"),
        package=dep.name,
        version=dep.version,
        type=dep.type,
        license=dep.license,
        license_url=dep.license_url,
        direct=dep.direct,
        purl=dep.purl,
        source_type=dep.source_type,
        source_target=dep.source_target,
        layer_digest=dep.layer_digest,
        found_by=dep.found_by,
        locations=dep.locations,
        cpes=dep.cpes,
        description=dep.description,
        author=dep.author,
        publisher=dep.publisher,
        group=dep.group,
        homepage=dep.homepage,
        repository_url=dep.repository_url,
        download_url=dep.download_url,
        hashes=dep.hashes,
        properties=dep.properties,
    )


@router.get("/search", responses=RESP_AUTH)
async def search_dependencies_advanced(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    q: Annotated[str, Query(min_length=2, description="Search query for package name")],
    version: Annotated[str | None, Query(description="Filter by specific version")] = None,
    type: Annotated[str | None, Query(description="Filter by package type")] = None,
    source_type: Annotated[
        str | None,
        Query(description="Filter by source type (image, directory, file, application)"),
    ] = None,
    has_vulnerabilities: Annotated[bool | None, Query(description="Filter by vulnerability status")] = None,
    project_ids: Annotated[str | None, Query(description="Comma-separated list of project IDs")] = None,
    sort_by: Annotated[
        str,
        Query(description="Sort field: name, version, type, project_name, license, direct"),
    ] = "name",
    sort_order: SortOrderQuery = "asc",
    release_environment: ReleaseEnvironmentQuery = None,
    skip: Annotated[int, Query(ge=0, description="Number of items to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> DependencySearchResponse:
    """Advanced dependency search with multiple filters and pagination."""
    project_name_map, scan_ids, counts = await _resolve_search_scope(current_user, db, project_ids, release_environment)
    if not scan_ids:
        return DependencySearchResponse(items=[], **page_meta(0, skip, limit), **counts)

    dep_repo = DependencyRepository(db)

    query = {"scan_id": {"$in": scan_ids}, "name": {"$regex": re.escape(q), "$options": "i"}}
    if version:
        query["version"] = version
    if type:
        query["type"] = type
    if source_type:
        query["source_type"] = source_type

    sort_field_map = {
        "name": "name",
        "version": "version",
        "type": "type",
        "project_name": "project_id",  # sorts by project_id, not name
        "license": "license",
        "direct": "direct",
    }
    mongo_sort_field = sort_field_map.get(sort_by, "name")
    sort_direction = parse_sort_direction(sort_order)

    if has_vulnerabilities is None:
        total_count = await dep_repo.count(query)
        dependencies = await dep_repo.find_many(
            query, skip=skip, limit=limit, sort_by=mongo_sort_field, sort_order=sort_direction
        )
    else:
        sort = {mongo_sort_field: sort_direction, "_id": 1}
        matching = await _dependency_ids_by_vulnerability(db, query, scan_ids, has_vulnerabilities, sort)
        total_count = len(matching)
        dependencies = await dep_repo.find_many(
            {"_id": {"$in": matching[skip : skip + limit]}},
            limit=limit,
            sort_by=mongo_sort_field,
            sort_order=sort_direction,
        )

    results = [_dep_to_search_result(dep, project_name_map) for dep in dependencies]
    return DependencySearchResponse(items=results, **page_meta(total_count, skip, limit), **counts)


_DESCRIPTION_CHARS = 200


def _finding_fields(finding: FindingRecord, project_name_map: dict[str, str]) -> dict[str, Any]:
    return {
        "component": finding.component,
        "version": finding.version or "",
        "project_id": finding.project_id,
        "project_name": project_name_map.get(finding.project_id, "Unknown"),
        "scan_id": finding.scan_id,
        "finding_id": finding.finding_id,
        "finding_type": finding.type,
    }


def _build_direct_vuln_result(
    finding: FindingRecord, details: dict[str, Any], project_name_map: dict[str, str]
) -> VulnerabilitySearchResult:
    return VulnerabilitySearchResult(
        **_finding_fields(finding, project_name_map),
        vulnerability_id=finding.finding_id,
        aliases=finding.aliases,
        severity=finding.severity,
        cvss_score=max_advisory_cvss(details),
        epss_score=details.get("epss_score"),
        epss_percentile=details.get("epss_percentile"),
        in_kev=bool(details.get(DETAILS_KEY_IN_KEV)),
        kev_ransomware=bool(details.get(DETAILS_KEY_KEV_RANSOMWARE)),
        kev_due_date=details.get("kev_due_date"),
        description=finding.description[:_DESCRIPTION_CHARS] or None,
        fixed_version=details.get("fixed_version"),
        waived=finding.waived,
        waiver_reason=finding.waiver_reason,
    )


def _build_nested_vuln_result(
    vuln: dict[str, Any], finding: FindingRecord, project_name_map: dict[str, str]
) -> VulnerabilitySearchResult:
    vulnerability_id = canonical_cve(vuln) or finding.finding_id
    return VulnerabilitySearchResult(
        **_finding_fields(finding, project_name_map),
        vulnerability_id=vulnerability_id,
        aliases=sorted({vuln.get("id"), *(vuln.get("aliases") or [])} - {vulnerability_id, None}),
        severity=vuln.get("severity") or finding.severity,
        cvss_score=vuln.get("cvss_score"),
        epss_score=vuln.get("epss_score"),
        epss_percentile=vuln.get("epss_percentile"),
        in_kev=bool(vuln.get(DETAILS_KEY_IN_KEV)),
        kev_ransomware=bool(vuln.get(DETAILS_KEY_KEV_RANSOMWARE)),
        kev_due_date=vuln.get("kev_due_date"),
        description=(vuln.get("description") or finding.description)[:_DESCRIPTION_CHARS] or None,
        fixed_version=vuln.get("fixed_version"),
        waived=bool(vuln.get("waived")) or finding.waived,
        waiver_reason=vuln.get("waiver_reason") or finding.waiver_reason,
    )


def _build_vuln_query(
    scan_ids: list[str],
    q: str,
    severity: str | None,
    in_kev: bool | None,
    has_fix: bool | None,
    finding_type: str | None,
    include_waived: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """(query, rows): findings with a row that passes the filters; a row is a named advisory, else the finding."""
    pattern = re.escape(q)
    search_regex = {"$regex": pattern, "$options": "i"}
    names_advisory = {"$or": [{"id": search_regex}, {"resolved_cve": search_regex}]}
    advisory_row: dict[str, Any] = {}
    finding_row: dict[str, Any] = {}
    names_row = [
        {"$regexMatch": {"input": {"$ifNull": [f"$$v.{field}", ""]}, "regex": pattern, "options": "i"}}
        for field in ("id", "resolved_cve")
    ]
    row_conds: list[dict[str, Any]] = [{"$or": names_row}]
    if severity:
        advisory_row["severity"] = finding_row["severity"] = severity.upper()
        row_conds.append({"$eq": ["$$v.severity", severity.upper()]})
    if in_kev is not None:
        kev = True if in_kev else {"$ne": True}
        advisory_row[DETAILS_KEY_IN_KEV] = finding_row[f"details.{DETAILS_KEY_IN_KEV}"] = kev
        listed = {"$eq": [f"$$v.{DETAILS_KEY_IN_KEV}", True]}
        row_conds.append(listed if in_kev else {"$not": [listed]})
    if has_fix is not None:
        fix = {"$nin": [None, ""]} if has_fix else {"$in": [None, ""]}
        advisory_row["fixed_version"] = finding_row["details.fixed_version"] = fix
        unfixed = {"$in": [{"$ifNull": ["$$v.fixed_version", None]}, [None, ""]]}
        row_conds.append({"$not": [unfixed]} if has_fix else unfixed)
    if not include_waived:
        advisory_row["waived"] = {"$ne": True}
        row_conds.append({"$ne": ["$$v.waived", True]})
    query: dict[str, Any] = {
        "scan_id": {"$in": scan_ids},
        "$or": [
            {"details.vulnerabilities": {"$elemMatch": {**names_advisory, **advisory_row}}},
            {
                **finding_row,
                "$nor": [{"details.vulnerabilities": {"$elemMatch": names_advisory}}],
                "$or": [
                    {"id": search_regex},
                    {"aliases": search_regex},
                    {"type": {"$ne": FindingType.VULNERABILITY.value}, "description": search_regex},
                ],
            },
        ],
    }
    if finding_type:
        query["type"] = finding_type
    if not include_waived:
        query["waived"] = {"$ne": True}
    rows = {"$filter": {"input": {"$ifNull": ["$details.vulnerabilities", []]}, "as": "v", "cond": {"$and": row_conds}}}
    return query, rows


_RowKey = Callable[[VulnerabilitySearchResult], float]

# sort_by -> (value over a finding's advisory rows, value of a finding that is its own row, order of its rows)
_VULN_SORTS: dict[str, tuple[Any, Any, _RowKey | None]] = {
    "severity": (
        {"$map": {"input": "$rows", "as": "v", "in": severity_rank_expr({"$ifNull": ["$$v.severity", "$severity"]})}},
        severity_rank_expr("$severity"),
        lambda row: get_severity_value(row.severity),
    ),
    "cvss": ("$rows.cvss_score", {"$max": "$details.vulnerabilities.cvss_score"}, lambda row: row.cvss_score or 0.0),
    "epss": ("$rows.epss_score", "$details.epss_score", lambda row: row.epss_score or 0.0),
    "component": ("$component", "$component", None),
    "project_name": ("$project_id", "$project_id", None),
}


def _vuln_results_for_finding(
    finding: FindingRecord, rows: list[dict[str, Any]], project_name_map: dict[str, str]
) -> list[VulnerabilitySearchResult]:
    if not rows:
        return [_build_direct_vuln_result(finding, finding.details, project_name_map)]
    return [_build_nested_vuln_result(vuln, finding, project_name_map) for vuln in rows]


@router.get("/vulnerability-search", responses=RESP_AUTH)
async def search_vulnerabilities(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    q: Annotated[
        str,
        Query(min_length=2, description="Search query for CVE, GHSA, or other vulnerability identifiers"),
    ],
    severity: Annotated[str | None, Query(description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW")] = None,
    in_kev: Annotated[bool | None, Query(description="Filter by CISA KEV inclusion")] = None,
    has_fix: Annotated[bool | None, Query(description="Filter by fix availability")] = None,
    finding_type: Annotated[
        str | None, Query(description="Filter by finding type: vulnerability, license, secret, etc.")
    ] = None,
    project_ids: Annotated[str | None, Query(description="Comma-separated list of project IDs")] = None,
    include_waived: Annotated[bool, Query(description="Include waived findings")] = False,
    sort_by: Annotated[
        str,
        Query(description="Sort field: severity, cvss, epss, component, project_name"),
    ] = "severity",
    sort_order: SortOrderQuery = "desc",
    release_environment: ReleaseEnvironmentQuery = None,
    skip: Annotated[int, Query(ge=0, description="Number of items to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> VulnerabilitySearchResponse:
    """Search vulnerabilities by id, aliases and advisory ids; description matches reach non-vulnerability findings."""
    project_name_map, scan_ids, counts = await _resolve_search_scope(current_user, db, project_ids, release_environment)
    if not scan_ids:
        return VulnerabilitySearchResponse(items=[], **page_meta(0, skip, limit), **counts)

    finding_repo = FindingRepository(db)

    query, rows = _build_vuln_query(scan_ids, q, severity, in_kev, has_fix, finding_type, include_waived)

    total_count = await finding_repo.count(query)

    direction = parse_sort_direction(sort_order)
    rows_value, finding_value, row_key = _VULN_SORTS.get(sort_by, _VULN_SORTS["severity"])
    # A finding pages by its first row in sort order.
    sort_key = {"$cond": [{"$eq": ["$rows", []]}, finding_value, {"$max" if direction < 0 else "$min": rows_value}]}
    findings = await finding_repo.aggregate(
        [
            {"$match": query},
            {"$addFields": {"rows": rows}},
            {"$addFields": {"sort_key": sort_key}},
            {"$sort": {"sort_key": direction, "_id": 1}},
            {"$skip": skip},
            {"$limit": limit},
        ]
    )

    results = []
    for finding in findings:
        finding_rows = _vuln_results_for_finding(FindingRecord(**finding), finding["rows"], project_name_map)
        if row_key:
            finding_rows.sort(key=row_key, reverse=direction < 0)
        results.extend(finding_rows)

    return VulnerabilitySearchResponse(items=results, **page_meta(total_count, skip, limit), **counts)
