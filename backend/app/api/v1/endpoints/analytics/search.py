"""Analytics search endpoints: /search and /vulnerability-search."""

import re
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
from app.core.constants import DETAILS_KEY_IN_KEV, DETAILS_KEY_KEV_RANSOMWARE, get_severity_value
from app.core.permissions import Permissions
from app.models.dependency import Dependency
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


def _passes_vuln_filter(
    dep: Dependency, has_vulnerabilities: bool | None, vuln_versions: dict[str, dict[str, set[str]]]
) -> bool:
    if has_vulnerabilities is None:
        return True
    versions = lookup_component(vuln_versions.get(dep.project_id, {}), dep.name) or set()
    # A finding without a version cannot tell the package's versions apart, so it covers them all.
    has_vulns = "unknown" in versions or normalize_version(dep.version) in versions
    return has_vulnerabilities == has_vulns


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


def _build_search_results(
    dependencies: list[Dependency],
    has_vulnerabilities: bool | None,
    vuln_versions: dict[str, dict[str, set[str]]],
    project_name_map: dict[str, str],
) -> list[DependencySearchResult]:
    return [
        _dep_to_search_result(dep, project_name_map)
        for dep in dependencies
        if _passes_vuln_filter(dep, has_vulnerabilities, vuln_versions)
    ]


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
    finding_repo = FindingRepository(db)

    query = {"scan_id": {"$in": scan_ids}, "name": {"$regex": re.escape(q), "$options": "i"}}
    if version:
        query["version"] = version
    if type:
        query["type"] = type
    if source_type:
        query["source_type"] = source_type

    total_count = await dep_repo.count(query)

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

    dependencies = await dep_repo.find_many(
        query,
        skip=skip,
        limit=limit,
        sort_by=mongo_sort_field,
        sort_order=sort_direction,
    )

    vuln_versions: dict[str, dict[str, set[str]]] = {}
    if has_vulnerabilities is not None and dependencies:
        dep_keys = list({(dep.project_id, dep.name) for dep in dependencies})

        # No component filter: a finding's component can be a qualified form of the
        # dependency name, which no $in list over inventory names can express.
        vuln_pipeline: list[dict[str, Any]] = [
            {
                "$match": {
                    "scan_id": {"$in": scan_ids},
                    "project_id": {"$in": [k[0] for k in dep_keys]},
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
        vuln_results = await finding_repo.aggregate(vuln_pipeline)
        by_project: dict[str, dict[str, set[str]]] = {}
        for r in vuln_results:
            versions = {normalize_version(v) for v in r["versions"]}
            by_project.setdefault(r["_id"]["project_id"], {})[r["_id"]["component"]] = versions
        vuln_versions = {pid: build_component_index(components) for pid, components in by_project.items()}

    results = _build_search_results(dependencies, has_vulnerabilities, vuln_versions, project_name_map)

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
    finding_type: str | None,
    include_waived: bool,
) -> dict[str, Any]:
    search_regex = {"$regex": re.escape(q), "$options": "i"}
    clauses: list[dict[str, Any]] = [
        {
            "$or": [
                {"id": search_regex},
                {"aliases": search_regex},
                {"description": search_regex},
                {"details.vulnerabilities.id": search_regex},
                {"details.vulnerabilities.resolved_cve": search_regex},
            ]
        }
    ]
    if severity:
        # A document carries its worst advisory's severity, so a HIGH CVE can sit in a CRITICAL one.
        sev = severity.upper()
        clauses.append({"$or": [{"severity": sev}, {"details.vulnerabilities.severity": sev}]})
    query: dict[str, Any] = {"scan_id": {"$in": scan_ids}, "$and": clauses}
    if finding_type:
        query["type"] = finding_type
    if not include_waived:
        query["waived"] = {"$ne": True}
    return query


_VULN_SORT_FIELD_MAP = {
    "severity": "severity",
    # CVSS only exists per CVE; Mongo sorts array paths by max (desc) / min (asc).
    "cvss": "details.vulnerabilities.cvss_score",
    "epss": "details.epss_score",
    "component": "component",
    "project_name": "project_id",
}


def _vuln_results_for_finding(
    finding: FindingRecord, query_lower: str, project_name_map: dict[str, str]
) -> list[VulnerabilitySearchResult]:
    """One row per advisory the query names, else one row for the whole finding."""
    details = finding.details
    matched_vulns = [
        vuln
        for vuln in details.get("vulnerabilities", [])
        if query_lower in vuln.get("id", "").lower() or query_lower in vuln.get("resolved_cve", "").lower()
    ]
    if not matched_vulns:
        return [_build_direct_vuln_result(finding, details, project_name_map)]
    return [_build_nested_vuln_result(vuln, finding, project_name_map) for vuln in matched_vulns]


def _row_matches(
    row: VulnerabilitySearchResult,
    severity: str | None,
    in_kev: bool | None,
    has_fix: bool | None,
    include_waived: bool,
) -> bool:
    return (
        (include_waived or not row.waived)
        and (severity is None or row.severity == severity.upper())
        and (in_kev is None or row.in_kev == in_kev)
        and (has_fix is None or bool(row.fixed_version) == has_fix)
    )


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

    query = _build_vuln_query(scan_ids, q, severity, finding_type, include_waived)

    total_count = await finding_repo.count(query)

    mongo_sort_field = _VULN_SORT_FIELD_MAP.get(sort_by, "severity")
    sort_direction = parse_sort_direction(sort_order)

    findings = await finding_repo.find_many(
        query,
        skip=skip,
        limit=limit,
        sort_by=mongo_sort_field,
        sort_order=sort_direction,
    )

    query_lower = q.lower()
    results = [
        row
        for finding in findings
        for row in _vuln_results_for_finding(finding, query_lower, project_name_map)
        if _row_matches(row, severity, in_kev, has_fix, include_waived)
    ]

    # MongoDB can't sort by severity order, so resort in Python with the rank map.
    if sort_by == "severity":
        results.sort(
            key=lambda x: get_severity_value(x.severity),
            reverse=sort_direction == -1,
        )

    return VulnerabilitySearchResponse(items=results, **page_meta(total_count, skip, limit), **counts)
