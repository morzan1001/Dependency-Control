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
from app.api.v1.helpers.responses import RESP_413, RESP_AUTH
from app.api.v1.helpers.sorting import (
    SortOrderQuery,
    case_insensitive_key,
    case_insensitive_sort,
    parse_sort_direction,
)
from app.core.constants import (
    DEPENDENCIES_SCAN_PACKAGE_INDEX,
    DEPENDENCIES_SCAN_VERSION_INDEX,
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
    FINDINGS_SCAN_TYPE_INDEX,
    get_severity_value,
    severity_rank_expr,
)
from app.core.cve import canonical_cve
from app.core.permissions import Permissions
from app.models.finding import FindingType
from app.models.finding_record import FindingRecord
from app.models.user import User
from app.repositories.base import BaseRepository
from app.repositories.dependencies import DependencyRepository
from app.repositories.findings import FindingRepository
from app.schemas.analytics import (
    DependencySearchResponse,
    DependencySearchResult,
    VulnerabilitySearchResponse,
    VulnerabilitySearchResult,
)
from app.services.aggregation.versions import normalize_version, version_covered
from app.services.component_identity import build_component_index, lookup_component
from app.services.inventory.components import NUMBERED_SORT_FIELDS, TEXT_SORT_FIELDS
from app.services.recommendation.common import max_advisory_cvss

router = CustomAPIRouter(responses=RESP_413)


async def _resolve_search_scope(
    current_user: User, db: AsyncIOMotorDatabase, project_ids: str | None, release_environment: str | None
) -> tuple[dict[str, str], list[str], dict[str, int]]:
    require_analytics_permission(current_user, Permissions.ANALYTICS_SEARCH)
    projects = await get_user_projects(current_user, db)
    if project_ids:
        requested = {pid.strip() for pid in project_ids.split(",")}
        projects = [p for p in projects if p.id in requested]
    project_name_map, scan_ids = await get_projects_with_scans(projects, db, release_environment=release_environment)
    resolved, without_release = scope_resolution_counts([p.id for p in projects], scan_ids)
    return project_name_map, scan_ids, {"resolved_projects": resolved, "projects_without_release": without_release}


async def _page_ids(
    repo: BaseRepository[Any],
    query: dict[str, Any],
    ordered: list[dict[str, Any]],
    skip: int,
    limit: int,
    hint: dict[str, int],
) -> tuple[list[Any], int]:
    """The page carries ids alone: $facet returns one 16 MB document, and one finding can name thousands of advisories."""
    page = [*ordered, {"$skip": skip}, {"$limit": limit}, {"$project": {"_id": 1}}]
    [bucket] = await repo.aggregate(
        [{"$match": query}, {"$facet": {"total": [{"$count": "n"}], "ids": page}}], hint=hint
    )
    return [row["_id"] for row in bucket["ids"]], bucket["total"][0]["n"] if bucket["total"] else 0


_PROJECT_RANK = "_project_rank"


def _project_name_rank(project_name_map: dict[str, str]) -> dict[str, Any]:
    ordered = sorted(project_name_map, key=lambda pid: case_insensitive_key(project_name_map[pid]))
    return {"$indexOfArray": [ordered, "$project_id"]}


async def _dependency_ids_by_vulnerability(
    db: AsyncIOMotorDatabase,
    query: dict[str, Any],
    has_vulnerabilities: bool,
    ordered: list[dict[str, Any]],
    hint: dict[str, int],
) -> list[str]:
    candidates = await DependencyRepository(db).aggregate(
        [{"$match": query}, *ordered, {"$project": {"project_id": 1, "scan_id": 1, "name": 1, "version": 1}}],
        hint=hint,
    )
    # No component filter: a finding's component can be a qualified form no $in over inventory names expresses.
    vuln_pipeline: list[dict[str, Any]] = [
        {
            "$match": {
                "scan_id": {"$in": list({dep["scan_id"] for dep in candidates})},
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
    for r in await FindingRepository(db).aggregate(vuln_pipeline, hint=FINDINGS_SCAN_TYPE_INDEX):
        versions = {normalize_version(v) for v in r["versions"]}
        by_project.setdefault(r["_id"]["project_id"], {})[r["_id"]["component"]] = versions
    vuln_versions = {pid: build_component_index(components) for pid, components in by_project.items()}

    def is_vulnerable(dep: dict[str, Any]) -> bool:
        versions = lookup_component(vuln_versions.get(dep["project_id"], {}), dep["name"]) or set()
        return version_covered(versions, dep["version"])

    return [dep["_id"] for dep in candidates if is_vulnerable(dep) == has_vulnerabilities]


# Every other result field carries the dependency's own field of the same name.
_DEPENDENCY_PROJECTION = dict.fromkeys(
    [*DependencySearchResult.model_fields.keys() - {"project_name", "package"}, "name"], 1
)


def _dep_to_search_result(dep: dict[str, Any], project_name_map: dict[str, str]) -> DependencySearchResult:
    return DependencySearchResult(
        **dep, project_name=project_name_map.get(dep["project_id"], "Unknown"), package=dep["name"]
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
        "project_name": _PROJECT_RANK,
        "license": "license",
        "direct": "direct",
    }
    mongo_sort_field = sort_field_map.get(sort_by, "name")
    ranked = (
        [{"$addFields": {_PROJECT_RANK: _project_name_rank(project_name_map)}}] if sort_by == "project_name" else []
    )
    ordered = [
        *ranked,
        *case_insensitive_sort(
            [(mongo_sort_field, parse_sort_direction(sort_order)), ("_id", 1)], TEXT_SORT_FIELDS, NUMBERED_SORT_FIELDS
        ),
    ]
    # An unanchored name regex bounds no key range, so only an exact version narrows the scan.
    hint = DEPENDENCIES_SCAN_VERSION_INDEX if version else DEPENDENCIES_SCAN_PACKAGE_INDEX

    if has_vulnerabilities is None:
        page, total_count = await _page_ids(dep_repo, query, ordered, skip, limit, hint)
    else:
        matching = await _dependency_ids_by_vulnerability(db, query, has_vulnerabilities, ordered, hint)
        total_count = len(matching)
        page = matching[skip : skip + limit]
    rows = await dep_repo.find_many_raw({"_id": {"$in": page}}, limit=limit, projection=_DEPENDENCY_PROJECTION)
    by_id = {dep["_id"]: dep for dep in rows}

    results = [_dep_to_search_result(by_id[dep_id], project_name_map) for dep_id in page if dep_id in by_id]
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
    if in_kev is not None or has_fix is not None:
        # An outdated finding's fixed_version is its latest release, not a fix for an advisory.
        finding_row["type"] = FindingType.VULNERABILITY.value
    if not include_waived:
        advisory_row["waived"] = {"$ne": True}
        row_conds.append({"$ne": ["$$v.waived", True]})
    query: dict[str, Any] = {
        "scan_id": {"$in": scan_ids},
        "type": finding_type or {"$ne": FindingType.SYSTEM_WARNING.value},
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
    if not include_waived:
        query["waived"] = {"$ne": True}
    rows = {"$filter": {"input": {"$ifNull": ["$details.vulnerabilities", []]}, "as": "v", "cond": {"$and": row_conds}}}
    return query, rows


# FindingRecord's required fields plus every finding field the result rows read; the rows carry their advisories.
_VULN_PAGE_PROJECTION = dict.fromkeys(
    [
        *("id", "scanners", "finding_id", "aliases", "severity", "component", "version", "project_id", "scan_id"),
        *("type", "description", "waived", "waiver_reason", "rows", "details.vulnerabilities.cvss_score"),
        *("details.fixed_version", "details.epss_score", "details.epss_percentile", "details.kev_due_date"),
        f"details.{DETAILS_KEY_IN_KEV}",
        f"details.{DETAILS_KEY_KEV_RANSOMWARE}",
    ],
    1,
)

_RowKey = Callable[[VulnerabilitySearchResult], float]

_VULN_SORTS: dict[str, tuple[Any, Any, _RowKey | None]] = {
    "severity": (
        {"$map": {"input": "$rows", "as": "v", "in": severity_rank_expr({"$ifNull": ["$$v.severity", "$severity"]})}},
        severity_rank_expr("$severity"),
        lambda row: get_severity_value(row.severity),
    ),
    "cvss": ("$rows.cvss_score", {"$max": "$details.vulnerabilities.cvss_score"}, lambda row: row.cvss_score or 0.0),
    "epss": ("$rows.epss_score", "$details.epss_score", lambda row: row.epss_score or 0.0),
    "component": ("$component", "$component", None),
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
        str | None,
        Query(min_length=2, description="Search query for CVE, GHSA, or other vulnerability identifiers"),
    ] = None,
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

    query, rows = _build_vuln_query(scan_ids, q or "", severity, in_kev, has_fix, finding_type, include_waived)

    direction = parse_sort_direction(sort_order)
    if sort_by == "project_name":
        rank = _project_name_rank(project_name_map)
        rows_value, finding_value, row_key = rank, rank, None
    else:
        rows_value, finding_value, row_key = _VULN_SORTS.get(sort_by, _VULN_SORTS["severity"])
    # A finding pages by its first row in sort order.
    sort_key = {"$cond": [{"$eq": ["$rows", []]}, finding_value, {"$max" if direction < 0 else "$min": rows_value}]}
    ordered: list[dict[str, Any]] = [
        {"$addFields": {"rows": rows}},
        {"$addFields": {"sort_key": sort_key}},
        {"$sort": {"sort_key": direction, "_id": 1}},
    ]
    page, total_count = await _page_ids(finding_repo, query, ordered, skip, limit, FINDINGS_SCAN_TYPE_INDEX)
    findings = await finding_repo.aggregate(
        [{"$match": {"_id": {"$in": page}}}, {"$addFields": {"rows": rows}}, {"$project": _VULN_PAGE_PROJECTION}]
    )
    by_id = {finding["_id"]: finding for finding in findings}

    results = []
    for finding in (by_id[finding_id] for finding_id in page if finding_id in by_id):
        finding_rows = _vuln_results_for_finding(FindingRecord(**finding), finding["rows"], project_name_map)
        if row_key:
            finding_rows.sort(key=row_key, reverse=direction < 0)
        results.extend(finding_rows)

    return VulnerabilitySearchResponse(items=results, **page_meta(total_count, skip, limit), **counts)
