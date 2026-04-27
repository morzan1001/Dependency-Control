"""Analytics search endpoints: /search and /vulnerability-search."""

import re
from typing import Annotated, Any, Dict, List, Optional

from fastapi import Query

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    get_projects_with_scans,
    get_user_project_ids,
    require_analytics_permission,
)
from app.api.v1.helpers.responses import RESP_AUTH
from app.core.constants import get_severity_value
from app.core.permissions import Permissions
from app.repositories import (
    DependencyRepository,
    FindingRepository,
)
from app.schemas.analytics import (
    DependencySearchResponse,
    DependencySearchResult,
    VulnerabilitySearchResponse,
    VulnerabilitySearchResult,
)
from app.services.recommendation.common import get_attr

router = CustomAPIRouter()


def _passes_vuln_filter(
    dep_project_id: str, dep_name: str, has_vulnerabilities: Optional[bool], vuln_status_map: Dict[str, bool]
) -> bool:
    if has_vulnerabilities is None:
        return True
    key = f"{dep_project_id}:{dep_name}"
    has_vulns = vuln_status_map.get(key, False)
    return has_vulnerabilities == has_vulns


def _dep_to_search_result(dep: Any, project_name_map: Dict[str, str]) -> DependencySearchResult:
    dep_project_id = get_attr(dep, "project_id")
    return DependencySearchResult(
        project_id=dep_project_id,
        project_name=project_name_map.get(dep_project_id, "Unknown"),
        package=get_attr(dep, "name"),
        version=get_attr(dep, "version"),
        type=get_attr(dep, "type", "unknown"),
        license=get_attr(dep, "license"),
        license_url=get_attr(dep, "license_url"),
        direct=get_attr(dep, "direct", False),
        purl=get_attr(dep, "purl"),
        source_type=get_attr(dep, "source_type"),
        source_target=get_attr(dep, "source_target"),
        layer_digest=get_attr(dep, "layer_digest"),
        found_by=get_attr(dep, "found_by"),
        locations=get_attr(dep, "locations", []),
        cpes=get_attr(dep, "cpes", []),
        description=get_attr(dep, "description"),
        author=get_attr(dep, "author"),
        publisher=get_attr(dep, "publisher"),
        group=get_attr(dep, "group"),
        homepage=get_attr(dep, "homepage"),
        repository_url=get_attr(dep, "repository_url"),
        download_url=get_attr(dep, "download_url"),
        hashes=get_attr(dep, "hashes", {}),
        properties=get_attr(dep, "properties", {}),
    )


def _build_search_results(
    dependencies: List[Any],
    has_vulnerabilities: Optional[bool],
    vuln_status_map: Dict[str, bool],
    project_name_map: Dict[str, str],
) -> List[DependencySearchResult]:
    results = []
    for dep in dependencies:
        dep_project_id = get_attr(dep, "project_id")
        dep_name = get_attr(dep, "name")
        if not _passes_vuln_filter(dep_project_id, dep_name, has_vulnerabilities, vuln_status_map):
            continue
        results.append(_dep_to_search_result(dep, project_name_map))
    return results


@router.get("/search", responses=RESP_AUTH)
async def search_dependencies_advanced(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    q: Annotated[str, Query(min_length=2, description="Search query for package name")],
    version: Annotated[Optional[str], Query(description="Filter by specific version")] = None,
    type: Annotated[Optional[str], Query(description="Filter by package type")] = None,
    source_type: Annotated[
        Optional[str],
        Query(description="Filter by source type (image, file-system, directory, application)"),
    ] = None,
    has_vulnerabilities: Annotated[Optional[bool], Query(description="Filter by vulnerability status")] = None,
    project_ids: Annotated[Optional[str], Query(description="Comma-separated list of project IDs")] = None,
    sort_by: Annotated[
        str,
        Query(description="Sort field: name, version, type, project_name, license, direct"),
    ] = "name",
    sort_order: Annotated[str, Query(description="Sort order: asc or desc")] = "asc",
    skip: Annotated[int, Query(ge=0, description="Number of items to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> DependencySearchResponse:
    """Advanced dependency search with multiple filters and pagination."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_SEARCH)

    accessible_project_ids = await get_user_project_ids(current_user, db)

    if project_ids:
        requested_ids = [pid.strip() for pid in project_ids.split(",")]
        accessible_project_ids = [pid for pid in accessible_project_ids if pid in requested_ids]

    if not accessible_project_ids:
        return DependencySearchResponse(items=[], total=0, page=0, size=limit)

    dep_repo = DependencyRepository(db)
    finding_repo = FindingRepository(db)

    project_name_map, scan_ids = await get_projects_with_scans(accessible_project_ids, db)

    if not scan_ids:
        return DependencySearchResponse(items=[], total=0, page=0, size=limit)

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
        "project_name": "project_id",  # close enough — sorts by project_id, not name.
        "license": "license",
        "direct": "direct",
    }
    mongo_sort_field = sort_field_map.get(sort_by, "name")
    sort_direction = 1 if sort_order == "asc" else -1

    dependencies = await dep_repo.find_many(
        query,
        skip=skip,
        limit=limit,
        sort_by=mongo_sort_field,
        sort_order=sort_direction,
    )

    vuln_status_map: Dict[str, bool] = {}
    if has_vulnerabilities is not None and dependencies:
        dep_keys = list({(get_attr(dep, "project_id"), get_attr(dep, "name")) for dep in dependencies})
        component_names = list({get_attr(dep, "name") for dep in dependencies})

        vuln_pipeline: List[Dict[str, Any]] = [
            {
                "$match": {
                    "project_id": {"$in": [k[0] for k in dep_keys]},
                    "component": {"$in": component_names},
                    "type": "vulnerability",
                }
            },
            {"$group": {"_id": {"project_id": "$project_id", "component": "$component"}}},
        ]
        vuln_results = await finding_repo.aggregate(vuln_pipeline)
        for r in vuln_results:
            key = f"{r['_id']['project_id']}:{r['_id']['component']}"
            vuln_status_map[key] = True

    results = _build_search_results(dependencies, has_vulnerabilities, vuln_status_map, project_name_map)

    return DependencySearchResponse(
        items=results,
        total=total_count,
        page=(skip // limit) + 1 if limit > 0 else 1,
        size=limit,
    )


def _get_description(vuln: dict, finding: Any) -> str | None:
    if vuln.get("description"):
        desc_text: str = vuln["description"][:200]
        return desc_text
    desc = getattr(finding, "description", None)
    if desc:
        return str(desc)[:200]
    return None


def _aggregate_kev_status(details: Dict[str, Any], nested_vulns: List[Dict[str, Any]]) -> tuple[bool, bool, Any]:
    """Return (in_kev_status, kev_ransomware, kev_due_date) merged from finding details
    and nested vulnerabilities."""
    in_kev_status = details.get("kev", False)
    kev_ransomware = details.get("kev_ransomware", False)
    kev_due_date = details.get("kev_due_date")

    for vuln in nested_vulns:
        if vuln.get("kev"):
            in_kev_status = True
        if vuln.get("kev_ransomware"):
            kev_ransomware = True
        if vuln.get("kev_due_date") and (not kev_due_date or vuln["kev_due_date"] < kev_due_date):
            kev_due_date = vuln["kev_due_date"]

    return in_kev_status, kev_ransomware, kev_due_date


def _check_fix_availability(details: Dict[str, Any], nested_vulns: List[Dict[str, Any]]) -> bool:
    if details.get("fixed_version"):
        return True
    return any(vuln.get("fixed_version") for vuln in nested_vulns)


def _build_direct_vuln_result(
    finding: Any,
    details: Dict[str, Any],
    in_kev_status: bool,
    kev_ransomware: bool,
    kev_due_date: Any,
    project_name_map: Dict[str, str],
) -> VulnerabilitySearchResult:
    return VulnerabilitySearchResult(
        vulnerability_id=finding.finding_id,
        aliases=finding.aliases or [],
        severity=finding.severity or "UNKNOWN",
        cvss_score=details.get("cvss_score"),
        epss_score=details.get("epss_score"),
        epss_percentile=details.get("epss_percentile"),
        in_kev=in_kev_status,
        kev_ransomware=kev_ransomware,
        kev_due_date=kev_due_date,
        component=finding.component or "",
        version=finding.version or "",
        component_type=details.get("type"),
        purl=details.get("purl"),
        project_id=finding.project_id or "",
        project_name=project_name_map.get(finding.project_id or "", "Unknown"),
        scan_id=finding.scan_id,
        finding_id=finding.finding_id,
        finding_type=finding.type or "vulnerability",
        description=(finding.description[:200] if finding.description else None),
        fixed_version=details.get("fixed_version"),
        waived=finding.waived if finding.waived is not None else False,
        waiver_reason=finding.waiver_reason,
    )


def _build_nested_vuln_result(
    vuln: Dict[str, Any],
    finding: Any,
    details: Dict[str, Any],
    in_kev_status: bool,
    kev_ransomware: bool,
    kev_due_date: Any,
    project_name_map: Dict[str, str],
) -> VulnerabilitySearchResult:
    return VulnerabilitySearchResult(
        vulnerability_id=(vuln.get("id") or vuln.get("resolved_cve") or finding.finding_id),
        aliases=([finding.finding_id] if vuln.get("id") != finding.finding_id else finding.aliases or []),
        severity=(vuln.get("severity") or finding.severity or "UNKNOWN"),
        cvss_score=(vuln.get("cvss_score") or details.get("cvss_score")),
        epss_score=(vuln.get("epss_score") or details.get("epss_score")),
        epss_percentile=(vuln.get("epss_percentile") or details.get("epss_percentile")),
        in_kev=vuln.get("kev", False) or in_kev_status,
        kev_ransomware=(vuln.get("kev_ransomware", False) or kev_ransomware),
        kev_due_date=vuln.get("kev_due_date") or kev_due_date,
        component=finding.component or "",
        version=finding.version or "",
        component_type=details.get("type"),
        purl=details.get("purl"),
        project_id=finding.project_id or "",
        project_name=project_name_map.get(finding.project_id or "", "Unknown"),
        scan_id=finding.scan_id,
        finding_id=finding.finding_id,
        finding_type=finding.type or "vulnerability",
        description=_get_description(vuln, finding),
        fixed_version=(vuln.get("fixed_version") or details.get("fixed_version")),
        waived=vuln.get("waived", False) or (finding.waived if finding.waived is not None else False),
        waiver_reason=(vuln.get("waiver_reason") or finding.waiver_reason),
    )


@router.get("/vulnerability-search", responses=RESP_AUTH)
async def search_vulnerabilities(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    q: Annotated[
        str,
        Query(min_length=2, description="Search query for CVE, GHSA, or other vulnerability identifiers"),
    ],
    severity: Annotated[Optional[str], Query(description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW")] = None,
    in_kev: Annotated[Optional[bool], Query(description="Filter by CISA KEV inclusion")] = None,
    has_fix: Annotated[Optional[bool], Query(description="Filter by fix availability")] = None,
    finding_type: Annotated[
        Optional[str], Query(description="Filter by finding type: vulnerability, license, secret, etc.")
    ] = None,
    project_ids: Annotated[Optional[str], Query(description="Comma-separated list of project IDs")] = None,
    include_waived: Annotated[bool, Query(description="Include waived findings")] = False,
    sort_by: Annotated[
        str,
        Query(description="Sort field: severity, cvss, epss, component, project_name"),
    ] = "severity",
    sort_order: Annotated[str, Query(description="Sort order: asc or desc")] = "desc",
    skip: Annotated[int, Query(ge=0, description="Number of items to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> VulnerabilitySearchResponse:
    """Search for vulnerabilities/CVEs across accessible projects.

    Searches finding id, aliases, nested vulnerability ids, and description text.
    """
    require_analytics_permission(current_user, Permissions.ANALYTICS_SEARCH)

    accessible_project_ids = await get_user_project_ids(current_user, db)

    if project_ids:
        requested_ids = [pid.strip() for pid in project_ids.split(",")]
        accessible_project_ids = [pid for pid in accessible_project_ids if pid in requested_ids]

    if not accessible_project_ids:
        return VulnerabilitySearchResponse(items=[], total=0, page=0, size=limit)

    finding_repo = FindingRepository(db)

    project_name_map, scan_ids = await get_projects_with_scans(accessible_project_ids, db)

    if not scan_ids:
        return VulnerabilitySearchResponse(items=[], total=0, page=0, size=limit)

    search_regex = {"$regex": re.escape(q), "$options": "i"}

    query = {
        "scan_id": {"$in": scan_ids},
        "$or": [
            {"id": search_regex},
            {"aliases": search_regex},
            {"description": search_regex},
            {"details.vulnerabilities.id": search_regex},
            {"details.vulnerabilities.resolved_cve": search_regex},
        ],
    }

    if severity:
        query["severity"] = severity.upper()

    if finding_type:
        query["type"] = finding_type

    if not include_waived:
        query["waived"] = {"$ne": True}

    total_count = await finding_repo.count(query)

    sort_field_map = {
        "severity": "severity",
        "cvss": "details.cvss_score",
        "epss": "details.epss_score",
        "component": "component",
        "project_name": "project_id",
    }
    mongo_sort_field = sort_field_map.get(sort_by, "severity")
    sort_direction = -1 if sort_order == "desc" else 1

    findings = await finding_repo.find_many(
        query,
        skip=skip,
        limit=limit,
        sort_by=mongo_sort_field,
        sort_order=sort_direction,
    )

    results = []
    query_lower = q.lower()

    for finding in findings:
        details = finding.details
        nested_vulns = details.get("vulnerabilities", [])

        in_kev_status, kev_ransomware, kev_due_date = _aggregate_kev_status(details, nested_vulns)

        if in_kev is not None and in_kev != in_kev_status:
            continue

        has_fix_status = _check_fix_availability(details, nested_vulns)
        if has_fix is not None and has_fix != has_fix_status:
            continue

        matched_vulns = [
            vuln
            for vuln in nested_vulns
            if query_lower in vuln.get("id", "").lower() or query_lower in vuln.get("resolved_cve", "").lower()
        ]

        if not matched_vulns:
            results.append(
                _build_direct_vuln_result(
                    finding, details, in_kev_status, kev_ransomware, kev_due_date, project_name_map
                )
            )
        else:
            for vuln in matched_vulns:
                results.append(
                    _build_nested_vuln_result(
                        vuln, finding, details, in_kev_status, kev_ransomware, kev_due_date, project_name_map
                    )
                )

    # MongoDB can't sort by severity order, so resort in Python with the rank map.
    if sort_by == "severity":
        results.sort(
            key=lambda x: get_severity_value(x.severity),
            reverse=(sort_order == "desc"),
        )

    return VulnerabilitySearchResponse(
        items=results,
        total=total_count,
        page=(skip // limit) + 1 if limit > 0 else 1,
        size=limit,
    )
