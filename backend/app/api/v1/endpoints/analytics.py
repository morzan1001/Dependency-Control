import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Query

from app.api.router import CustomAPIRouter
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.services.recommendation.common import get_attr
from app.api.v1.helpers.analytics import (
    build_findings_severity_map,
    build_hotspot_priority_reasons,
    build_priority_reasons,
    calculate_days_known,
    calculate_days_until_due,
    calculate_impact_score,
    count_severities,
    extract_fix_versions,
    gather_cross_project_data,
    get_latest_scan_ids,
    get_projects_with_scans,
    get_user_project_ids,
    process_cve_enrichments,
    require_analytics_permission,
)
from app.core.constants import ANALYTICS_MAX_QUERY_LIMIT, get_severity_value
from app.core.permissions import Permissions
from app.db.mongodb import get_database
from app.models.user import User
from app.repositories import (
    DependencyEnrichmentRepository,
    DependencyRepository,
    FindingRepository,
    ProjectRepository,
    ScanRepository,
)
from app.schemas.analytics import (
    AnalyticsSummary,
    DependencyMetadata,
    DependencySearchResponse,
    DependencySearchResult,
    DependencyTreeNode,
    DependencyTypeStats,
    DependencyUsage,
    ImpactAnalysisResult,
    RecommendationResponse,
    RecommendationsResponse,
    SeverityBreakdown,
    VulnerabilityHotspot,
    VulnerabilitySearchResponse,
    VulnerabilitySearchResult,
)
from app.services.enrichment import get_cve_enrichment
from app.services.recommendations import recommendation_engine

logger = logging.getLogger(__name__)

router = CustomAPIRouter()


@router.get("/summary", response_model=AnalyticsSummary)
async def get_analytics_summary(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
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
                    percentage=round(
                        (t["count"] / total_deps * 100) if total_deps > 0 else 0, 1
                    ),
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


@router.get("/dependencies/top", response_model=List[DependencyUsage])
async def get_top_dependencies(
    limit: int = Query(20, ge=1, le=100),
    type: Optional[str] = Query(
        None, description="Filter by dependency type (npm, pypi, maven, etc.)"
    ),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Get most frequently used dependencies across all accessible projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_DEPENDENCIES)

    project_ids = await get_user_project_ids(current_user, db)

    if not project_ids:
        return []

    scan_ids = await get_latest_scan_ids(project_ids, db)

    if not scan_ids:
        return []

    # Aggregate dependencies
    match_stage = {"scan_id": {"$in": scan_ids}}
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
    vuln_count_map = await finding_repo.get_vuln_counts_by_components(
        project_ids, component_names
    )

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


@router.get(
    "/projects/{project_id}/dependency-tree", response_model=List[DependencyTreeNode]
)
async def get_dependency_tree(
    project_id: str,
    scan_id: Optional[str] = Query(
        None, description="Specific scan ID, defaults to latest"
    ),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Get dependency tree for a project showing direct and transitive dependencies."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_TREE)

    project_repo = ProjectRepository(db)
    dep_repo = DependencyRepository(db)
    finding_repo = FindingRepository(db)

    # Verify access
    project_ids = await get_user_project_ids(current_user, db)
    if project_id not in project_ids:
        raise HTTPException(status_code=403, detail="Access denied to this project")

    # Get scan ID
    if not scan_id:
        project = await project_repo.get_raw_by_id(project_id)
        scan_id = project.get("latest_scan_id") if project else None

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

    def build_node(dep) -> DependencyTreeNode:
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
    transitive_deps = [
        build_node(d) for d in dependencies if not get_attr(d, "direct", False)
    ]

    # Sort by findings count (most problematic first)
    direct_deps.sort(key=lambda x: x.findings_count, reverse=True)
    transitive_deps.sort(key=lambda x: x.findings_count, reverse=True)

    return direct_deps + transitive_deps


@router.get("/impact", response_model=List[ImpactAnalysisResult])
async def get_impact_analysis(
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Analyze which dependency fixes would have the highest impact across projects."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_IMPACT)

    finding_repo = FindingRepository(db)

    project_ids = await get_user_project_ids(current_user, db)
    if not project_ids:
        return []

    project_name_map, scan_ids = await get_projects_with_scans(project_ids, db)
    if not scan_ids:
        return []

    # Aggregate vulnerabilities by component with more details
    pipeline: List[Dict[str, Any]] = [
        {"$match": {"scan_id": {"$in": scan_ids}, "type": "vulnerability"}},
        {
            "$group": {
                "_id": {"component": "$component", "version": "$version"},
                "project_ids": {"$addToSet": "$project_id"},
                "total_findings": {"$sum": 1},
                "severities": {"$push": "$severity"},
                "finding_ids": {"$push": "$finding_id"},
                "first_seen": {"$min": "$created_at"},
                "details_list": {"$push": "$details"},
            }
        },
        {
            "$project": {
                "component": "$_id.component",
                "version": "$_id.version",
                "project_ids": 1,
                "total_findings": 1,
                "severities": 1,
                "finding_ids": 1,
                "first_seen": 1,
                "details_list": 1,
                "affected_projects": {"$size": "$project_ids"},
            }
        },
        {"$sort": {"affected_projects": -1, "total_findings": -1}},
        {"$limit": limit},
    ]

    results = await finding_repo.aggregate(pipeline)

    # Collect all CVE IDs for enrichment
    all_cves = [
        fid
        for r in results
        for fid in r.get("finding_ids", [])
        if fid and fid.startswith("CVE-")
    ]

    # Enrich with EPSS/KEV data
    enrichments = {}
    if all_cves:
        try:
            enrichments = await get_cve_enrichment(all_cves)
        except Exception as e:
            logger.warning(f"Failed to enrich CVEs: {e}")

    impact_results = []
    for r in results:
        severity_counts = count_severities(r.get("severities", []))
        fix_versions = extract_fix_versions(r.get("details_list", []))
        has_fix = len(fix_versions) > 0

        # Process CVE enrichment data
        finding_ids = [
            fid for fid in r.get("finding_ids", []) if fid and fid.startswith("CVE-")
        ]
        enrichment_data = process_cve_enrichments(finding_ids, enrichments)

        # Calculate days known and days until due
        days_known = calculate_days_known(r.get("first_seen"))
        days_until_due = calculate_days_until_due(enrichment_data["kev_due_date"])
        enrichment_data["days_until_due"] = days_until_due

        # Calculate impact score using helper function
        base_impact = calculate_impact_score(
            severity_counts,
            r["affected_projects"],
            enrichment_data,
            has_fix,
            days_known,
        )

        # Filter project_ids to only accessible projects
        # Prevents information disclosure of project names user doesn't have access to
        accessible_impact_project_ids = [
            pid for pid in r["project_ids"] if pid in project_ids
        ]

        # Build priority reasons using helper function
        priority_reasons = build_priority_reasons(
            severity_counts,
            enrichment_data,
            len(accessible_impact_project_ids),  # Use filtered count
            has_fix,
            days_known,
        )

        impact_results.append(
            ImpactAnalysisResult(
                component=r["component"],
                version=r.get("version") or "unknown",
                affected_projects=len(
                    accessible_impact_project_ids
                ),  # Only accessible count
                total_findings=r["total_findings"],
                findings_by_severity=SeverityBreakdown(**severity_counts),
                fix_impact_score=base_impact,
                affected_project_names=[
                    project_name_map.get(pid, "Unknown")
                    for pid in accessible_impact_project_ids[
                        :5
                    ]  # Only accessible projects!
                ],
                max_epss_score=enrichment_data["max_epss"],
                epss_percentile=enrichment_data["max_percentile"],
                has_kev=enrichment_data["has_kev"],
                kev_count=enrichment_data["kev_count"],
                kev_ransomware_use=enrichment_data["kev_ransomware_use"],
                kev_due_date=enrichment_data["kev_due_date"],
                days_until_due=days_until_due,
                exploit_maturity=enrichment_data["exploit_maturity"],
                max_risk_score=enrichment_data["max_risk"],
                days_known=days_known,
                has_fix=has_fix,
                fix_versions=list(fix_versions)[:3],
                priority_reasons=priority_reasons,
            )
        )

    # Sort by impact score
    impact_results.sort(key=lambda x: x.fix_impact_score, reverse=True)

    return impact_results


@router.get("/hotspots", response_model=List[VulnerabilityHotspot])
async def get_vulnerability_hotspots(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100),
    sort_by: str = Query(
        "finding_count",
        description="Sort field: finding_count, component, first_seen, epss, risk",
    ),
    sort_order: str = Query("desc", description="Sort order: asc, desc"),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Get dependencies with the most vulnerabilities (hotspots)."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_HOTSPOTS)

    finding_repo = FindingRepository(db)
    dep_repo = DependencyRepository(db)

    project_ids = await get_user_project_ids(current_user, db)
    if not project_ids:
        return []

    project_name_map, scan_ids = await get_projects_with_scans(project_ids, db)
    if not scan_ids:
        return []

    # Determine sort direction
    sort_direction = -1 if sort_order == "desc" else 1

    # Map sort fields (for MongoDB aggregation)
    sort_field_map = {
        "finding_count": "finding_count",
        "component": "_id.component",
        "first_seen": "first_seen",
    }
    mongo_sort_field = sort_field_map.get(sort_by, "finding_count")

    # For EPSS/risk sorting, we'll sort after enrichment
    post_sort_by = sort_by if sort_by in ["epss", "risk"] else None

    pipeline: List[Dict[str, Any]] = [
        {"$match": {"scan_id": {"$in": scan_ids}, "type": "vulnerability"}},
        {
            "$group": {
                "_id": {"component": "$component", "version": "$version"},
                "project_ids": {"$addToSet": "$project_id"},
                "finding_count": {"$sum": 1},
                "severities": {"$push": "$severity"},
                "first_seen": {"$min": "$created_at"},
                "finding_ids": {"$push": "$finding_id"},
                "details_list": {"$push": "$details"},
            }
        },
        {"$sort": {mongo_sort_field: sort_direction}},
        # Fetch more if we need to sort by enrichment data
        {"$limit": limit * 3 if post_sort_by else skip + limit},
    ]

    results = await finding_repo.aggregate(pipeline)

    if not post_sort_by:
        results = results[skip : skip + limit]

    # Collect all CVE IDs for enrichment
    all_cves = list(
        set(
            fid
            for r in results
            for fid in r.get("finding_ids", [])
            if fid and fid.startswith("CVE-")
        )
    )

    # Enrich with EPSS/KEV data
    enrichments = {}
    if all_cves:
        try:
            enrichments = await get_cve_enrichment(all_cves)
        except Exception as e:
            logger.warning(f"Failed to enrich CVEs: {e}")

    # Batch fetch dependency types to avoid N+1 queries
    component_names = list(set(r["_id"]["component"] for r in results))
    # Use find_all() instead of find_many() when using projection
    # find_many() returns Pydantic models which don't work with partial projections
    deps_by_name = await dep_repo.find_all(
        {"name": {"$in": component_names}},
        projection={"name": 1, "type": 1},
    )
    dep_type_map = {d["name"]: d.get("type", "unknown") for d in deps_by_name}

    hotspots = []
    for r in results:
        severity_counts = count_severities(r.get("severities", []))
        fix_versions = extract_fix_versions(r.get("details_list", []))
        has_fix = len(fix_versions) > 0

        # Get dependency type from pre-fetched map
        dep_type = dep_type_map.get(r["_id"]["component"], "unknown")

        # Format first_seen and calculate days known
        first_seen = r.get("first_seen")
        first_seen_str = ""
        if first_seen:
            if isinstance(first_seen, datetime):
                first_seen_str = first_seen.isoformat()
            else:
                first_seen_str = str(first_seen)
        days_known = calculate_days_known(first_seen)

        # Collect top CVEs and process enrichment data
        finding_ids = r.get("finding_ids", [])
        top_cves = list(
            dict.fromkeys(fid for fid in finding_ids if fid and fid.startswith("CVE-"))
        )[:5]

        cve_finding_ids = [fid for fid in finding_ids if fid and fid.startswith("CVE-")]
        enrichment_data = process_cve_enrichments(cve_finding_ids, enrichments)
        days_until_due = calculate_days_until_due(enrichment_data["kev_due_date"])

        # Build priority reasons using helper
        priority_reasons = build_hotspot_priority_reasons(
            enrichment_data, severity_counts, has_fix, days_until_due
        )

        # Filter project_ids to only accessible projects
        # Prevents information disclosure of project names user doesn't have access to
        accessible_affected_projects = [
            pid for pid in r["project_ids"] if pid in project_ids
        ]

        hotspots.append(
            VulnerabilityHotspot(
                component=r["_id"]["component"],
                version=r["_id"].get("version") or "unknown",
                type=dep_type,
                finding_count=r["finding_count"],
                severity_breakdown=SeverityBreakdown(**severity_counts),
                affected_projects=[
                    project_name_map.get(pid, "Unknown")
                    for pid in accessible_affected_projects[
                        :10
                    ]  # Only accessible projects!
                ],
                first_seen=first_seen_str,
                max_epss_score=enrichment_data["max_epss"],
                epss_percentile=enrichment_data["max_percentile"],
                has_kev=enrichment_data["has_kev"],
                kev_count=enrichment_data["kev_count"],
                kev_ransomware_use=enrichment_data["kev_ransomware_use"],
                kev_due_date=enrichment_data["kev_due_date"],
                days_until_due=days_until_due,
                exploit_maturity=enrichment_data["exploit_maturity"],
                max_risk_score=enrichment_data["max_risk"],
                days_known=days_known,
                has_fix=has_fix,
                fix_versions=list(fix_versions)[:3],
                top_cves=top_cves,
                priority_reasons=priority_reasons,
            )
        )

    # Post-sort by enrichment data if needed
    if post_sort_by == "epss":
        hotspots.sort(
            key=lambda x: x.max_epss_score or 0, reverse=(sort_order == "desc")
        )
        hotspots = hotspots[skip : skip + limit]
    elif post_sort_by == "risk":
        hotspots.sort(
            key=lambda x: x.max_risk_score or 0, reverse=(sort_order == "desc")
        )
        hotspots = hotspots[skip : skip + limit]

    return hotspots


@router.get("/search", response_model=DependencySearchResponse)
async def search_dependencies_advanced(
    q: str = Query(..., min_length=2, description="Search query for package name"),
    version: Optional[str] = Query(None, description="Filter by specific version"),
    type: Optional[str] = Query(None, description="Filter by package type"),
    source_type: Optional[str] = Query(
        None,
        description="Filter by source type (image, file-system, directory, application)",
    ),
    has_vulnerabilities: Optional[bool] = Query(
        None, description="Filter by vulnerability status"
    ),
    project_ids: Optional[str] = Query(
        None, description="Comma-separated list of project IDs"
    ),
    sort_by: str = Query(
        "name",
        description="Sort field: name, version, type, project_name, license, direct",
    ),
    sort_order: str = Query("asc", description="Sort order: asc or desc"),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Advanced dependency search with multiple filters and pagination."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_SEARCH)

    accessible_project_ids = await get_user_project_ids(current_user, db)

    # Filter by requested project IDs if provided
    if project_ids:
        requested_ids = [pid.strip() for pid in project_ids.split(",")]
        accessible_project_ids = [
            pid for pid in accessible_project_ids if pid in requested_ids
        ]

    if not accessible_project_ids:
        return DependencySearchResponse(items=[], total=0, page=0, size=limit)

    dep_repo = DependencyRepository(db)
    finding_repo = FindingRepository(db)

    project_name_map, scan_ids = await get_projects_with_scans(
        accessible_project_ids, db
    )

    if not scan_ids:
        return DependencySearchResponse(items=[], total=0, page=0, size=limit)

    query = {"scan_id": {"$in": scan_ids}, "name": {"$regex": q, "$options": "i"}}
    if version:
        query["version"] = version
    if type:
        query["type"] = type
    if source_type:
        query["source_type"] = source_type

    # Get total count for pagination
    total_count = await dep_repo.count(query)

    # Map sort fields to MongoDB fields
    sort_field_map = {
        "name": "name",
        "version": "version",
        "type": "type",
        "project_name": "project_id",  # Will sort by project_id, but close enough
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

    # Batch fetch vulnerability status if filter is set
    vuln_status_map: Dict[str, bool] = {}
    if has_vulnerabilities is not None and dependencies:
        # Build unique (project_id, component) pairs
        dep_keys = list(set((get_attr(dep, "project_id"), get_attr(dep, "name")) for dep in dependencies))
        component_names = list(set(get_attr(dep, "name") for dep in dependencies))

        # Single aggregation to get components with vulnerabilities
        vuln_pipeline: List[Dict[str, Any]] = [
            {
                "$match": {
                    "project_id": {"$in": [k[0] for k in dep_keys]},
                    "component": {"$in": component_names},
                    "type": "vulnerability",
                }
            },
            {
                "$group": {
                    "_id": {"project_id": "$project_id", "component": "$component"}
                }
            },
        ]
        vuln_results = await finding_repo.aggregate(vuln_pipeline)
        for r in vuln_results:
            key = f"{r['_id']['project_id']}:{r['_id']['component']}"
            vuln_status_map[key] = True

    results = []
    for dep in dependencies:
        # Check for vulnerabilities if filter is set
        dep_project_id = get_attr(dep, "project_id")
        dep_name = get_attr(dep, "name")
        if has_vulnerabilities is not None:
            key = f"{dep_project_id}:{dep_name}"
            has_vulns = vuln_status_map.get(key, False)
            if has_vulnerabilities and not has_vulns:
                continue
            if not has_vulnerabilities and has_vulns:
                continue

        results.append(
            DependencySearchResult(
                project_id=dep_project_id,
                project_name=project_name_map.get(dep_project_id, "Unknown"),
                package=dep_name,
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
        )

    return DependencySearchResponse(
        items=results,
        total=total_count,
        page=skip // limit,
        size=limit,
    )


@router.get("/vulnerability-search", response_model=VulnerabilitySearchResponse)
async def search_vulnerabilities(
    q: str = Query(
        ...,
        min_length=2,
        description="Search query for CVE, GHSA, or other vulnerability identifiers",
    ),
    severity: Optional[str] = Query(
        None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"
    ),
    in_kev: Optional[bool] = Query(None, description="Filter by CISA KEV inclusion"),
    has_fix: Optional[bool] = Query(None, description="Filter by fix availability"),
    finding_type: Optional[str] = Query(
        None, description="Filter by finding type: vulnerability, license, secret, etc."
    ),
    project_ids: Optional[str] = Query(
        None, description="Comma-separated list of project IDs"
    ),
    include_waived: bool = Query(False, description="Include waived findings"),
    sort_by: str = Query(
        "severity",
        description="Sort field: severity, cvss, epss, component, project_name",
    ),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Search for vulnerabilities, CVEs, and other security identifiers across all accessible projects.

    Searches in:
    - Finding ID (e.g., CVE-2021-44228)
    - Aliases (e.g., GHSA-xxx)
    - Nested vulnerability IDs in details
    - Description text
    """
    require_analytics_permission(current_user, Permissions.ANALYTICS_SEARCH)

    accessible_project_ids = await get_user_project_ids(current_user, db)

    # Filter by requested project IDs if provided
    if project_ids:
        requested_ids = [pid.strip() for pid in project_ids.split(",")]
        accessible_project_ids = [
            pid for pid in accessible_project_ids if pid in requested_ids
        ]

    if not accessible_project_ids:
        return VulnerabilitySearchResponse(items=[], total=0, page=0, size=limit)

    finding_repo = FindingRepository(db)

    project_name_map, scan_ids = await get_projects_with_scans(
        accessible_project_ids, db
    )

    if not scan_ids:
        return VulnerabilitySearchResponse(items=[], total=0, page=0, size=limit)

    # Build query for findings
    # Search in: id, aliases, details.vulnerabilities[].id, description
    search_regex = {"$regex": q, "$options": "i"}

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

    # Apply filters
    if severity:
        query["severity"] = severity.upper()

    if finding_type:
        query["type"] = finding_type

    if not include_waived:
        query["waived"] = {"$ne": True}

    # Get total count
    total_count = await finding_repo.count(query)

    # Sort mapping - uses SEVERITY_ORDER from constants for consistency
    sort_field_map = {
        "severity": "severity",
        "cvss": "details.cvss_score",
        "epss": "details.epss_score",
        "component": "component",
        "project_name": "project_id",
    }
    mongo_sort_field = sort_field_map.get(sort_by, "severity")
    sort_direction = -1 if sort_order == "desc" else 1

    # Fetch findings with Pydantic models
    findings = await finding_repo.find_many(
        query,
        skip=skip,
        limit=limit,
        sort_by=mongo_sort_field,
        sort_order=sort_direction,
    )

    results = []
    for finding in findings:
        details = finding.details

        # Extract vulnerability info from nested vulnerabilities if present
        nested_vulns = details.get("vulnerabilities", [])

        # Check KEV status
        in_kev_status = details.get("kev", False)
        kev_ransomware = details.get("kev_ransomware", False)
        kev_due_date = details.get("kev_due_date")

        # Check nested vulns for KEV
        for vuln in nested_vulns:
            if vuln.get("kev"):
                in_kev_status = True
            if vuln.get("kev_ransomware"):
                kev_ransomware = True
            if vuln.get("kev_due_date") and (
                not kev_due_date or vuln["kev_due_date"] < kev_due_date
            ):
                kev_due_date = vuln["kev_due_date"]

        # Apply KEV filter
        if in_kev is not None:
            if in_kev and not in_kev_status:
                continue
            if not in_kev and in_kev_status:
                continue

        # Check fix availability
        has_fix_status = bool(details.get("fixed_version"))
        for vuln in nested_vulns:
            if vuln.get("fixed_version"):
                has_fix_status = True
                break

        # Apply fix filter
        if has_fix is not None:
            if has_fix and not has_fix_status:
                continue
            if not has_fix and has_fix_status:
                continue

        # Build result - if there are nested vulnerabilities matching the query, include each
        matched_vulns = []
        query_lower = q.lower()

        # Check if any nested vulnerability matches
        for vuln in nested_vulns:
            vuln_id = vuln.get("id", "")
            resolved_cve = vuln.get("resolved_cve", "")
            if query_lower in vuln_id.lower() or query_lower in resolved_cve.lower():
                matched_vulns.append(vuln)

        # If no nested vulns match, this is a direct match on the finding
        if not matched_vulns:
            results.append(
                VulnerabilitySearchResult(
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
                    description=(
                        finding.get("description", "")[:200]
                        if finding.get("description")
                        else None
                    ),
                    fixed_version=details.get("fixed_version"),
                    waived=finding.get("waived", False),
                    waiver_reason=finding.get("waiver_reason"),
                )
            )
        else:
            # Add each matched nested vulnerability as a separate result
            for vuln in matched_vulns:
                results.append(
                    VulnerabilitySearchResult(
                        vulnerability_id=(
                            vuln.get("id") or vuln.get("resolved_cve") or finding.finding_id
                        ),
                        aliases=(
                            [finding.finding_id]
                            if vuln.get("id") != finding.finding_id
                            else finding.aliases or []
                        ),
                        severity=(
                            vuln.get("severity") or finding.get("severity", "UNKNOWN")
                        ),
                        cvss_score=(
                            vuln.get("cvss_score") or details.get("cvss_score")
                        ),
                        epss_score=(
                            vuln.get("epss_score") or details.get("epss_score")
                        ),
                        epss_percentile=(
                            vuln.get("epss_percentile")
                            or details.get("epss_percentile")
                        ),
                        in_kev=vuln.get("kev", False) or in_kev_status,
                        kev_ransomware=(
                            vuln.get("kev_ransomware", False) or kev_ransomware
                        ),
                        kev_due_date=vuln.get("kev_due_date") or kev_due_date,
                        component=finding.get("component", ""),
                        version=finding.get("version", ""),
                        component_type=details.get("type"),
                        purl=details.get("purl"),
                        project_id=finding.get("project_id", ""),
                        project_name=project_name_map.get(
                            finding.get("project_id", ""), "Unknown"
                        ),
                        scan_id=finding.scan_id,
                        finding_id=finding.finding_id,
                        finding_type=finding.type or "vulnerability",
                        description=(
                            vuln.get("description", "")[:200]
                            if vuln.get("description")
                            else (
                                finding.get("description", "")[:200]
                                if finding.get("description")
                                else None
                            )
                        ),
                        fixed_version=(
                            vuln.get("fixed_version") or details.get("fixed_version")
                        ),
                        waived=vuln.get("waived", False)
                        or finding.get("waived", False),
                        waiver_reason=(
                            vuln.get("waiver_reason") or finding.get("waiver_reason")
                        ),
                    )
                )

    # Sort by severity if needed (since MongoDB can't sort by severity order)
    if sort_by == "severity":
        results.sort(
            key=lambda x: get_severity_value(x.severity),
            reverse=(sort_order == "desc"),
        )

    return VulnerabilitySearchResponse(
        items=results,
        total=total_count,
        page=skip // limit if limit > 0 else 0,
        size=limit,
    )


@router.get("/component-findings", response_model=List[Dict[str, Any]])
async def get_component_findings(
    component: str = Query(..., description="Component/package name"),
    version: Optional[str] = Query(None, description="Specific version"),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
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


@router.get("/dependency-metadata", response_model=Optional[DependencyMetadata])
async def get_dependency_metadata_endpoint(
    component: str = Query(..., description="Component/package name"),
    version: Optional[str] = Query(None, description="Specific version"),
    type: Optional[str] = Query(None, description="Package type"),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
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
    projects = await project_repo.find_many(
        {"_id": {"$in": project_ids}},
        limit=ANALYTICS_MAX_QUERY_LIMIT,
        projection={"_id": 1, "name": 1},
    )
    project_name_map = {p["_id"]: p["name"] for p in projects}

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

    # Get enrichment data (deps.dev + license) - single query
    deps_dev_data = None
    enrichment_sources = []
    license_category = None
    license_risks: List[str] = []
    license_obligations: List[str] = []

    dep_purl = get_attr(first_dep, "purl")
    if dep_purl:
        enrichment = await enrichment_repo.get_by_purl(dep_purl)
        if enrichment:
            # deps.dev data
            deps_dev_data = enrichment.get("deps_dev")
            if deps_dev_data:
                enrichment_sources.append("deps_dev")

            # License compliance data
            license_info = enrichment.get("license_compliance")
            if license_info:
                enrichment_sources.append("license_compliance")
                license_category = license_info.get("category")
                license_risks = license_info.get("risks", [])
                license_obligations = license_info.get("obligations", [])

    # Helper function to get first non-null value from dependencies
    def first_value(key: str):
        for dep in dependencies:
            val = get_attr(dep, key)
            if val:
                return val
        return None

    # Count findings for this component
    finding_query = {"scan_id": {"$in": scan_ids}, "component": component}
    if version:
        finding_query["version"] = version

    finding_count = await finding_repo.count(finding_query)

    # Count vulnerabilities specifically
    vuln_query = {**finding_query, "type": "vulnerability"}
    vuln_count = await finding_repo.count(vuln_query)

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
        license_category=license_category,
        license_risks=license_risks,
        license_obligations=license_obligations,
        deps_dev=deps_dev_data,
        project_count=len(affected_projects),
        affected_projects=list(affected_projects.values()),
        total_vulnerability_count=vuln_count,
        total_finding_count=finding_count,
        enrichment_sources=enrichment_sources,
    )


@router.get("/dependency-types", response_model=List[str])
async def get_dependency_types(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
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


@router.get(
    "/projects/{project_id}/recommendations", response_model=RecommendationsResponse
)
async def get_project_recommendations(
    project_id: str,
    scan_id: Optional[str] = None,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get remediation recommendations for a project's security findings.

    Analyzes all finding types and generates actionable recommendations:
    - Base image updates (fix multiple OS-level vulns at once)
    - Direct dependency updates (with specific version targets)
    - Transitive dependency fixes
    - Secret rotation and removal
    - SAST code fixes
    - IAC infrastructure fixes
    - License compliance issues
    - Dependency health (outdated, fragmented)
    - Trend analysis (regressions, recurring issues)
    - Cross-project patterns (shared vulnerabilities)

    Recommendations are prioritized by impact and effort.
    """
    require_analytics_permission(current_user, Permissions.ANALYTICS_RECOMMENDATIONS)

    project_repo = ProjectRepository(db)
    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
    dep_repo = DependencyRepository(db)

    # Verify project access
    project = await project_repo.get_raw_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Check if user has access to this project
    user_project_ids = await get_user_project_ids(current_user, db)
    if project_id not in user_project_ids:
        raise HTTPException(status_code=403, detail="Access denied to this project")

    # Get the latest scan or specified scan
    if scan_id:
        scan = await scan_repo.get_by_id(scan_id)
        if scan and scan.project_id != project_id:
            scan = None
    else:
        # Get latest scan for project
        scans = await scan_repo.find_many(
            {"project_id": project_id},
            limit=1,
            sort=[("created_at", -1)],
        )
        scan = scans[0] if scans else None

    if not scan:
        raise HTTPException(status_code=404, detail="No scan found for this project")

    scan_id = scan.id

    # Get source target (e.g., Docker image name) from scan
    source_target = None

    # Fetch ALL findings for this scan (all types: vulnerability, secret, sast, iac, license, quality)
    findings = await finding_repo.find_by_scan(scan_id, limit=ANALYTICS_MAX_QUERY_LIMIT)

    # Fetch all dependencies for this scan
    dependencies = await dep_repo.find_by_scan(scan_id)

    # Try to get source target from dependencies (Dependency is a Pydantic model)
    for dep in dependencies:
        if dep.source_target:
            source_target = dep.source_target
            break

    previous_scan_findings = None
    scan_history = None

    # Get previous scan for regression detection
    previous_scans = await scan_repo.find_many(
        {"project_id": project_id, "_id": {"$ne": scan_id}},
        limit=1,
        sort=[("created_at", -1)],
    )
    previous_scan = previous_scans[0] if previous_scans else None

    if previous_scan:
        previous_scan_findings = await finding_repo.find_by_scan(
            previous_scan.id, limit=ANALYTICS_MAX_QUERY_LIMIT
        )

    # Get last 10 scans for recurring issue detection
    recent_scans = await scan_repo.find_many(
        {"project_id": project_id},
        limit=10,
        sort=[("created_at", -1)],
        projection={"_id": 1, "findings_summary": 1, "created_at": 1},
    )

    if recent_scans:
        scan_history = recent_scans

    # Gather cross-project data using helper
    cross_project_data = await gather_cross_project_data(
        user_project_ids, project_id, db
    )

    recommendations = await recommendation_engine.generate_recommendations(
        findings=findings,
        dependencies=dependencies,
        source_target=source_target,
        previous_scan_findings=previous_scan_findings,
        scan_history=scan_history,
        cross_project_data=cross_project_data,
    )

    # Count findings by type for stats (FindingRecord uses type attribute, not dict)
    vuln_count = sum(1 for f in findings if f.type == "vulnerability")
    secret_count = sum(1 for f in findings if f.type == "secret")
    sast_count = sum(1 for f in findings if f.type == "sast")
    iac_count = sum(1 for f in findings if f.type == "iac")
    license_count = sum(1 for f in findings if f.type == "license")
    quality_count = sum(1 for f in findings if f.type == "quality")

    # Build extended summary
    summary: Dict[str, Any] = {
        "base_image_updates": 0,
        "direct_updates": 0,
        "transitive_updates": 0,
        "no_fix": 0,
        "total_fixable_vulns": 0,
        "total_unfixable_vulns": 0,
        "secrets_to_rotate": 0,
        "sast_issues": 0,
        "iac_issues": 0,
        "license_issues": 0,
        "quality_issues": 0,
        # New summary fields
        "outdated_deps": 0,
        "fragmentation_issues": 0,
        "trend_alerts": 0,
        "cross_project_issues": 0,
        # Finding type counts
        "finding_counts": {
            "vulnerabilities": vuln_count,
            "secrets": secret_count,
            "sast": sast_count,
            "iac": iac_count,
            "license": license_count,
            "quality": quality_count,
        },
    }

    for rec in recommendations:
        rec_type = rec.type.value
        impact_total = rec.impact.get("total", 0)

        if rec_type == "base_image_update":
            summary["base_image_updates"] += 1
            summary["total_fixable_vulns"] += impact_total
        elif rec_type == "direct_dependency_update":
            summary["direct_updates"] += 1
            summary["total_fixable_vulns"] += impact_total
        elif rec_type == "transitive_fix_via_parent":
            summary["transitive_updates"] += 1
            summary["total_fixable_vulns"] += impact_total
        elif rec_type == "no_fix_available":
            summary["no_fix"] += 1
            summary["total_unfixable_vulns"] += impact_total
        elif rec_type in ("rotate_secrets", "remove_secrets"):
            summary["secrets_to_rotate"] += impact_total
        elif rec_type == "fix_code_security":
            summary["sast_issues"] += impact_total
        elif rec_type == "fix_infrastructure":
            summary["iac_issues"] += impact_total
        elif rec_type == "license_compliance":
            summary["license_issues"] += impact_total
        elif rec_type == "supply_chain_risk":
            summary["quality_issues"] += impact_total
        # New types
        elif rec_type in ("outdated_dependency", "unmaintained_package"):
            summary["outdated_deps"] += impact_total
        elif rec_type in (
            "version_fragmentation",
            "dev_in_production",
            "duplicate_functionality",
            "deep_dependency_chain",
        ):
            summary["fragmentation_issues"] += impact_total
        elif rec_type in ("recurring_vulnerability", "regression_detected"):
            summary["trend_alerts"] += 1
        elif rec_type in ("cross_project_pattern", "shared_vulnerability"):
            summary["cross_project_issues"] += impact_total

    return RecommendationsResponse(
        project_id=project_id,
        project_name=project.get("name", "Unknown"),
        scan_id=scan_id,
        total_findings=len(findings),
        total_vulnerabilities=vuln_count,
        recommendations=[
            RecommendationResponse(**r.to_dict()) for r in recommendations
        ],
        summary=summary,
    )
