from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel

from app.api import deps
from app.api.deps import PermissionChecker
from app.db.mongodb import get_database
from app.models.user import User

router = APIRouter()


def check_analytics_permission(user: User, required_permission: str) -> bool:
    """Check if user has the required analytics permission."""
    if "*" in user.permissions:
        return True
    if "analytics:read" in user.permissions:
        return True
    if required_permission in user.permissions:
        return True
    return False


def require_analytics_permission(user: User, permission: str):
    """Raise 403 if user doesn't have the required analytics permission."""
    if not check_analytics_permission(user, permission):
        raise HTTPException(
            status_code=403,
            detail=f"Analytics permission required: {permission}. Grant 'analytics:read' for full analytics access or '{permission}' for this specific feature.",
        )


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DependencyUsage(BaseModel):
    name: str
    type: str
    versions: List[str]
    project_count: int
    total_occurrences: int
    has_vulnerabilities: bool
    vulnerability_count: int


class DependencyListItem(BaseModel):
    """Single dependency item with full details for list view."""
    name: str
    version: str
    type: str
    purl: Optional[str] = None
    license: Optional[str] = None
    direct: bool = False
    project_count: int = 1
    project_id: str
    project_name: str
    has_vulnerabilities: bool = False
    vulnerability_count: int = 0
    source_type: Optional[str] = None


class DependencyListResponse(BaseModel):
    """Paginated response for dependency list."""
    items: List[DependencyListItem]
    total: int
    page: int
    size: int
    has_more: bool


class DependencyTreeNode(BaseModel):
    id: str
    name: str
    version: str
    purl: str
    type: str
    direct: bool
    has_findings: bool
    findings_count: int
    findings_severity: Optional[SeverityBreakdown] = None
    children: List["DependencyTreeNode"] = []
    # Source/Origin info
    source_type: Optional[str] = None
    source_target: Optional[str] = None
    layer_digest: Optional[str] = None
    locations: List[str] = []


class ImpactAnalysisResult(BaseModel):
    component: str
    version: str
    affected_projects: int
    total_findings: int
    findings_by_severity: SeverityBreakdown
    recommended_version: Optional[str] = None
    fix_impact_score: float
    affected_project_names: List[str]


class VulnerabilityHotspot(BaseModel):
    component: str
    version: str
    type: str
    finding_count: int
    severity_breakdown: SeverityBreakdown
    affected_projects: List[str]
    first_seen: str


class DependencyTypeStats(BaseModel):
    type: str
    count: int
    percentage: float


class AnalyticsSummary(BaseModel):
    total_dependencies: int
    total_vulnerabilities: int
    unique_packages: int
    dependency_types: List[DependencyTypeStats]
    severity_distribution: SeverityBreakdown


# Helper to get user-accessible project IDs
async def get_user_project_ids(user: User, db: AsyncIOMotorDatabase) -> List[str]:
    """Get list of project IDs the user has access to."""
    if "*" in user.permissions or "project:read_all" in user.permissions:
        projects = await db.projects.find({}, {"_id": 1}).to_list(None)
        return [p["_id"] for p in projects]

    user_teams = await db.teams.find(
        {"members.user_id": str(user.id)}, {"_id": 1}
    ).to_list(1000)
    user_team_ids = [str(t["_id"]) for t in user_teams]

    projects = await db.projects.find(
        {
            "$or": [
                {"owner_id": str(user.id)},
                {"members.user_id": str(user.id)},
                {"team_id": {"$in": user_team_ids}},
            ]
        },
        {"_id": 1},
    ).to_list(None)

    return [p["_id"] for p in projects]


async def get_latest_scan_ids(
    project_ids: List[str], db: AsyncIOMotorDatabase
) -> List[str]:
    """Get latest scan IDs for given projects."""
    projects = await db.projects.find(
        {"_id": {"$in": project_ids}}, {"latest_scan_id": 1}
    ).to_list(None)

    return [p["latest_scan_id"] for p in projects if p.get("latest_scan_id")]


@router.get("/summary", response_model=AnalyticsSummary)
async def get_analytics_summary(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Get analytics summary across all accessible projects."""
    require_analytics_permission(current_user, "analytics:summary")

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

    # Count total dependencies
    total_deps = await db.dependencies.count_documents({"scan_id": {"$in": scan_ids}})

    # Count unique packages
    unique_pipeline = [
        {"$match": {"scan_id": {"$in": scan_ids}}},
        {"$group": {"_id": "$name"}},
        {"$count": "count"},
    ]
    unique_result = await db.dependencies.aggregate(unique_pipeline).to_list(1)
    unique_packages = unique_result[0]["count"] if unique_result else 0

    # Get dependency types distribution
    type_pipeline = [
        {"$match": {"scan_id": {"$in": scan_ids}}},
        {"$group": {"_id": "$type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    type_results = await db.dependencies.aggregate(type_pipeline).to_list(None)

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

    # Get vulnerability counts by severity
    severity_pipeline = [
        {"$match": {"scan_id": {"$in": scan_ids}, "type": "vulnerability"}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    severity_results = await db.findings.aggregate(severity_pipeline).to_list(None)

    severity_dist = SeverityBreakdown()
    total_vulns = 0
    for s in severity_results:
        sev = s["_id"].lower() if s["_id"] else "unknown"
        count = s["count"]
        total_vulns += count
        if sev == "critical":
            severity_dist.critical = count
        elif sev == "high":
            severity_dist.high = count
        elif sev == "medium":
            severity_dist.medium = count
        elif sev == "low":
            severity_dist.low = count

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
    require_analytics_permission(current_user, "analytics:dependencies")

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

    pipeline = [
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

    results = await db.dependencies.aggregate(pipeline).to_list(None)

    # Enrich with vulnerability info
    enriched = []
    for dep in results:
        vuln_count = await db.findings.count_documents(
            {
                "project_id": {"$in": project_ids},
                "component": dep["name"],
                "type": "vulnerability",
            }
        )
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


@router.get("/dependencies/list", response_model=DependencyListResponse)
async def get_dependencies_list(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(50, ge=1, le=200, description="Items per page"),
    sort_by: str = Query("name", description="Sort field: name, version, type, project_count, vulnerability_count"),
    sort_order: str = Query("asc", description="Sort order: asc or desc"),
    type_filter: Optional[str] = Query(None, description="Filter by dependency type"),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Get paginated list of all dependencies with sorting."""
    require_analytics_permission(current_user, "analytics:dependencies")

    project_ids = await get_user_project_ids(current_user, db)
    if not project_ids:
        return DependencyListResponse(items=[], total=0, page=page, size=size, has_more=False)

    # Build match stage
    match_stage: dict = {"project_id": {"$in": project_ids}}
    if type_filter:
        match_stage["type"] = type_filter

    # Define sort mapping
    sort_map = {
        "name": "name",
        "version": "version",
        "type": "type",
        "project_name": "project_name",
        "direct": "direct",
    }
    sort_field = sort_map.get(sort_by, "name")
    sort_direction = 1 if sort_order == "asc" else -1

    # Get total count
    total = await db.dependencies.count_documents(match_stage)

    # Calculate skip
    skip = (page - 1) * size

    # Main pipeline - first get dependencies grouped by project
    pipeline = [
        {"$match": match_stage},
        {
            "$lookup": {
                "from": "projects",
                "localField": "project_id",
                "foreignField": "_id",
                "as": "project_info",
            }
        },
        {"$unwind": {"path": "$project_info", "preserveNullAndEmptyArrays": True}},
        {
            "$project": {
                "name": 1,
                "version": 1,
                "type": 1,
                "purl": 1,
                "license": "$licenses",
                "direct": 1,
                "project_id": 1,
                "project_name": {"$ifNull": ["$project_info.name", "Unknown"]},
                "source_type": 1,
            }
        },
        {"$sort": {sort_field: sort_direction, "_id": 1}},
        {"$skip": skip},
        {"$limit": size},
    ]

    results = await db.dependencies.aggregate(pipeline).to_list(None)

    # Get vulnerability counts for each dependency
    items = []
    for dep in results:
        # Count vulnerabilities for this dependency in this project
        vuln_count = await db.findings.count_documents({
            "project_id": dep["project_id"],
            "component": dep["name"],
            "type": "vulnerability",
        })
        
        # Count how many projects use this dependency
        project_count = await db.dependencies.count_documents({
            "project_id": {"$in": project_ids},
            "name": dep["name"],
        })
        
        # Get license as string
        license_str = None
        if dep.get("license"):
            if isinstance(dep["license"], list) and len(dep["license"]) > 0:
                license_str = dep["license"][0]
            elif isinstance(dep["license"], str):
                license_str = dep["license"]

        items.append(DependencyListItem(
            name=dep["name"],
            version=dep.get("version", "unknown"),
            type=dep.get("type", "unknown"),
            purl=dep.get("purl"),
            license=license_str,
            direct=dep.get("direct", False),
            project_count=project_count,
            project_id=dep["project_id"],
            project_name=dep.get("project_name", "Unknown"),
            has_vulnerabilities=vuln_count > 0,
            vulnerability_count=vuln_count,
            source_type=dep.get("source_type"),
        ))

    has_more = skip + len(items) < total

    return DependencyListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        has_more=has_more,
    )


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
    require_analytics_permission(current_user, "analytics:tree")

    # Verify access
    project_ids = await get_user_project_ids(current_user, db)
    if project_id not in project_ids:
        raise HTTPException(status_code=403, detail="Access denied to this project")

    # Get scan ID
    if not scan_id:
        project = await db.projects.find_one({"_id": project_id})
        scan_id = project.get("latest_scan_id") if project else None

    if not scan_id:
        return []

    # Get all dependencies for this scan
    dependencies = await db.dependencies.find({"scan_id": scan_id}).to_list(None)

    if not dependencies:
        return []

    # Get findings for this scan
    findings = await db.findings.find(
        {"scan_id": scan_id, "type": "vulnerability"}, {"component": 1, "severity": 1}
    ).to_list(None)

    # Build findings map
    findings_map = {}
    for f in findings:
        comp = f["component"]
        sev = f.get("severity", "UNKNOWN")
        if comp not in findings_map:
            findings_map[comp] = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0,
            }
        sev_lower = sev.lower()
        if sev_lower in findings_map[comp]:
            findings_map[comp][sev_lower] += 1
        findings_map[comp]["total"] += 1

    def build_node(dep) -> DependencyTreeNode:
        name = dep["name"]
        finding_info = findings_map.get(name, {})

        return DependencyTreeNode(
            id=str(dep.get("_id", dep["purl"])),
            name=name,
            version=dep["version"],
            purl=dep["purl"],
            type=dep.get("type", "unknown"),
            direct=dep.get("direct", False),
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
            source_type=dep.get("source_type"),
            source_target=dep.get("source_target"),
            layer_digest=dep.get("layer_digest"),
            locations=dep.get("locations", []),
            children=[],
        )

    # Separate direct and transitive dependencies
    direct_deps = [build_node(d) for d in dependencies if d.get("direct", False)]
    transitive_deps = [
        build_node(d) for d in dependencies if not d.get("direct", False)
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
    require_analytics_permission(current_user, "analytics:impact")

    project_ids = await get_user_project_ids(current_user, db)

    if not project_ids:
        return []

    # Get project name map
    projects = await db.projects.find(
        {"_id": {"$in": project_ids}}, {"_id": 1, "name": 1, "latest_scan_id": 1}
    ).to_list(None)

    project_name_map = {p["_id"]: p["name"] for p in projects}
    scan_ids = [p["latest_scan_id"] for p in projects if p.get("latest_scan_id")]

    if not scan_ids:
        return []

    # Aggregate vulnerabilities by component
    pipeline = [
        {"$match": {"scan_id": {"$in": scan_ids}, "type": "vulnerability"}},
        {
            "$group": {
                "_id": {"component": "$component", "version": "$version"},
                "project_ids": {"$addToSet": "$project_id"},
                "total_findings": {"$sum": 1},
                "severities": {"$push": "$severity"},
            }
        },
        {
            "$project": {
                "component": "$_id.component",
                "version": "$_id.version",
                "project_ids": 1,
                "total_findings": 1,
                "severities": 1,
                "affected_projects": {"$size": "$project_ids"},
            }
        },
        {"$sort": {"affected_projects": -1, "total_findings": -1}},
        {"$limit": limit},
    ]

    results = await db.findings.aggregate(pipeline).to_list(None)

    impact_results = []
    for r in results:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for sev in r.get("severities", []):
            if sev:
                sev_lower = sev.lower()
                if sev_lower in severity_counts:
                    severity_counts[sev_lower] += 1

        # Calculate impact score (weighted by severity and reach)
        # Higher score = fixing this would have more impact
        impact_score = (
            severity_counts["critical"] * 10
            + severity_counts["high"] * 5
            + severity_counts["medium"] * 2
            + severity_counts["low"] * 1
        ) * r["affected_projects"]

        impact_results.append(
            ImpactAnalysisResult(
                component=r["component"],
                version=r.get("version") or "unknown",
                affected_projects=r["affected_projects"],
                total_findings=r["total_findings"],
                findings_by_severity=SeverityBreakdown(**severity_counts),
                fix_impact_score=float(impact_score),
                affected_project_names=[
                    project_name_map.get(pid, "Unknown")
                    for pid in r["project_ids"][:5]  # Limit to 5 names
                ],
            )
        )

    # Sort by impact score
    impact_results.sort(key=lambda x: x.fix_impact_score, reverse=True)

    return impact_results


@router.get("/hotspots", response_model=List[VulnerabilityHotspot])
async def get_vulnerability_hotspots(
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Get dependencies with the most vulnerabilities (hotspots)."""
    require_analytics_permission(current_user, "analytics:hotspots")

    project_ids = await get_user_project_ids(current_user, db)

    if not project_ids:
        return []

    projects = await db.projects.find(
        {"_id": {"$in": project_ids}}, {"_id": 1, "name": 1, "latest_scan_id": 1}
    ).to_list(None)

    project_name_map = {p["_id"]: p["name"] for p in projects}
    scan_ids = [p["latest_scan_id"] for p in projects if p.get("latest_scan_id")]

    if not scan_ids:
        return []

    pipeline = [
        {"$match": {"scan_id": {"$in": scan_ids}, "type": "vulnerability"}},
        {
            "$group": {
                "_id": {"component": "$component", "version": "$version"},
                "project_ids": {"$addToSet": "$project_id"},
                "finding_count": {"$sum": 1},
                "severities": {"$push": "$severity"},
                "first_seen": {"$min": "$created_at"},
            }
        },
        {"$sort": {"finding_count": -1}},
        {"$limit": limit},
    ]

    results = await db.findings.aggregate(pipeline).to_list(None)

    hotspots = []
    for r in results:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for sev in r.get("severities", []):
            if sev:
                sev_lower = sev.lower()
                if sev_lower in severity_counts:
                    severity_counts[sev_lower] += 1

        # Get dependency type
        dep = await db.dependencies.find_one({"name": r["_id"]["component"]})
        dep_type = dep.get("type", "unknown") if dep else "unknown"

        first_seen_str = ""
        if r.get("first_seen"):
            if isinstance(r["first_seen"], datetime):
                first_seen_str = r["first_seen"].isoformat()
            else:
                first_seen_str = str(r["first_seen"])

        hotspots.append(
            VulnerabilityHotspot(
                component=r["_id"]["component"],
                version=r["_id"].get("version") or "unknown",
                type=dep_type,
                finding_count=r["finding_count"],
                severity_breakdown=SeverityBreakdown(**severity_counts),
                affected_projects=[
                    project_name_map.get(pid, "Unknown")
                    for pid in r["project_ids"][:10]
                ],
                first_seen=first_seen_str,
            )
        )

    return hotspots


@router.get("/search")
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
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Advanced dependency search with multiple filters and pagination."""
    require_analytics_permission(current_user, "analytics:search")

    accessible_project_ids = await get_user_project_ids(current_user, db)

    # Filter by requested project IDs if provided
    if project_ids:
        requested_ids = [pid.strip() for pid in project_ids.split(",")]
        accessible_project_ids = [
            pid for pid in accessible_project_ids if pid in requested_ids
        ]

    if not accessible_project_ids:
        return {"items": [], "total": 0, "page": 0, "size": limit}

    projects = await db.projects.find(
        {"_id": {"$in": accessible_project_ids}},
        {"_id": 1, "name": 1, "latest_scan_id": 1},
    ).to_list(None)

    project_name_map = {p["_id"]: p["name"] for p in projects}
    scan_ids = [p["latest_scan_id"] for p in projects if p.get("latest_scan_id")]

    if not scan_ids:
        return {"items": [], "total": 0, "page": 0, "size": limit}

    query = {"scan_id": {"$in": scan_ids}, "name": {"$regex": q, "$options": "i"}}
    if version:
        query["version"] = version
    if type:
        query["type"] = type
    if source_type:
        query["source_type"] = source_type

    # Get total count for pagination
    total_count = await db.dependencies.count_documents(query)

    dependencies = (
        await db.dependencies.find(query).skip(skip).limit(limit).to_list(limit)
    )

    results = []
    for dep in dependencies:
        # Check for vulnerabilities if filter is set
        if has_vulnerabilities is not None:
            vuln_count = await db.findings.count_documents(
                {
                    "project_id": dep["project_id"],
                    "component": dep["name"],
                    "type": "vulnerability",
                }
            )
            if has_vulnerabilities and vuln_count == 0:
                continue
            if not has_vulnerabilities and vuln_count > 0:
                continue

        results.append(
            {
                "project_id": dep["project_id"],
                "project_name": project_name_map.get(dep["project_id"], "Unknown"),
                "package": dep["name"],
                "version": dep["version"],
                "type": dep.get("type", "unknown"),
                "license": dep.get("license"),
                "license_url": dep.get("license_url"),
                "direct": dep.get("direct", False),
                "purl": dep.get("purl"),
                # Source/Origin info
                "source_type": dep.get("source_type"),
                "source_target": dep.get("source_target"),
                "layer_digest": dep.get("layer_digest"),
                "found_by": dep.get("found_by"),
                "locations": dep.get("locations", []),
                # Extended SBOM fields
                "cpes": dep.get("cpes", []),
                "description": dep.get("description"),
                "author": dep.get("author"),
                "publisher": dep.get("publisher"),
                "group": dep.get("group"),
                "homepage": dep.get("homepage"),
                "repository_url": dep.get("repository_url"),
                "download_url": dep.get("download_url"),
                "hashes": dep.get("hashes", {}),
                "properties": dep.get("properties", {}),
            }
        )

    return {
        "items": results,
        "total": total_count,
        "page": skip // limit,
        "size": limit,
    }


@router.get("/component-findings")
async def get_component_findings(
    component: str = Query(..., description="Component/package name"),
    version: Optional[str] = Query(None, description="Specific version"),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Get all findings for a specific component across accessible projects."""
    require_analytics_permission(current_user, "analytics:search")

    project_ids = await get_user_project_ids(current_user, db)

    if not project_ids:
        return []

    scan_ids = await get_latest_scan_ids(project_ids, db)

    if not scan_ids:
        return []

    query = {"scan_id": {"$in": scan_ids}, "component": component}
    if version:
        query["version"] = version

    finding_records = await db.findings.find(query).limit(100).to_list(100)

    # Get project names for enrichment
    projects = await db.projects.find(
        {"_id": {"$in": project_ids}}, {"_id": 1, "name": 1}
    ).to_list(None)
    project_name_map = {p["_id"]: p["name"] for p in projects}

    results = []
    for fr in finding_records:
        finding = dict(fr)
        finding["project_name"] = project_name_map.get(fr.get("project_id"), "Unknown")
        results.append(finding)

    return results


@router.get("/dependency-types")
async def get_dependency_types(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Get list of all dependency types used across accessible projects."""
    require_analytics_permission(current_user, "analytics:search")

    project_ids = await get_user_project_ids(current_user, db)

    if not project_ids:
        return []

    scan_ids = await get_latest_scan_ids(project_ids, db)

    if not scan_ids:
        return []

    pipeline = [
        {"$match": {"scan_id": {"$in": scan_ids}}},
        {"$group": {"_id": "$type"}},
        {"$sort": {"_id": 1}},
    ]

    results = await db.dependencies.aggregate(pipeline).to_list(None)

    return [r["_id"] for r in results if r["_id"]]


# ============================================================================
# RECOMMENDATIONS
# ============================================================================


class RecommendationResponse(BaseModel):
    """Response model for a single recommendation."""

    type: str
    priority: str
    title: str
    description: str
    impact: dict
    affected_components: List[str]
    action: dict
    effort: str


class RecommendationsResponse(BaseModel):
    """Response model for recommendations endpoint."""

    project_id: str
    project_name: str
    scan_id: str
    total_findings: int
    total_vulnerabilities: int
    recommendations: List[RecommendationResponse]
    summary: dict


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
    require_analytics_permission(current_user, "analytics:recommendations")

    from app.services.recommendations import recommendation_engine

    # Verify project access
    project = await db.projects.find_one({"_id": project_id})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Check if user has access to this project
    user_project_ids = await get_user_project_ids(current_user, db)
    if project_id not in user_project_ids:
        raise HTTPException(status_code=403, detail="Access denied to this project")

    # Get the latest scan or specified scan
    if scan_id:
        scan = await db.scans.find_one({"_id": scan_id, "project_id": project_id})
    else:
        scan = await db.scans.find_one(
            {"project_id": project_id}, sort=[("created_at", -1)]
        )

    if not scan:
        raise HTTPException(status_code=404, detail="No scan found for this project")

    scan_id = scan["_id"]

    # Get source target (e.g., Docker image name) from scan
    source_target = None
    sbom_refs = scan.get("sbom_refs", [])
    # Could extract from SBOM metadata if available

    # Fetch ALL findings for this scan (all types: vulnerability, secret, sast, iac, license, quality)
    findings = await db.findings.find({"scan_id": scan_id}).to_list(None)

    # Fetch all dependencies for this scan
    dependencies = await db.dependencies.find({"scan_id": scan_id}).to_list(None)

    # Try to get source target from dependencies
    for dep in dependencies:
        if dep.get("source_target"):
            source_target = dep["source_target"]
            break

    # ----------------------------------------------------------------
    # NEW: Fetch historical data for trend analysis
    # ----------------------------------------------------------------
    previous_scan_findings = None
    scan_history = None

    # Get previous scan for regression detection
    previous_scan = await db.scans.find_one(
        {"project_id": project_id, "_id": {"$ne": scan_id}}, sort=[("created_at", -1)]
    )

    if previous_scan:
        previous_scan_findings = await db.findings.find(
            {"scan_id": previous_scan["_id"]}
        ).to_list(None)

    # Get last 10 scans for recurring issue detection
    recent_scans = (
        await db.scans.find(
            {"project_id": project_id},
            {"_id": 1, "findings_summary": 1, "created_at": 1},
        )
        .sort("created_at", -1)
        .limit(10)
        .to_list(10)
    )

    if recent_scans:
        scan_history = recent_scans

    # ----------------------------------------------------------------
    # NEW: Fetch cross-project data (only for user's accessible projects)
    # ----------------------------------------------------------------
    cross_project_data = None

    # Only gather cross-project data if user has multiple projects
    if len(user_project_ids) > 1:
        cross_project_data = {"projects": [], "total_projects": len(user_project_ids)}

        # Get summary data from other projects (limit to 20 for performance)
        other_project_ids = [pid for pid in user_project_ids if pid != project_id][:20]

        for other_pid in other_project_ids:
            # Get latest scan for each project
            other_scan = await db.scans.find_one(
                {"project_id": other_pid}, sort=[("created_at", -1)]
            )

            if other_scan:
                other_project = await db.projects.find_one({"_id": other_pid})

                # Get vulnerability CVEs
                other_findings = await db.findings.find(
                    {"scan_id": other_scan["_id"], "type": "vulnerability"}
                ).to_list(None)

                cves = []
                for f in other_findings:
                    cve = f.get("details", {}).get("cve_id")
                    if cve:
                        cves.append(cve)

                # Get packages
                other_deps = (
                    await db.dependencies.find(
                        {"scan_id": other_scan["_id"]}, {"name": 1, "version": 1}
                    )
                    .limit(100)
                    .to_list(100)
                )

                # Count severities
                stats = other_scan.get("stats") or {}
                severity_counts = stats.get("severity_counts", {})

                cross_project_data["projects"].append(
                    {
                        "project_id": other_pid,
                        "project_name": (
                            other_project.get("name", "Unknown")
                            if other_project
                            else "Unknown"
                        ),
                        "cves": cves,
                        "packages": [
                            {"name": d.get("name"), "version": d.get("version")}
                            for d in other_deps
                        ],
                        "total_critical": severity_counts.get("CRITICAL", 0),
                        "total_high": severity_counts.get("HIGH", 0),
                    }
                )

    # ----------------------------------------------------------------
    # Generate recommendations with all data
    # ----------------------------------------------------------------
    recommendations = await recommendation_engine.generate_recommendations(
        findings=findings,
        dependencies=dependencies,
        source_target=source_target,
        previous_scan_findings=previous_scan_findings,
        scan_history=scan_history,
        cross_project_data=cross_project_data,
    )

    # Count findings by type for stats
    vuln_count = sum(1 for f in findings if f.get("type") == "vulnerability")
    secret_count = sum(1 for f in findings if f.get("type") == "secret")
    sast_count = sum(1 for f in findings if f.get("type") == "sast")
    iac_count = sum(1 for f in findings if f.get("type") == "iac")
    license_count = sum(1 for f in findings if f.get("type") == "license")
    quality_count = sum(1 for f in findings if f.get("type") == "quality")

    # Build extended summary
    summary = {
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
