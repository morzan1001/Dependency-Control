from fastapi import APIRouter, Depends, Query, HTTPException
from typing import List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel
from datetime import datetime

from app.api import deps
from app.api.deps import PermissionChecker
from app.models.user import User
from app.db.mongodb import get_database

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
            detail=f"Analytics permission required: {permission}. Grant 'analytics:read' for full analytics access or '{permission}' for this specific feature."
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
                {"team_id": {"$in": user_team_ids}}
            ]
        },
        {"_id": 1}
    ).to_list(None)
    
    return [p["_id"] for p in projects]


async def get_latest_scan_ids(project_ids: List[str], db: AsyncIOMotorDatabase) -> List[str]:
    """Get latest scan IDs for given projects."""
    projects = await db.projects.find(
        {"_id": {"$in": project_ids}},
        {"latest_scan_id": 1}
    ).to_list(None)
    
    return [p["latest_scan_id"] for p in projects if p.get("latest_scan_id")]


@router.get("/summary", response_model=AnalyticsSummary)
async def get_analytics_summary(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
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
            severity_distribution=SeverityBreakdown()
        )
    
    scan_ids = await get_latest_scan_ids(project_ids, db)
    
    if not scan_ids:
        return AnalyticsSummary(
            total_dependencies=0,
            total_vulnerabilities=0,
            unique_packages=0,
            dependency_types=[],
            severity_distribution=SeverityBreakdown()
        )
    
    # Count total dependencies
    total_deps = await db.dependencies.count_documents({"scan_id": {"$in": scan_ids}})
    
    # Count unique packages
    unique_pipeline = [
        {"$match": {"scan_id": {"$in": scan_ids}}},
        {"$group": {"_id": "$name"}},
        {"$count": "count"}
    ]
    unique_result = await db.dependencies.aggregate(unique_pipeline).to_list(1)
    unique_packages = unique_result[0]["count"] if unique_result else 0
    
    # Get dependency types distribution
    type_pipeline = [
        {"$match": {"scan_id": {"$in": scan_ids}}},
        {"$group": {"_id": "$type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    type_results = await db.dependencies.aggregate(type_pipeline).to_list(None)
    
    dependency_types = []
    for t in type_results:
        if t["_id"]:
            dependency_types.append(DependencyTypeStats(
                type=t["_id"],
                count=t["count"],
                percentage=round((t["count"] / total_deps * 100) if total_deps > 0 else 0, 1)
            ))
    
    # Get vulnerability counts by severity
    severity_pipeline = [
        {"$match": {
            "scan_id": {"$in": scan_ids},
            "finding.type": "vulnerability"
        }},
        {"$group": {
            "_id": "$finding.severity",
            "count": {"$sum": 1}
        }}
    ]
    severity_results = await db.finding_records.aggregate(severity_pipeline).to_list(None)
    
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
        severity_distribution=severity_dist
    )


@router.get("/dependencies/top", response_model=List[DependencyUsage])
async def get_top_dependencies(
    limit: int = Query(20, ge=1, le=100),
    type: Optional[str] = Query(None, description="Filter by dependency type (npm, pypi, maven, etc.)"),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
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
        {"$group": {
            "_id": "$name",
            "type": {"$first": "$type"},
            "versions": {"$addToSet": "$version"},
            "project_ids": {"$addToSet": "$project_id"},
            "total_occurrences": {"$sum": 1}
        }},
        {"$project": {
            "name": "$_id",
            "type": 1,
            "versions": 1,
            "project_count": {"$size": "$project_ids"},
            "total_occurrences": 1
        }},
        {"$sort": {"project_count": -1, "total_occurrences": -1}},
        {"$limit": limit}
    ]
    
    results = await db.dependencies.aggregate(pipeline).to_list(None)
    
    # Enrich with vulnerability info
    enriched = []
    for dep in results:
        vuln_count = await db.finding_records.count_documents({
            "project_id": {"$in": project_ids},
            "finding.component": dep["name"],
            "finding.type": "vulnerability"
        })
        enriched.append(DependencyUsage(
            name=dep["name"],
            type=dep.get("type", "unknown"),
            versions=dep["versions"][:10],  # Limit versions to 10
            project_count=dep["project_count"],
            total_occurrences=dep["total_occurrences"],
            has_vulnerabilities=vuln_count > 0,
            vulnerability_count=vuln_count
        ))
    
    return enriched


@router.get("/projects/{project_id}/dependency-tree", response_model=List[DependencyTreeNode])
async def get_dependency_tree(
    project_id: str,
    scan_id: Optional[str] = Query(None, description="Specific scan ID, defaults to latest"),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
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
    dependencies = await db.dependencies.find(
        {"scan_id": scan_id}
    ).to_list(None)
    
    if not dependencies:
        return []
    
    # Get findings for this scan
    findings = await db.finding_records.find(
        {"scan_id": scan_id, "finding.type": "vulnerability"},
        {"finding.component": 1, "finding.severity": 1}
    ).to_list(None)
    
    # Build findings map
    findings_map = {}
    for f in findings:
        comp = f["finding"]["component"]
        sev = f["finding"].get("severity", "UNKNOWN")
        if comp not in findings_map:
            findings_map[comp] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
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
            findings_severity=SeverityBreakdown(
                critical=finding_info.get("critical", 0),
                high=finding_info.get("high", 0),
                medium=finding_info.get("medium", 0),
                low=finding_info.get("low", 0)
            ) if finding_info else None,
            source_type=dep.get("source_type"),
            source_target=dep.get("source_target"),
            layer_digest=dep.get("layer_digest"),
            locations=dep.get("locations", []),
            children=[]
        )
    
    # Separate direct and transitive dependencies
    direct_deps = [build_node(d) for d in dependencies if d.get("direct", False)]
    transitive_deps = [build_node(d) for d in dependencies if not d.get("direct", False)]
    
    # Sort by findings count (most problematic first)
    direct_deps.sort(key=lambda x: x.findings_count, reverse=True)
    transitive_deps.sort(key=lambda x: x.findings_count, reverse=True)
    
    return direct_deps + transitive_deps


@router.get("/impact", response_model=List[ImpactAnalysisResult])
async def get_impact_analysis(
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Analyze which dependency fixes would have the highest impact across projects."""
    require_analytics_permission(current_user, "analytics:impact")
    
    project_ids = await get_user_project_ids(current_user, db)
    
    if not project_ids:
        return []
    
    # Get project name map
    projects = await db.projects.find(
        {"_id": {"$in": project_ids}},
        {"_id": 1, "name": 1, "latest_scan_id": 1}
    ).to_list(None)
    
    project_name_map = {p["_id"]: p["name"] for p in projects}
    scan_ids = [p["latest_scan_id"] for p in projects if p.get("latest_scan_id")]
    
    if not scan_ids:
        return []
    
    # Aggregate vulnerabilities by component
    pipeline = [
        {"$match": {
            "scan_id": {"$in": scan_ids},
            "finding.type": "vulnerability"
        }},
        {"$group": {
            "_id": {
                "component": "$finding.component",
                "version": "$finding.version"
            },
            "project_ids": {"$addToSet": "$project_id"},
            "total_findings": {"$sum": 1},
            "severities": {"$push": "$finding.severity"}
        }},
        {"$project": {
            "component": "$_id.component",
            "version": "$_id.version",
            "project_ids": 1,
            "total_findings": 1,
            "severities": 1,
            "affected_projects": {"$size": "$project_ids"}
        }},
        {"$sort": {"affected_projects": -1, "total_findings": -1}},
        {"$limit": limit}
    ]
    
    results = await db.finding_records.aggregate(pipeline).to_list(None)
    
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
            severity_counts["critical"] * 10 +
            severity_counts["high"] * 5 +
            severity_counts["medium"] * 2 +
            severity_counts["low"] * 1
        ) * r["affected_projects"]
        
        impact_results.append(ImpactAnalysisResult(
            component=r["component"],
            version=r.get("version") or "unknown",
            affected_projects=r["affected_projects"],
            total_findings=r["total_findings"],
            findings_by_severity=SeverityBreakdown(**severity_counts),
            fix_impact_score=float(impact_score),
            affected_project_names=[
                project_name_map.get(pid, "Unknown") 
                for pid in r["project_ids"][:5]  # Limit to 5 names
            ]
        ))
    
    # Sort by impact score
    impact_results.sort(key=lambda x: x.fix_impact_score, reverse=True)
    
    return impact_results


@router.get("/hotspots", response_model=List[VulnerabilityHotspot])
async def get_vulnerability_hotspots(
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Get dependencies with the most vulnerabilities (hotspots)."""
    require_analytics_permission(current_user, "analytics:hotspots")
    
    project_ids = await get_user_project_ids(current_user, db)
    
    if not project_ids:
        return []
    
    projects = await db.projects.find(
        {"_id": {"$in": project_ids}},
        {"_id": 1, "name": 1, "latest_scan_id": 1}
    ).to_list(None)
    
    project_name_map = {p["_id"]: p["name"] for p in projects}
    scan_ids = [p["latest_scan_id"] for p in projects if p.get("latest_scan_id")]
    
    if not scan_ids:
        return []
    
    pipeline = [
        {"$match": {
            "scan_id": {"$in": scan_ids},
            "finding.type": "vulnerability"
        }},
        {"$group": {
            "_id": {
                "component": "$finding.component",
                "version": "$finding.version"
            },
            "project_ids": {"$addToSet": "$project_id"},
            "finding_count": {"$sum": 1},
            "severities": {"$push": "$finding.severity"},
            "first_seen": {"$min": "$created_at"}
        }},
        {"$sort": {"finding_count": -1}},
        {"$limit": limit}
    ]
    
    results = await db.finding_records.aggregate(pipeline).to_list(None)
    
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
        
        hotspots.append(VulnerabilityHotspot(
            component=r["_id"]["component"],
            version=r["_id"].get("version") or "unknown",
            type=dep_type,
            finding_count=r["finding_count"],
            severity_breakdown=SeverityBreakdown(**severity_counts),
            affected_projects=[
                project_name_map.get(pid, "Unknown") 
                for pid in r["project_ids"][:10]
            ],
            first_seen=first_seen_str
        ))
    
    return hotspots


@router.get("/search")
async def search_dependencies_advanced(
    q: str = Query(..., min_length=2, description="Search query for package name"),
    version: Optional[str] = Query(None, description="Filter by specific version"),
    type: Optional[str] = Query(None, description="Filter by package type"),
    source_type: Optional[str] = Query(None, description="Filter by source type (image, file-system, directory, application)"),
    has_vulnerabilities: Optional[bool] = Query(None, description="Filter by vulnerability status"),
    project_ids: Optional[str] = Query(None, description="Comma-separated list of project IDs"),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Advanced dependency search with multiple filters."""
    require_analytics_permission(current_user, "analytics:search")
    
    accessible_project_ids = await get_user_project_ids(current_user, db)
    
    # Filter by requested project IDs if provided
    if project_ids:
        requested_ids = [pid.strip() for pid in project_ids.split(",")]
        accessible_project_ids = [
            pid for pid in accessible_project_ids 
            if pid in requested_ids
        ]
    
    if not accessible_project_ids:
        return []
    
    projects = await db.projects.find(
        {"_id": {"$in": accessible_project_ids}},
        {"_id": 1, "name": 1, "latest_scan_id": 1}
    ).to_list(None)
    
    project_name_map = {p["_id"]: p["name"] for p in projects}
    scan_ids = [p["latest_scan_id"] for p in projects if p.get("latest_scan_id")]
    
    if not scan_ids:
        return []
    
    query = {
        "scan_id": {"$in": scan_ids},
        "name": {"$regex": q, "$options": "i"}
    }
    if version:
        query["version"] = version
    if type:
        query["type"] = type
    if source_type:
        query["source_type"] = source_type
    
    dependencies = await db.dependencies.find(query).limit(limit).to_list(limit)
    
    results = []
    for dep in dependencies:
        # Check for vulnerabilities if filter is set
        if has_vulnerabilities is not None:
            vuln_count = await db.finding_records.count_documents({
                "project_id": dep["project_id"],
                "finding.component": dep["name"],
                "finding.type": "vulnerability"
            })
            if has_vulnerabilities and vuln_count == 0:
                continue
            if not has_vulnerabilities and vuln_count > 0:
                continue
        
        results.append({
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
        })
    
    return results


@router.get("/component-findings")
async def get_component_findings(
    component: str = Query(..., description="Component/package name"),
    version: Optional[str] = Query(None, description="Specific version"),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Get all findings for a specific component across accessible projects."""
    require_analytics_permission(current_user, "analytics:search")
    
    project_ids = await get_user_project_ids(current_user, db)
    
    if not project_ids:
        return []
    
    scan_ids = await get_latest_scan_ids(project_ids, db)
    
    if not scan_ids:
        return []
    
    query = {
        "scan_id": {"$in": scan_ids},
        "finding.component": component
    }
    if version:
        query["finding.version"] = version
    
    finding_records = await db.finding_records.find(query).limit(100).to_list(100)
    
    # Get project names for enrichment
    projects = await db.projects.find(
        {"_id": {"$in": project_ids}},
        {"_id": 1, "name": 1}
    ).to_list(None)
    project_name_map = {p["_id"]: p["name"] for p in projects}
    
    results = []
    for fr in finding_records:
        finding = fr["finding"]
        finding["project_id"] = fr.get("project_id")
        finding["project_name"] = project_name_map.get(fr.get("project_id"), "Unknown")
        results.append(finding)
    
    return results


@router.get("/dependency-types")
async def get_dependency_types(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
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
        {"$sort": {"_id": 1}}
    ]
    
    results = await db.dependencies.aggregate(pipeline).to_list(None)
    
    return [r["_id"] for r in results if r["_id"]]
