from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.api.deps import PermissionChecker
from app.db.mongodb import get_database
from app.models.user import User
from app.schemas.analytics import (
    SeverityBreakdown,
    DependencyUsage,
    DependencyListItem,
    DependencyListResponse,
    DependencyTreeNode,
    ImpactAnalysisResult,
    VulnerabilityHotspot,
    DependencyTypeStats,
    AnalyticsSummary,
    DependencyMetadata,
)

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

    # Aggregate vulnerabilities by component with more details
    pipeline = [
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

    results = await db.findings.aggregate(pipeline).to_list(None)

    # Collect all CVE IDs for enrichment
    all_cves = []
    cve_to_result = {}
    cvss_scores = {}
    
    for r in results:
        for fid in r.get("finding_ids", []):
            if fid and fid.startswith("CVE-"):
                all_cves.append(fid)
                if fid not in cve_to_result:
                    cve_to_result[fid] = []
                cve_to_result[fid].append(r)
        
        # Extract CVSS scores from details
        for details in r.get("details_list", []):
            if isinstance(details, dict):
                for vuln in details.get("vulnerabilities", []):
                    vid = vuln.get("id", "")
                    if vid.startswith("CVE-") and vuln.get("cvss_score"):
                        cvss_scores[vid] = vuln["cvss_score"]

    # Enrich with EPSS/KEV data
    enrichments = {}
    if all_cves:
        try:
            from app.services.vulnerability_enrichment import get_cve_enrichment
            enrichments = await get_cve_enrichment(all_cves)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Failed to enrich CVEs: {e}")

    impact_results = []
    for r in results:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for sev in r.get("severities", []):
            if sev:
                sev_lower = sev.lower()
                if sev_lower in severity_counts:
                    severity_counts[sev_lower] += 1

        # Extract fix versions from details
        fix_versions = set()
        for details in r.get("details_list", []):
            if isinstance(details, dict):
                if details.get("fixed_version"):
                    fix_versions.add(details["fixed_version"])
                for vuln in details.get("vulnerabilities", []):
                    if vuln.get("fixed_version"):
                        fix_versions.add(vuln["fixed_version"])

        # Get enrichment data for this component's CVEs
        max_epss = None
        max_percentile = None
        max_risk = None
        has_kev = False
        kev_count = 0
        kev_ransomware_use = False
        kev_due_date = None
        exploit_maturity = "unknown"
        maturity_levels = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "active": 4, "weaponized": 5}
        
        for fid in r.get("finding_ids", []):
            if fid in enrichments:
                enr = enrichments[fid]
                if enr.epss_score is not None:
                    if max_epss is None or enr.epss_score > max_epss:
                        max_epss = enr.epss_score
                        max_percentile = enr.epss_percentile
                if enr.risk_score is not None:
                    if max_risk is None or enr.risk_score > max_risk:
                        max_risk = enr.risk_score
                if enr.is_kev:
                    has_kev = True
                    kev_count += 1
                    # Track ransomware use
                    if enr.kev_ransomware_use:
                        kev_ransomware_use = True
                    # Track earliest due date
                    if enr.kev_due_date:
                        if kev_due_date is None or enr.kev_due_date < kev_due_date:
                            kev_due_date = enr.kev_due_date
                if maturity_levels.get(enr.exploit_maturity, 0) > maturity_levels.get(exploit_maturity, 0):
                    exploit_maturity = enr.exploit_maturity

        # Calculate days known
        days_known = None
        if r.get("first_seen"):
            try:
                first_seen_dt = r["first_seen"]
                if isinstance(first_seen_dt, datetime):
                    days_known = (datetime.now(first_seen_dt.tzinfo or None) - first_seen_dt).days
            except Exception:
                pass

        # Calculate days until KEV due date (negative = overdue)
        days_until_due = None
        if kev_due_date:
            try:
                from datetime import date
                due = datetime.strptime(kev_due_date, "%Y-%m-%d").date()
                days_until_due = (due - date.today()).days
            except Exception:
                pass

        # ============================================================
        # PRIORITY SCORE CALCULATION
        # Factors considered (in order of importance):
        # 1. KEV with ransomware usage (highest priority)
        # 2. KEV with overdue remediation deadline
        # 3. Any KEV entry (actively exploited)
        # 4. High EPSS score (>10% exploitation probability)
        # 5. CVSS severity distribution
        # 6. Number of affected projects (blast radius)
        # 7. Fix availability (prefer fixable issues)
        # 8. Days known (older = more urgent)
        # ============================================================
        
        # Base score from severity (weighted)
        severity_score = (
            severity_counts["critical"] * 10
            + severity_counts["high"] * 5
            + severity_counts["medium"] * 2
            + severity_counts["low"] * 1
        )
        
        # Reach multiplier (how many projects affected)
        reach_multiplier = min(r["affected_projects"], 10)  # Cap at 10x
        
        base_impact = severity_score * reach_multiplier
        
        # KEV Boost (strongest signal - actively exploited)
        if has_kev:
            # Ransomware usage = highest priority
            if kev_ransomware_use:
                base_impact *= 3.0
            # Overdue remediation deadline
            elif days_until_due is not None and days_until_due < 0:
                base_impact *= 2.5
            # Due within 30 days
            elif days_until_due is not None and days_until_due <= 30:
                base_impact *= 2.0
            # KEV but no urgent deadline
            else:
                base_impact *= 1.8
        
        # EPSS Boost (probability of exploitation)
        if max_epss:
            if max_epss >= 0.5:  # 50%+ chance of exploitation
                base_impact *= 1.5
            elif max_epss >= 0.1:  # 10%+ chance
                base_impact *= 1.3
            elif max_epss >= 0.01:  # 1%+ chance
                base_impact *= 1.1
        
        # Exploit maturity boost
        maturity_boost = {
            "weaponized": 1.4,
            "active": 1.3,
            "high": 1.2,
            "medium": 1.1,
            "low": 1.0,
            "unknown": 1.0,
        }
        base_impact *= maturity_boost.get(exploit_maturity, 1.0)
        
        # Fix availability boost (prioritize fixable issues)
        has_fix = len(fix_versions) > 0
        if has_fix:
            base_impact *= 1.2  # Boost fixable issues
        
        # Age factor (older vulnerabilities slightly higher priority)
        if days_known and days_known > 90:
            base_impact *= 1.1  # Known for over 3 months

        # Build priority reasons (human-readable explanations)
        priority_reasons = []
        if kev_ransomware_use:
            priority_reasons.append("🔒 Used in ransomware campaigns - fix immediately")
        if days_until_due is not None and days_until_due < 0:
            priority_reasons.append(f"⚠️ CISA deadline overdue by {abs(days_until_due)} days")
        elif days_until_due is not None and days_until_due <= 30:
            priority_reasons.append(f"📅 CISA deadline in {days_until_due} days")
        if has_kev and not kev_ransomware_use:
            priority_reasons.append("🎯 Actively exploited in the wild (CISA KEV)")
        if max_epss and max_epss >= 0.1:
            priority_reasons.append(f"📈 High exploitation probability ({max_epss*100:.1f}% EPSS)")
        if severity_counts["critical"] > 0:
            priority_reasons.append(f"🔴 {severity_counts['critical']} critical vulnerabilities")
        if r["affected_projects"] >= 3:
            priority_reasons.append(f"🌐 Affects {r['affected_projects']} projects (high blast radius)")
        if has_fix:
            priority_reasons.append("✅ Fix available - easy to remediate")
        if days_known and days_known > 90:
            priority_reasons.append(f"⏰ Known for {days_known} days - overdue for remediation")

        impact_results.append(
            ImpactAnalysisResult(
                component=r["component"],
                version=r.get("version") or "unknown",
                affected_projects=r["affected_projects"],
                total_findings=r["total_findings"],
                findings_by_severity=SeverityBreakdown(**severity_counts),
                fix_impact_score=float(base_impact),
                affected_project_names=[
                    project_name_map.get(pid, "Unknown")
                    for pid in r["project_ids"][:5]
                ],
                max_epss_score=max_epss,
                epss_percentile=max_percentile,
                has_kev=has_kev,
                kev_count=kev_count,
                kev_ransomware_use=kev_ransomware_use,
                kev_due_date=kev_due_date,
                days_until_due=days_until_due,
                exploit_maturity=exploit_maturity,
                max_risk_score=max_risk,
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
    sort_by: str = Query("finding_count", description="Sort field: finding_count, component, first_seen, epss, risk"),
    sort_order: str = Query("desc", description="Sort order: asc, desc"),
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

    pipeline = [
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

    results = await db.findings.aggregate(pipeline).to_list(None)
    
    if not post_sort_by:
        results = results[skip:skip + limit]

    # Collect all CVE IDs for enrichment
    all_cves = []
    for r in results:
        for fid in r.get("finding_ids", []):
            if fid and fid.startswith("CVE-"):
                all_cves.append(fid)

    # Enrich with EPSS/KEV data
    enrichments = {}
    if all_cves:
        try:
            from app.services.vulnerability_enrichment import get_cve_enrichment
            enrichments = await get_cve_enrichment(list(set(all_cves)))
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Failed to enrich CVEs: {e}")

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
        days_known = None
        if r.get("first_seen"):
            if isinstance(r["first_seen"], datetime):
                first_seen_str = r["first_seen"].isoformat()
                try:
                    days_known = (datetime.now(r["first_seen"].tzinfo or None) - r["first_seen"]).days
                except Exception:
                    pass
            else:
                first_seen_str = str(r["first_seen"])

        # Extract fix versions from details
        fix_versions = set()
        for details in r.get("details_list", []):
            if isinstance(details, dict):
                if details.get("fixed_version"):
                    fix_versions.add(details["fixed_version"])
                for vuln in details.get("vulnerabilities", []):
                    if vuln.get("fixed_version"):
                        fix_versions.add(vuln["fixed_version"])

        # Get enrichment data for this component's CVEs
        max_epss = None
        max_percentile = None
        max_risk = None
        has_kev = False
        kev_count = 0
        kev_ransomware_use = False
        kev_due_date = None
        exploit_maturity = "unknown"
        top_cves = []
        maturity_levels = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "active": 4, "weaponized": 5}
        
        for fid in r.get("finding_ids", []):
            if fid and fid.startswith("CVE-"):
                if fid not in top_cves:
                    top_cves.append(fid)
                if fid in enrichments:
                    enr = enrichments[fid]
                    if enr.epss_score is not None:
                        if max_epss is None or enr.epss_score > max_epss:
                            max_epss = enr.epss_score
                            max_percentile = enr.epss_percentile
                    if enr.risk_score is not None:
                        if max_risk is None or enr.risk_score > max_risk:
                            max_risk = enr.risk_score
                    if enr.is_kev:
                        has_kev = True
                        kev_count += 1
                        if enr.kev_ransomware_use:
                            kev_ransomware_use = True
                        if enr.kev_due_date:
                            if kev_due_date is None or enr.kev_due_date < kev_due_date:
                                kev_due_date = enr.kev_due_date
                    if maturity_levels.get(enr.exploit_maturity, 0) > maturity_levels.get(exploit_maturity, 0):
                        exploit_maturity = enr.exploit_maturity

        # Calculate days until KEV due date
        days_until_due = None
        if kev_due_date:
            try:
                from datetime import date
                due = datetime.strptime(kev_due_date, "%Y-%m-%d").date()
                days_until_due = (due - date.today()).days
            except Exception:
                pass

        # Build priority reasons
        priority_reasons = []
        if kev_ransomware_use:
            priority_reasons.append("🔒 Used in ransomware campaigns")
        if days_until_due is not None and days_until_due < 0:
            priority_reasons.append(f"⚠️ CISA deadline overdue by {abs(days_until_due)} days")
        elif days_until_due is not None and days_until_due <= 30:
            priority_reasons.append(f"📅 CISA deadline in {days_until_due} days")
        if has_kev and not kev_ransomware_use:
            priority_reasons.append("🎯 Actively exploited (CISA KEV)")
        if max_epss and max_epss >= 0.1:
            priority_reasons.append(f"📈 High EPSS ({max_epss*100:.1f}%)")
        if severity_counts["critical"] > 0:
            priority_reasons.append(f"🔴 {severity_counts['critical']} critical vulns")
        has_fix = len(fix_versions) > 0
        if has_fix:
            priority_reasons.append("✅ Fix available")

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
                max_epss_score=max_epss,
                epss_percentile=max_percentile,
                has_kev=has_kev,
                kev_count=kev_count,
                kev_ransomware_use=kev_ransomware_use,
                kev_due_date=kev_due_date,
                days_until_due=days_until_due,
                exploit_maturity=exploit_maturity,
                max_risk_score=max_risk,
                days_known=days_known,
                has_fix=has_fix,
                fix_versions=list(fix_versions)[:3],
                top_cves=top_cves[:5],
                priority_reasons=priority_reasons,
            )
        )

    # Post-sort by enrichment data if needed
    if post_sort_by == "epss":
        hotspots.sort(key=lambda x: x.max_epss_score or 0, reverse=(sort_order == "desc"))
        hotspots = hotspots[skip:skip + limit]
    elif post_sort_by == "risk":
        hotspots.sort(key=lambda x: x.max_risk_score or 0, reverse=(sort_order == "desc"))
        hotspots = hotspots[skip:skip + limit]

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
    sort_by: str = Query("name", description="Sort field: name, version, type, project_name, license, direct"),
    sort_order: str = Query("asc", description="Sort order: asc or desc"),
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

    dependencies = (
        await db.dependencies.find(query)
        .sort(mongo_sort_field, sort_direction)
        .skip(skip)
        .limit(limit)
        .to_list(limit)
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


@router.get("/dependency-metadata")
async def get_dependency_metadata_endpoint(
    component: str = Query(..., description="Component/package name"),
    version: Optional[str] = Query(None, description="Specific version"),
    type: Optional[str] = Query(None, description="Package type"),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get aggregated metadata for a dependency across all accessible projects.
    Returns dependency-specific information (not project-specific like Docker layers).
    """
    require_analytics_permission(current_user, "analytics:search")

    project_ids = await get_user_project_ids(current_user, db)

    if not project_ids:
        return None

    scan_ids = await get_latest_scan_ids(project_ids, db)

    if not scan_ids:
        return None

    # Build query for dependencies
    dep_query = {"scan_id": {"$in": scan_ids}, "name": component}
    if version:
        dep_query["version"] = version
    if type:
        dep_query["type"] = type

    dependencies = await db.dependencies.find(dep_query).to_list(100)

    if not dependencies:
        return None

    # Get project names for enrichment
    projects = await db.projects.find(
        {"_id": {"$in": project_ids}}, {"_id": 1, "name": 1}
    ).to_list(None)
    project_name_map = {p["_id"]: p["name"] for p in projects}

    # Aggregate dependency-specific metadata (take first non-null value)
    first_dep = dependencies[0]
    
    # Collect affected projects (with deduplication)
    affected_projects = {}
    for dep in dependencies:
        proj_id = dep.get("project_id")
        if proj_id and proj_id not in affected_projects:
            affected_projects[proj_id] = {
                "id": proj_id,
                "name": project_name_map.get(proj_id, "Unknown"),
                "direct": dep.get("direct", False),
            }
    
    # Get deps.dev enrichment if available
    deps_dev_data = None
    enrichment_sources = []
    
    dep_purl = first_dep.get("purl")
    if dep_purl:
        enrichment = await db.dependency_enrichments.find_one({"purl": dep_purl})
        if enrichment:
            deps_dev_data = enrichment.get("deps_dev")
            if deps_dev_data:
                enrichment_sources.append("deps_dev")
            
            # Get license enrichment
            license_info = enrichment.get("license_compliance")
            if license_info:
                enrichment_sources.append("license_compliance")
    
    # Helper function to get first non-null value from dependencies
    def first_value(key: str):
        for dep in dependencies:
            val = dep.get(key)
            if val:
                return val
        return None
    
    # Count findings for this component
    finding_query = {"scan_id": {"$in": scan_ids}, "component": component}
    if version:
        finding_query["version"] = version
    
    finding_count = await db.findings.count_documents(finding_query)
    
    # Count vulnerabilities specifically
    vuln_query = {**finding_query, "type": "VULNERABILITY"}
    vuln_count = await db.findings.count_documents(vuln_query)
    
    # Collect license info (may come from enrichment or SBOM)
    license_category = None
    license_risks = []
    license_obligations = []
    
    if dep_purl:
        enrichment = await db.dependency_enrichments.find_one({"purl": dep_purl})
        if enrichment and enrichment.get("license_compliance"):
            lic_info = enrichment["license_compliance"]
            license_category = lic_info.get("category")
            license_risks = lic_info.get("risks", [])
            license_obligations = lic_info.get("obligations", [])
    
    return DependencyMetadata(
        name=first_dep.get("name", component),
        version=first_dep.get("version", version or "unknown"),
        type=first_dep.get("type", "unknown"),
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
