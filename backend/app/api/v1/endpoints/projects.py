from fastapi import APIRouter, Depends, HTTPException, status, Response
from typing import List, Dict, Any
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket
from bson import ObjectId
import secrets
import csv
import io
import json
from datetime import datetime, timedelta

from app.api import deps
from app.core import security
from app.models.project import Project, Scan, AnalysisResult, ProjectMember
from app.models.user import User
from app.models.invitation import ProjectInvitation
from app.schemas.project import ProjectCreate, ProjectUpdate, ProjectMemberInvite, ProjectNotificationSettings, ProjectApiKeyResponse, ProjectMemberUpdate, ProjectList
from app.db.mongodb import get_database
from pydantic import BaseModel

router = APIRouter()

class RecentScan(Scan):
    project_name: str

async def check_project_access(project_id: str, user: User, db: AsyncIOMotorDatabase, required_role: str = None) -> Project:
    project_data = await db.projects.find_one({"_id": project_id})
    if not project_data:
        raise HTTPException(status_code=404, detail="Project not found")
    
    project = Project(**project_data)
    
    if "*" in user.permissions:
        return project

    # Global read access
    if required_role is None and "project:read_all" in user.permissions:
        return project

    is_owner = project.owner_id == str(user.id)
    is_member = False
    member_role = None
    
    for member in project.members:
        if member.user_id == str(user.id):
            is_member = True
            member_role = member.role
            break
            
    # Check team membership if project belongs to a team
    if project.team_id:
        team = await db.teams.find_one({"_id": project.team_id, "members.user_id": str(user.id)})
        if team:
            # Team members get 'viewer' access by default, 
            # Team admins/owners get 'admin' access on project.
            for tm in team["members"]:
                if tm["user_id"] == str(user.id):
                    if tm["role"] in ["admin", "owner"]:
                        member_role = "admin"
                    else:
                        member_role = "viewer"
                    break
            is_member = True

    if not (is_owner or is_member):
        raise HTTPException(status_code=403, detail="Not enough permissions")

    # Check for basic read permission
    if "project:read" not in user.permissions and "project:read_all" not in user.permissions:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    if required_role:
        if is_owner:
            return project
        # Role hierarchy: admin > editor > viewer
        roles = ["viewer", "editor", "admin"]
        # If member_role is None, default to viewer
        current_role = member_role or "viewer"
        if roles.index(current_role) < roles.index(required_role):
             raise HTTPException(status_code=403, detail="Not enough permissions")
             
    return project

class DashboardStats(BaseModel):
    total_projects: int
    total_critical: int
    total_high: int
    avg_risk_score: float
    top_risky_projects: List[Dict[str, Any]]

@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.get_current_active_user),
):
    # Filter projects user has access to
    query = {}
    if "*" not in current_user.permissions and "project:read_all" not in current_user.permissions:
        # Find teams user is member of
        user_teams = await db.teams.find({"members.user_id": str(current_user.id)}).to_list(None)
        team_ids = [t["_id"] for t in user_teams]
        
        query = {
            "$or": [
                {"owner_id": str(current_user.id)},
                {"members.user_id": str(current_user.id)},
                {"team_id": {"$in": team_ids}}
            ]
        }

    # Use aggregation for performance instead of fetching all projects
    pipeline = [
        {"$match": query},
        {"$project": {
            "name": 1,
            "stats": 1,
            # Calculate risk if missing (fallback logic)
            "calculated_risk": {
                "$ifNull": [
                    "$stats.risk_score",
                    {"$add": [
                        {"$multiply": [{"$ifNull": ["$stats.critical", 0]}, 10]},
                        {"$multiply": [{"$ifNull": ["$stats.high", 0]}, 7.5]},
                        {"$multiply": [{"$ifNull": ["$stats.medium", 0]}, 4]},
                        {"$multiply": [{"$ifNull": ["$stats.low", 0]}, 1]}
                    ]}
                ]
            }
        }},
        {"$facet": {
            "totals": [
                {"$group": {
                    "_id": None,
                    "total_projects": {"$sum": 1},
                    "total_critical": {"$sum": "$stats.critical"},
                    "total_high": {"$sum": "$stats.high"},
                    "total_risk_score": {"$sum": "$calculated_risk"}
                }}
            ],
            "top_risky": [
                {"$sort": {"calculated_risk": -1}},
                {"$limit": 5},
                {"$project": {"name": 1, "risk": "$calculated_risk", "id": "$_id"}}
            ]
        }}
    ]

    result = await db.projects.aggregate(pipeline).to_list(1)
    
    if not result:
        return {
            "total_projects": 0,
            "total_critical": 0,
            "total_high": 0,
            "avg_risk_score": 0.0,
            "top_risky_projects": []
        }

    data = result[0]
    totals = data["totals"][0] if data["totals"] else {}
    top_risky = data["top_risky"]

    total_projects = totals.get("total_projects", 0)
    total_risk_score = totals.get("total_risk_score", 0.0)
    
    avg_risk = 0.0
    if total_projects > 0:
        avg_risk = round(total_risk_score / total_projects, 1)

    return {
        "total_projects": total_projects,
        "total_critical": totals.get("total_critical", 0),
        "total_high": totals.get("total_high", 0),
        "avg_risk_score": avg_risk,
        "top_risky_projects": top_risky
    }

@router.post("/", response_model=ProjectApiKeyResponse, summary="Create a new project", status_code=201)
async def create_project(
    project_in: ProjectCreate,
    current_user: User = Depends(deps.PermissionChecker("project:create")),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Create a new project and return the initial API Key.
    
    **Important**: The API Key is only returned once. Save it securely.
    """
    # If team_id is provided, check if user is member of that team
    if project_in.team_id:
        team = await db.teams.find_one({"_id": project_in.team_id, "members.user_id": str(current_user.id)})
        if not team:
             raise HTTPException(status_code=403, detail="You are not a member of the specified team")

    # Generate API Key
    # Format: project_id.secret
    # The project ID is required first.
    import uuid
    project_id = str(uuid.uuid4())
    secret = secrets.token_urlsafe(32)
    api_key = f"{project_id}.{secret}"
    api_key_hash = security.get_password_hash(secret)
    
    project = Project(
        id=project_id,
        name=project_in.name,
        owner_id=str(current_user.id),
        team_id=project_in.team_id,
        api_key_hash=api_key_hash,
        active_analyzers=project_in.active_analyzers,
        retention_days=project_in.retention_days if project_in.retention_days is not None else 90,
        members=[
            ProjectMember(
                user_id=str(current_user.id),
                role="admin"
            )
        ]
    )
    
    # api_key_hash is excluded from dict() by default in the model, so we must add it manually
    project_data = project.dict(by_alias=True)
    project_data["api_key_hash"] = api_key_hash
    
    await db.projects.insert_one(project_data)
    
    return ProjectApiKeyResponse(
        project_id=project_id,
        api_key=api_key
    )

@router.post("/{project_id}/rotate-key", response_model=ProjectApiKeyResponse, summary="Rotate Project API Key")
async def rotate_api_key(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Invalidate the old API Key and generate a new one.
    
    Requires 'admin' role on the project.
    """
    if "*" in current_user.permissions or "project:update" in current_user.permissions:
        project_data = await db.projects.find_one({"_id": project_id})
        if not project_data:
            raise HTTPException(status_code=404, detail="Project not found")
    else:
        await check_project_access(project_id, current_user, db, required_role="admin")
    
    # Generate new key
    secret = secrets.token_urlsafe(32)
    api_key = f"{project_id}.{secret}"
    api_key_hash = security.get_password_hash(secret)
    
    await db.projects.update_one(
        {"_id": project_id},
        {"$set": {"api_key_hash": api_key_hash}}
    )
    
    return ProjectApiKeyResponse(
        project_id=project_id,
        api_key=api_key
    )

@router.get("/", response_model=ProjectList, summary="List all projects")
async def read_projects(
    search: str = None,
    skip: int = 0,
    limit: int = 20,
    sort_by: str = "created_at",
    sort_order: str = "desc",
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Retrieve projects.
    
    - **Superusers** see all projects.
    - **Regular users** see projects they own or are members of.
    """
    query = {}
    if search:
        query["name"] = {"$regex": search, "$options": "i"}

    final_query = query

    if "*" not in current_user.permissions and "project:read_all" not in current_user.permissions:
        if "project:read" not in current_user.permissions:
             raise HTTPException(status_code=403, detail="Not enough permissions")

        # Get teams user is member of
        user_teams = await db.teams.find({"members.user_id": str(current_user.id)}).to_list(None)
        team_ids = [t["_id"] for t in user_teams]

        # Find projects where user is owner OR is in members list OR project belongs to one of user's teams
        permission_query = {
            "$or": [
                {"owner_id": str(current_user.id)},
                {"members.user_id": str(current_user.id)},
                {"team_id": {"$in": team_ids}}
            ]
        }
        
        if query:
            final_query = {"$and": [query, permission_query]}
        else:
            final_query = permission_query

    # Determine sort direction
    direction = -1 if sort_order.lower() == "desc" else 1
    
    # Validate sort_by to prevent injection or errors
    allowed_sort_fields = {
        "name": "name",
        "created_at": "created_at",
        "last_scan_at": "last_scan_at",
        "critical": "stats.critical",
        "high": "stats.high",
        "risk_score": "stats.risk_score"
    }
    
    sort_field = allowed_sort_fields.get(sort_by, "created_at")

    total = await db.projects.count_documents(final_query)
    cursor = db.projects.find(final_query).sort(sort_field, direction).skip(skip).limit(limit)
    projects = await cursor.to_list(length=limit)
    
    return {
        "items": projects,
        "total": total,
        "page": (skip // limit) + 1 if limit > 0 else 1,
        "size": limit,
        "pages": (total + limit - 1) // limit if limit > 0 else 0
    }

@router.get("/recent-scans", response_model=List[RecentScan], summary="List recent scans across all accessible projects")
async def read_recent_scans(
    limit: int = 10,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Retrieve recent scans for all projects the user has access to.
    """
    # 1. Get accessible project IDs
    if "*" in current_user.permissions or "project:read_all" in current_user.permissions:
        # Admin sees all
        project_cursor = db.projects.find({}, {"_id": 1, "name": 1})
    elif "project:read" in current_user.permissions:
        # Get teams user is member of
        user_teams = await db.teams.find({"members.user_id": str(current_user.id)}).to_list(1000)
        team_ids = [t["_id"] for t in user_teams]

        # Find projects where user is owner OR is in members list OR project belongs to one of user's teams
        project_cursor = db.projects.find({
            "$or": [
                {"owner_id": str(current_user.id)},
                {"members.user_id": str(current_user.id)},
                {"team_id": {"$in": team_ids}}
            ]
        }, {"_id": 1, "name": 1})
    else:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    projects = await project_cursor.to_list(10000)
    project_map = {p["_id"]: p["name"] for p in projects}
    project_ids = list(project_map.keys())

    if not project_ids:
        return []

    # 2. Get recent scans for these projects
    pipeline = [
        {"$match": {"project_id": {"$in": project_ids}}},
        {"$sort": {"created_at": -1}},
        {"$limit": limit},
        {"$lookup": {
            "from": "projects",
            "localField": "project_id",
            "foreignField": "_id",
            "as": "project_info"
        }},
        {"$unwind": "$project_info"},
        {"$addFields": {
            "project_name": "$project_info.name"
        }},
        {"$project": {"project_info": 0, "sboms": 0, "findings_summary": 0}}
    ]

    scans = await db.scans.aggregate(pipeline).to_list(limit)
    return scans

@router.get("/{project_id}", response_model=Project, summary="Get project details")
async def read_project(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get a specific project by ID.
    """
    # Optimized fetch with aggregation to avoid N+1 queries
    pipeline = [
        {"$match": {"_id": project_id}},
        # Lookup Team
        {"$lookup": {
            "from": "teams",
            "localField": "team_id",
            "foreignField": "_id",
            "as": "team_data"
        }},
        {"$unwind": {"path": "$team_data", "preserveNullAndEmptyArrays": True}},
        # Lookup Users (for project members)
        {"$lookup": {
            "from": "users",
            "let": {"member_ids": "$members.user_id"},
            "pipeline": [
                {"$match": {"$expr": {"$in": [{"$toString": "$_id"}, "$$member_ids"]}}},
                {"$project": {"_id": 1, "username": 1}}
            ],
            "as": "project_users"
        }},
        # Lookup Users (for team members)
        {"$lookup": {
            "from": "users",
            "let": {"team_member_ids": {"$ifNull": ["$team_data.members.user_id", []]}},
            "pipeline": [
                {"$match": {"$expr": {"$in": [{"$toString": "$_id"}, "$$team_member_ids"]}}},
                {"$project": {"_id": 1, "username": 1}}
            ],
            "as": "team_users"
        }}
    ]
    
    result = await db.projects.aggregate(pipeline).to_list(1)
    if not result:
        raise HTTPException(status_code=404, detail="Project not found")
        
    data = result[0]
    
    # Map users
    p_users = {str(u["_id"]): u["username"] for u in data.get("project_users", [])}
    t_users = {str(u["_id"]): u["username"] for u in data.get("team_users", [])}
    
    # Enrich direct members
    for m in data.get("members", []):
        m["username"] = p_users.get(m["user_id"])
        
    # Merge team members
    team_data = data.get("team_data")
    if team_data:
        existing_ids = set(m["user_id"] for m in data["members"])
        
        for tm in team_data.get("members", []):
            uid = tm["user_id"]
            if uid not in existing_ids:
                role = "admin" if tm.get("role") in ["admin", "owner"] else "viewer"
                data["members"].append({
                    "user_id": uid,
                    "role": role,
                    "username": t_users.get(uid),
                    "inherited_from": f"Team: {team_data.get('name')}"
                })

    # Construct Project object
    # We need to remove aux fields that are not in Project model
    data.pop("team_data", None)
    data.pop("project_users", None)
    data.pop("team_users", None)
    
    project = Project(**data)
    
    # Verify Access (Logic from check_project_access but using loaded data)
    if "*" in current_user.permissions or "project:read_all" in current_user.permissions:
        pass
    else:
        is_owner = project.owner_id == str(current_user.id)
        is_member = any(m.user_id == str(current_user.id) for m in project.members)
        
        if not (is_owner or is_member):
             raise HTTPException(status_code=403, detail="Not enough permissions")

        if "project:read" not in current_user.permissions:
            raise HTTPException(status_code=403, detail="Not enough permissions")

    return project

@router.put("/{project_id}", response_model=Project, summary="Update project details")
async def update_project(
    project_id: str,
    project_in: ProjectUpdate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Update project details (name, team, active analyzers).
    Requires 'admin' role on the project.
    """
    if "*" in current_user.permissions or "project:update" in current_user.permissions:
        project_data = await db.projects.find_one({"_id": project_id})
        if not project_data:
            raise HTTPException(status_code=404, detail="Project not found")
        project = Project(**project_data)
    else:
        project = await check_project_access(project_id, current_user, db, required_role="admin")
    
    # If transferring to a team, verify membership
    if project_in.team_id and project_in.team_id != project.team_id:
        # Check if user is member of the new team
        # Exception: Superusers can transfer to any team
        if "*" not in current_user.permissions and "project:update" not in current_user.permissions:
             team = await db.teams.find_one({"_id": project_in.team_id, "members.user_id": str(current_user.id)})
             if not team:
                 raise HTTPException(status_code=403, detail="You are not a member of the target team")

    update_data = {k: v for k, v in project_in.dict(exclude_unset=True).items()}
    
    if update_data:
        await db.projects.update_one(
            {"_id": project_id},
            {"$set": update_data}
        )
        
    updated_project_data = await db.projects.find_one({"_id": project_id})
    return Project(**updated_project_data)

@router.get("/{project_id}/branches", response_model=List[str], summary="List project branches")
async def read_project_branches(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get all unique branches for a project.
    """
    await check_project_access(project_id, current_user, db, required_role="viewer")
    
    branches = await db.scans.distinct("branch", {"project_id": project_id})
    return sorted(branches)

@router.get("/{project_id}/scans", response_model=List[Scan], summary="List project scans")
async def read_project_scans(
    project_id: str,
    skip: int = 0,
    limit: int = 20,
    branch: str = None,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get scans for a project.
    """
    await check_project_access(project_id, current_user, db, required_role="viewer")
    
    query = {"project_id": project_id}
    if branch:
        query["branch"] = branch

    scans = await db.scans.find(
        query
    ).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    return scans

@router.put("/{project_id}/notifications", response_model=Project, summary="Update notification settings")
async def update_notification_settings(
    project_id: str,
    settings: ProjectNotificationSettings,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Update notification preferences for the current user in this project.
    """
    project = await check_project_access(project_id, current_user, db)
    
    is_owner = project.owner_id == str(current_user.id)
    
    if is_owner:
        await db.projects.update_one(
            {"_id": project_id},
            {"$set": {"owner_notification_preferences": settings.notification_preferences}}
        )
    else:
        # Check if member
        member_found = False
        for i, member in enumerate(project.members):
            if member.user_id == str(current_user.id):
                # Update specific member in the array
                await db.projects.update_one(
                    {"_id": project_id, "members.user_id": str(current_user.id)},
                    {"$set": {f"members.{i}.notification_preferences": settings.notification_preferences}}
                )
                member_found = True
                break
        
        if not member_found:
             # Occurs if superuser is not a member
             if "*" in current_user.permissions:
                 # Superusers must be members to set preferences.
                 raise HTTPException(status_code=400, detail="You must be a member or owner to set notification preferences")
             else:
                 raise HTTPException(status_code=403, detail="Not a member of this project")

    # Return updated project
    updated_project_data = await db.projects.find_one({"_id": project_id})
    return Project(**updated_project_data)

@router.post("/{project_id}/invite", response_model=ProjectInvitation, summary="Invite a user to project")
async def invite_user(
    project_id: str,
    invite_in: ProjectMemberInvite,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Invite a user to the project.
    
    If the user already exists, they are added immediately.
    Otherwise, an invitation record is created (email sending to be implemented).
    """
    project = await check_project_access(project_id, current_user, db, required_role="admin")
    
    # Check if user already exists
    existing_user = await db.users.find_one({"email": invite_in.email})
    if existing_user:
        # If user exists, add directly to project
        member = ProjectMember(user_id=str(existing_user["_id"]), role=invite_in.role)
        
        # Check if already member
        for m in project.members:
            if m.user_id == member.user_id:
                raise HTTPException(status_code=400, detail="User already a member")
                
        await db.projects.update_one(
            {"_id": project_id},
            {"$push": {"members": member.dict()}}
        )
        return ProjectInvitation(
            project_id=project_id,
            email=invite_in.email,
            role=invite_in.role,
            token="auto-added",
            invited_by=str(current_user.id),
            expires_at=datetime.utcnow()
        )
    else:
        # Create invitation record
        token = secrets.token_urlsafe(32)
        invitation = ProjectInvitation(
            project_id=project_id,
            email=invite_in.email,
            role=invite_in.role,
            token=token,
            invited_by=str(current_user.id),
            expires_at=datetime.utcnow() + timedelta(days=7)
        )
        await db.invitations.insert_one(invitation.dict(by_alias=True))
        # In a real app, send email here
        return invitation

@router.get("/{project_id}/scans", response_model=List[Scan], summary="List project scans")
async def read_scans(
    project_id: str,
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get all scans for a project.
    """
    await check_project_access(project_id, current_user, db)
    # Exclude large SBOM fields for list view
    scans = await db.scans.find(
        {"project_id": project_id},
        {"sboms": 0}
    ).skip(skip).limit(limit).to_list(limit)
    return scans

@router.get("/scans/{scan_id}/results", response_model=List[AnalysisResult], summary="Get analysis results")
async def read_analysis_results(
    scan_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get the results of all analyzers for a specific scan.
    Also includes results from other scans on the same commit to provide a complete view.
    """
    # Need to find project_id from scan to check permissions
    # Projection to avoid fetching large SBOMs
    scan = await db.scans.find_one(
        {"_id": scan_id},
        {"project_id": 1, "commit_hash": 1}
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    await check_project_access(scan["project_id"], current_user, db)
    
    # Find all scans for this commit to aggregate results
    # This ensures that if scanners ran in different jobs (creating different scan entries),
    # we still see all results for this commit.
    related_scans_cursor = db.scans.find({
        "project_id": scan["project_id"],
        "commit_hash": scan["commit_hash"]
    }, {"_id": 1})
    related_scan_ids = [s["_id"] async for s in related_scans_cursor]
    
    if not related_scan_ids:
        related_scan_ids = [scan_id]
    
    results = await db.analysis_results.find({"scan_id": {"$in": related_scan_ids}}).to_list(1000)
    
    # Group results by analyzer_name
    grouped_results = {}
    for res in results:
        name = res["analyzer_name"]
        grouped_results.setdefault(name, []).append(res)
    
    final_results = []
    
    for name, group in grouped_results.items():
        # 1. Prefer results from the requested scan_id
        current_scan_results = [r for r in group if r["scan_id"] == scan_id]
        
        if current_scan_results:
            # If we have multiple results for the same analyzer in the same scan,
            # it means we processed multiple SBOMs. We should merge them for the "Raw Data" view.
            base_result = current_scan_results[0]
            
            if len(current_scan_results) > 1:
                for other in current_scan_results[1:]:
                    # Merge logic based on analyzer type
                    if name == "trivy":
                        if "Results" in other["result"] and isinstance(other["result"]["Results"], list):
                            if "Results" not in base_result["result"]:
                                base_result["result"]["Results"] = []
                            base_result["result"]["Results"].extend(other["result"]["Results"])
                            
                    elif name == "grype":
                        if "matches" in other["result"] and isinstance(other["result"]["matches"], list):
                            if "matches" not in base_result["result"]:
                                base_result["result"]["matches"] = []
                            base_result["result"]["matches"].extend(other["result"]["matches"])
                            
                    elif name == "osv":
                        if "results" in other["result"] and isinstance(other["result"]["results"], list):
                            if "results" not in base_result["result"]:
                                base_result["result"]["results"] = []
                            base_result["result"]["results"].extend(other["result"]["results"])
            
            final_results.append(base_result)
        else:
            # 2. Fallback to newest result from related scans
            if group:
                newest = max(group, key=lambda x: x["created_at"])
                final_results.append(newest)
            
    return final_results

@router.get("/scans/{scan_id}", response_model=Scan, summary="Get scan details")
async def read_scan(
    scan_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get details of a specific scan.
    """
    scan_data = await db.scans.find_one({"_id": scan_id})
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    await check_project_access(scan_data["project_id"], current_user, db)
    
    # Resolve GridFS references in sboms
    # Note: For performance, we might want to make this optional or separate endpoint
    if "sboms" in scan_data:
        resolved_sboms = []
        fs = AsyncIOMotorGridFSBucket(db)
        for item in scan_data["sboms"]:
            if isinstance(item, dict) and item.get("type") == "gridfs_reference":
                try:
                    gridfs_id = item.get("gridfs_id")
                    stream = await fs.open_download_stream(ObjectId(gridfs_id))
                    content = await stream.read()
                    resolved_sboms.append(json.loads(content))
                except Exception:
                    resolved_sboms.append(item)
            else:
                resolved_sboms.append(item)
        scan_data["sboms"] = resolved_sboms

    # Fetch findings from separate collection (Point B)
    # We only fetch if findings_summary is missing (new architecture)
    # OPTIMIZATION: Do NOT fetch findings here. Use /scans/{scan_id}/findings endpoint.
    # if "findings_summary" not in scan_data or not scan_data["findings_summary"]:
    #    findings_cursor = db.findings.find({"scan_id": scan_id})
    #    findings = await findings_cursor.to_list(None)
    #    
    #    mapped_findings = []
    #    for f in findings:
    #        # Map logical ID back to 'id' for the API response
    #        f["id"] = f.get("finding_id", f.get("_id")) 
    #        mapped_findings.append(f)
    #        
    #    scan_data["findings_summary"] = mapped_findings

    return scan_data

@router.get("/scans/{scan_id}/findings", response_model=Dict[str, Any], summary="Get scan findings with pagination")
async def read_scan_findings(
    scan_id: str,
    skip: int = 0,
    limit: int = 50,
    sort_by: str = "severity", # severity, type, component
    sort_order: str = "desc", # asc, desc
    type: str = None,
    category: str = None, # security, secret, sast, compliance, quality
    severity: str = None,
    search: str = None,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get paginated findings for a scan.
    """
    # Check access
    scan = await db.scans.find_one({"_id": scan_id}, {"project_id": 1})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await check_project_access(scan["project_id"], current_user, db)

    query = {"scan_id": scan_id}
    
    if type:
        query["type"] = type
        
    if category:
        if category == "security":
            query["type"] = {"$in": ["vulnerability", "malware", "typosquatting"]}
        elif category == "secret":
            query["type"] = "secret"
        elif category == "sast":
            query["type"] = {"$in": ["sast", "iac"]}
        elif category == "compliance":
            query["type"] = {"$in": ["license", "eol"]}
        elif category == "quality":
            query["type"] = {"$in": ["outdated", "quality"]}
            
    if severity:
        query["severity"] = severity.upper()
    if search:
        query["$or"] = [
            {"component": {"$regex": search, "$options": "i"}},
            {"finding_id": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}}
        ]

    # Severity Ranking for sorting
    pipeline = [
        {"$match": query},
        {"$addFields": {
            "severity_rank": {
                "$switch": {
                    "branches": [
                        {"case": {"$eq": ["$severity", "CRITICAL"]}, "then": 5},
                        {"case": {"$eq": ["$severity", "HIGH"]}, "then": 4},
                        {"case": {"$eq": ["$severity", "MEDIUM"]}, "then": 3},
                        {"case": {"$eq": ["$severity", "LOW"]}, "then": 2},
                        {"case": {"$eq": ["$severity", "INFO"]}, "then": 1}
                    ],
                    "default": 0
                }
            },
            # Map finding_id to id for frontend compatibility
            "id": "$finding_id"
        }}
    ]

    # Sorting
    sort_dir = -1 if sort_order == "desc" else 1
    if sort_by == "severity":
        pipeline.append({"$sort": {"severity_rank": sort_dir, "component": 1}})
    else:
        pipeline.append({"$sort": {sort_by: sort_dir}})

    # Pagination
    pipeline.append({"$facet": {
        "metadata": [{"$count": "total"}],
        "data": [{"$skip": skip}, {"$limit": limit}]
    }})

    result = await db.findings.aggregate(pipeline).to_list(1)
    
    data = result[0]["data"]
    metadata = result[0]["metadata"]
    total = metadata[0]["total"] if metadata else 0

    return {
        "items": data,
        "total": total,
        "page": (skip // limit) + 1,
        "size": limit,
        "pages": (total + limit - 1) // limit if limit > 0 else 0
    }

    return Scan(**scan_data)

@router.put("/{project_id}/members/{user_id}", response_model=Project, summary="Update project member role")
async def update_project_member(
    project_id: str,
    user_id: str,
    member_in: ProjectMemberUpdate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Update the role of a project member.
    Requires 'admin' role on the project.
    """
    project = await check_project_access(project_id, current_user, db, required_role="admin")
    
    # Check if target user is a member
    member_index = -1
    for i, member in enumerate(project.members):
        if member.user_id == user_id:
            member_index = i
            break
            
    if member_index == -1:
        raise HTTPException(status_code=404, detail="User is not a member of this project")
        
    # Prevent changing owner's role via this endpoint (though owner is not in members list usually, but just in case)
    if project.owner_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot change role of project owner")

    update_fields = {}
    if member_in.role:
        update_fields[f"members.{member_index}.role"] = member_in.role
    if member_in.notification_preferences:
        update_fields[f"members.{member_index}.notification_preferences"] = member_in.notification_preferences

    if update_fields:
        await db.projects.update_one(
            {"_id": project_id, "members.user_id": user_id},
            {"$set": update_fields}
        )
    
    updated_project_data = await db.projects.find_one({"_id": project_id})
    return Project(**updated_project_data)

@router.delete("/{project_id}/members/{user_id}", response_model=Project, summary="Remove user from project")
async def remove_project_member(
    project_id: str,
    user_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Remove a user from the project.
    Requires 'admin' role on the project.
    """
    project = await check_project_access(project_id, current_user, db, required_role="admin")
    
    # Check if target user is a member
    member_exists = False
    for member in project.members:
        if member.user_id == user_id:
            member_exists = True
            break
            
    if not member_exists:
        raise HTTPException(status_code=404, detail="User is not a member of this project")
        
    if project.owner_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot remove project owner")

    await db.projects.update_one(
        {"_id": project_id},
        {"$pull": {"members": {"user_id": user_id}}}
    )
    
    updated_project_data = await db.projects.find_one({"_id": project_id})
    return Project(**updated_project_data)

@router.get("/{project_id}/export/csv", summary="Export latest scan results as CSV")
async def export_project_csv(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    await check_project_access(project_id, current_user, db, required_role="viewer")
    
    # Get latest scan
    scan_data = await db.scans.find_one(
        {"project_id": project_id, "status": "completed"},
        sort=[("created_at", -1)]
    )
    
    if not scan_data:
        raise HTTPException(status_code=404, detail="No completed scans found for this project")
        
    scan = Scan(**scan_data)
    
    # Prepare CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["Component", "Version", "Type", "Vulnerability ID", "Severity", "Description", "Fixed Version"])
    
    # Iterate findings
    # Assuming findings_summary structure. Adjust based on actual data.
    if scan.findings_summary:
        for finding in scan.findings_summary:
            writer.writerow([
                finding.get("pkg_name", ""),
                finding.get("installed_version", ""),
                finding.get("pkg_type", ""),
                finding.get("vulnerability_id", ""),
                finding.get("severity", ""),
                finding.get("description", ""),
                finding.get("fixed_version", "")
            ])
            
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=project_{project_id}_scan.csv"}
    )

@router.get("/{project_id}/export/sbom", summary="Export latest SBOM")
async def export_project_sbom(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    await check_project_access(project_id, current_user, db, required_role="viewer")
    
    scan_data = await db.scans.find_one(
        {"project_id": project_id, "status": "completed"},
        sort=[("created_at", -1)]
    )
    
    if not scan_data:
        raise HTTPException(status_code=404, detail="No completed scans found for this project")
        
    scan = Scan(**scan_data)
    
    return Response(
        content=json.dumps(scan.sbom, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=project_{project_id}_sbom.json"}
    )

@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Delete a project and all associated data (scans, results).
    Requires 'project:delete' permission or being the project owner.
    """
    project = await check_project_access(project_id, current_user, db, required_role="admin")
    
    # Additional check: Only global admin or project owner can delete
    is_global_admin = "*" in current_user.permissions or "project:delete" in current_user.permissions
    is_owner = project.owner_id == str(current_user.id)
    
    if not (is_global_admin or is_owner):
         raise HTTPException(status_code=403, detail="Only project owner or administrator can delete a project")

    # 1. Find all scans
    cursor = db.scans.find({"project_id": project_id}, {"_id": 1})
    scan_ids = [doc["_id"] async for doc in cursor]
    
    # 2. Delete analysis results for these scans
    if scan_ids:
        await db.analysis_results.delete_many({"scan_id": {"$in": scan_ids}})
        
    # 3. Delete scans
    await db.scans.delete_many({"project_id": project_id})
    
    # 4. Delete project
    await db.projects.delete_one({"_id": project_id})
    
    return None
