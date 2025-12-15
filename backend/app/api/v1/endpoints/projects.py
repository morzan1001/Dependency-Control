from fastapi import APIRouter, Depends, HTTPException, status, Response
from typing import List, Dict, Any
from motor.motor_asyncio import AsyncIOMotorDatabase
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
from app.schemas.project import ProjectCreate, ProjectUpdate, ProjectMemberInvite, ProjectNotificationSettings, ProjectApiKeyResponse, ProjectMemberUpdate
from app.db.mongodb import get_database
from pydantic import BaseModel

router = APIRouter()

class RecentScan(Scan):
    project_name: str

async def enrich_project_details(project: Project, db: AsyncIOMotorDatabase):
    # 1. Get all direct member user IDs
    user_ids = [m.user_id for m in project.members]
    
    # 2. If project has a team, get team members
    team_members_map = {}
    if project.team_id:
        team = await db.teams.find_one({"_id": project.team_id})
        if team:
            for tm in team.get("members", []):
                # Map team role to project role
                # owner/admin -> admin, member -> viewer
                role = "admin" if tm.get("role") in ["admin", "owner"] else "viewer"
                
                team_members_map[tm["user_id"]] = {
                    "user_id": tm["user_id"],
                    "role": role,
                    "inherited_from": f"Team: {team.get('name', 'Unknown')}"
                }
                if tm["user_id"] not in user_ids:
                    user_ids.append(tm["user_id"])

    # 3. Fetch all users
    users = await db.users.find({"_id": {"$in": user_ids}}).to_list(None)
    user_map = {u["_id"]: u["username"] for u in users}

    # 4. Enrich direct members
    for m in project.members:
        m.username = user_map.get(m.user_id)

    # 5. Add team-only members to the list
    existing_member_ids = set(m.user_id for m in project.members)
    
    for uid, tm_data in team_members_map.items():
        if uid not in existing_member_ids:
            pm = ProjectMember(
                user_id=uid,
                role=tm_data["role"],
                username=user_map.get(uid),
                inherited_from=tm_data["inherited_from"]
            )
            project.members.append(pm)
            
    return project

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
    is_team_member = False
    if project.team_id:
        team = await db.teams.find_one({"_id": project.team_id, "members.user_id": str(user.id)})
        if team:
            is_team_member = True
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

    projects_cursor = db.projects.find(query)
    projects = await projects_cursor.to_list(None)
    
    total_projects = len(projects)
    total_critical = 0
    total_high = 0
    total_risk_score = 0.0
    
    risky_projects = []

    for p in projects:
        stats = p.get("stats", {}) or {}
        crit = stats.get("critical", 0)
        high = stats.get("high", 0)
        
        total_critical += crit
        total_high += high
        
        risk = stats.get("risk_score")
        if risk is None:
            # Fallback calculation
            risk = (crit * 10) + (high * 7.5) + (stats.get("medium", 0) * 4) + (stats.get("low", 0) * 1)
        
        total_risk_score += risk
        
        risky_projects.append({
            "name": p.get("name"),
            "risk": risk,
            "id": p.get("_id")
        })

    avg_risk = 0.0
    if total_projects > 0:
        avg_risk = round(total_risk_score / total_projects, 1)
        
    # Sort by risk desc
    risky_projects.sort(key=lambda x: x["risk"], reverse=True)
    
    return {
        "total_projects": total_projects,
        "total_critical": total_critical,
        "total_high": total_high,
        "avg_risk_score": avg_risk,
        "top_risky_projects": risky_projects[:5]
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
        project = Project(**project_data)
    else:
        project = await check_project_access(project_id, current_user, db, required_role="admin")
    
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

@router.get("/", response_model=List[Project], summary="List all projects")
async def read_projects(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Retrieve projects.
    
    - **Superusers** see all projects.
    - **Regular users** see projects they own or are members of.
    """
    if "*" in current_user.permissions or "project:read_all" in current_user.permissions:
        projects = await db.projects.find().to_list(1000)
    elif "project:read" in current_user.permissions:
        # Get teams user is member of
        user_teams = await db.teams.find({"members.user_id": str(current_user.id)}).to_list(1000)
        team_ids = [t["_id"] for t in user_teams]

        # Find projects where user is owner OR is in members list OR project belongs to one of user's teams
        projects = await db.projects.find({
            "$or": [
                {"owner_id": str(current_user.id)},
                {"members.user_id": str(current_user.id)},
                {"team_id": {"$in": team_ids}}
            ]
        }).to_list(1000)
    else:
        raise HTTPException(status_code=403, detail="Not enough permissions")
        
    return projects

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
    scans = await db.scans.find(
        {"project_id": {"$in": project_ids}}
    ).sort("created_at", -1).limit(limit).to_list(limit)

    # 3. Enrich with project name
    result = []
    for scan_data in scans:
        scan = Scan(**scan_data)
        # Create RecentScan object
        recent_scan = RecentScan(
            **scan.dict(by_alias=True),
            project_name=project_map.get(scan.project_id, "Unknown Project")
        )
        result.append(recent_scan)
        
    return result

@router.get("/{project_id}", response_model=Project, summary="Get project details")
async def read_project(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get a specific project by ID.
    """
    project = await check_project_access(project_id, current_user, db)
    await enrich_project_details(project, db)
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
    scans = await db.scans.find({"project_id": project_id}).skip(skip).limit(limit).to_list(limit)
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
    scan = await db.scans.find_one({"_id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    await check_project_access(scan["project_id"], current_user, db)
    
    # Find all scans for this commit to aggregate results
    # This ensures that if scanners ran in different jobs (creating different scan entries),
    # we still see all results for this commit.
    related_scans_cursor = db.scans.find({
        "project_id": scan["project_id"],
        "commit_hash": scan["commit_hash"]
    })
    related_scan_ids = [s["_id"] async for s in related_scans_cursor]
    
    if not related_scan_ids:
        related_scan_ids = [scan_id]
    
    results = await db.analysis_results.find({"scan_id": {"$in": related_scan_ids}}).to_list(1000)
    
    # Deduplicate results by analyzer_name (preferring the one from the requested scan_id, or latest)
    # Since we might have multiple runs for the same commit.
    unique_results = {}
    for res in results:
        name = res["analyzer_name"]
        # If we already have a result for this analyzer
        if name in unique_results:
            existing = unique_results[name]
            # If the current res is from the requested scan_id, prioritize it
            if res["scan_id"] == scan_id:
                unique_results[name] = res
            # Else if existing is NOT from requested scan_id, and res is newer, take res
            elif existing["scan_id"] != scan_id and res["created_at"] > existing["created_at"]:
                unique_results[name] = res
        else:
            unique_results[name] = res
            
    return list(unique_results.values())

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
