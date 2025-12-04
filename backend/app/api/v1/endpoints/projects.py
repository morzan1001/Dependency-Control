from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from motor.motor_asyncio import AsyncIOMotorDatabase
import secrets
from datetime import datetime, timedelta

from app.api import deps
from app.core import security
from app.models.project import Project, Scan, AnalysisResult, ProjectMember
from app.models.user import User
from app.models.invitation import ProjectInvitation
from app.schemas.project import ProjectCreate, ProjectUpdate, ProjectMemberInvite, ProjectNotificationSettings, ProjectApiKeyResponse, ProjectMemberUpdate
from app.db.mongodb import get_database

router = APIRouter()

async def check_project_access(project_id: str, user: User, db: AsyncIOMotorDatabase, required_role: str = None) -> Project:
    project_data = await db.projects.find_one({"_id": project_id})
    if not project_data:
        raise HTTPException(status_code=404, detail="Project not found")
    
    project = Project(**project_data)
    
    is_owner = project.owner_id == str(user.id)
    is_member = False
    member_role = None
    
    for member in project.members:
        if member.user_id == str(user.id):
            is_member = True
            member_role = member.role
            break
            
    if "*" in user.permissions:
        return project

    # Check team membership if project belongs to a team
    is_team_member = False
    if project.team_id:
        team = await db.teams.find_one({"_id": project.team_id, "members.user_id": str(user.id)})
        if team:
            is_team_member = True
            # Determine role from team membership? 
            # For simplicity, team members get 'viewer' access by default, 
            # team admins/owners get 'admin' access on project?
            # Let's say team members are viewers, team admins are admins.
            for tm in team["members"]:
                if tm["user_id"] == str(user.id):
                    if tm["role"] in ["admin", "owner"]:
                        member_role = "admin"
                    else:
                        member_role = "viewer" # Default for team member
                    break
            is_member = True # Treat as member for access check

    if not (is_owner or is_member):
        raise HTTPException(status_code=403, detail="Not enough permissions")

    if required_role:
        if is_owner:
            return project
        # Simple role hierarchy: admin > editor > viewer
        roles = ["viewer", "editor", "admin"]
        # If member_role is None (shouldn't happen if is_member is True), default to viewer
        current_role = member_role or "viewer"
        if roles.index(current_role) < roles.index(required_role):
             raise HTTPException(status_code=403, detail="Not enough permissions")
             
    return project

@router.post("/", response_model=ProjectApiKeyResponse, summary="Create a new project", status_code=201)
async def create_project(
    project_in: ProjectCreate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Create a new project and return the initial API Key.
    
    **Important**: The API Key is only returned once. Save it securely.
    """
    # Check if user has permission to create projects (optional, based on requirements)
    # if "project:create" not in current_user.permissions and not current_user.is_superuser:
    #     raise HTTPException(status_code=403, detail="Not allowed to create projects")

    # If team_id is provided, check if user is member of that team
    if project_in.team_id:
        team = await db.teams.find_one({"_id": project_in.team_id, "members.user_id": str(current_user.id)})
        if not team:
             raise HTTPException(status_code=403, detail="You are not a member of the specified team")

    # Generate API Key
    # Format: project_id.secret
    # We need the project ID first.
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
        active_analyzers=project_in.active_analyzers
    )
    
    await db.projects.insert_one(project.dict(by_alias=True))
    
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
    if "*" in current_user.permissions:
        projects = await db.projects.find().to_list(1000)
    else:
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
    return projects

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
    project = await check_project_access(project_id, current_user, db, required_role="admin")
    
    update_data = {k: v for k, v in project_in.dict(exclude_unset=True).items()}
    
    if update_data:
        await db.projects.update_one(
            {"_id": project_id},
            {"$set": update_data}
        )
        
    updated_project_data = await db.projects.find_one({"_id": project_id})
    return Project(**updated_project_data)

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
             # Should not happen if check_project_access passed, unless superuser who is not a member
             if "*" in current_user.permissions:
                 # Superuser can't set preferences if they are not a member/owner?
                 # Or maybe we should add them as member?
                 # For now, let's just say 400
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
        # If user exists, add directly to project? Or still send invite?
        # For simplicity, let's add them directly if they exist
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
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get all scans for a project.
    """
    await check_project_access(project_id, current_user, db)
    scans = await db.scans.find({"project_id": project_id}).to_list(100)
    return scans

@router.get("/scans/{scan_id}/results", response_model=List[AnalysisResult], summary="Get analysis results")
async def read_analysis_results(
    scan_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get the results of all analyzers for a specific scan.
    """
    # Need to find project_id from scan to check permissions
    scan = await db.scans.find_one({"_id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    await check_project_access(scan["project_id"], current_user, db)
    
    results = await db.analysis_results.find({"scan_id": scan_id}).to_list(100)
    return results

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

    await db.projects.update_one(
        {"_id": project_id, "members.user_id": user_id},
        {"$set": {f"members.{member_index}.role": member_in.role}}
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
