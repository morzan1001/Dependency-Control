import csv
import io
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Response, status
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket
from pydantic import BaseModel

from app.api import deps
from app.core import security
from app.core.constants import (
    PROJECT_ROLE_ADMIN,
    PROJECT_ROLE_VIEWER,
    PROJECT_ROLES,
    TEAM_ROLE_ADMIN,
    TEAM_ROLE_OWNER,
)
from app.core.worker import worker_manager
from app.db.mongodb import get_database
from app.models.invitation import ProjectInvitation
from app.models.project import AnalysisResult, Project, ProjectMember, Scan
from app.models.system import SystemSettings
from app.models.user import User
from app.schemas.project import (
    ProjectApiKeyResponse,
    ProjectCreate,
    ProjectList,
    ProjectMemberInvite,
    ProjectMemberUpdate,
    ProjectNotificationSettings,
    ProjectUpdate,
)

router = APIRouter()


class RecentScan(Scan):
    project_name: str


async def check_project_access(
    project_id: str,
    user: User,
    db: AsyncIOMotorDatabase,
    required_role: Optional[str] = None,
) -> Project:
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
        team = await db.teams.find_one(
            {"_id": project.team_id, "members.user_id": str(user.id)}
        )
        if team:
            # Team members get 'viewer' access by default,
            # Team admins/owners get 'admin' access on project.
            for tm in team["members"]:
                if tm["user_id"] == str(user.id):
                    if tm["role"] in [TEAM_ROLE_ADMIN, TEAM_ROLE_OWNER]:
                        member_role = PROJECT_ROLE_ADMIN
                    else:
                        member_role = PROJECT_ROLE_VIEWER
                    break
            is_member = True

    if not (is_owner or is_member):
        raise HTTPException(status_code=403, detail="Not enough permissions")

    # Check for basic read permission
    if (
        "project:read" not in user.permissions
        and "project:read_all" not in user.permissions
    ):
        raise HTTPException(status_code=403, detail="Not enough permissions")

    if required_role:
        if is_owner:
            return project
        # Role hierarchy: admin > editor > viewer
        roles = PROJECT_ROLES
        # If member_role is None, default to viewer
        current_role = member_role or PROJECT_ROLE_VIEWER
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
    if (
        "*" not in current_user.permissions
        and "project:read_all" not in current_user.permissions
    ):
        # Find teams user is member of
        user_teams = await db.teams.find(
            {"members.user_id": str(current_user.id)}
        ).to_list(None)
        team_ids = [t["_id"] for t in user_teams]

        query = {
            "$or": [
                {"owner_id": str(current_user.id)},
                {"members.user_id": str(current_user.id)},
                {"team_id": {"$in": team_ids}},
            ]
        }

    # Use aggregation for performance instead of fetching all projects
    pipeline: List[Dict[str, Any]] = [
        {"$match": query},
        {
            "$project": {
                "name": 1,
                "stats": 1,
                # Calculate risk if missing (fallback logic)
                "calculated_risk": {
                    "$ifNull": [
                        "$stats.risk_score",
                        {
                            "$add": [
                                {
                                    "$multiply": [
                                        {"$ifNull": ["$stats.critical", 0]},
                                        10,
                                    ]
                                },
                                {"$multiply": [{"$ifNull": ["$stats.high", 0]}, 7.5]},
                                {"$multiply": [{"$ifNull": ["$stats.medium", 0]}, 4]},
                                {"$multiply": [{"$ifNull": ["$stats.low", 0]}, 1]},
                            ]
                        },
                    ]
                },
            }
        },
        {
            "$facet": {
                "totals": [
                    {
                        "$group": {
                            "_id": None,
                            "total_projects": {"$sum": 1},
                            "total_critical": {"$sum": "$stats.critical"},
                            "total_high": {"$sum": "$stats.high"},
                            "total_risk_score": {"$sum": "$calculated_risk"},
                        }
                    }
                ],
                "top_risky": [
                    {"$sort": {"calculated_risk": -1}},
                    {"$limit": 5},
                    {"$project": {"name": 1, "risk": "$calculated_risk", "id": "$_id"}},
                ],
            }
        },
    ]

    result = await db.projects.aggregate(pipeline).to_list(1)

    if not result:
        return {
            "total_projects": 0,
            "total_critical": 0,
            "total_high": 0,
            "avg_risk_score": 0.0,
            "top_risky_projects": [],
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
        "top_risky_projects": top_risky,
    }


@router.post(
    "/",
    response_model=ProjectApiKeyResponse,
    summary="Create a new project",
    status_code=201,
)
async def create_project(
    project_in: ProjectCreate,
    current_user: User = Depends(deps.PermissionChecker("project:create")),
    db: AsyncIOMotorDatabase = Depends(get_database),
    settings: SystemSettings = Depends(deps.get_system_settings),
):
    """
    Create a new project and return the initial API Key.

    **Important**: The API Key is only returned once. Save it securely.
    """
    # Check Project Limit
    if settings.project_limit_per_user > 0:
        # Admins are exempt from limits
        is_admin = "*" in current_user.permissions or "system:manage" in current_user.permissions
        
        if not is_admin:
            # Count projects owned by the user
            current_count = await db.projects.count_documents({"owner_id": str(current_user.id)})
            if current_count >= settings.project_limit_per_user:
                raise HTTPException(
                    status_code=403,
                    detail=f"Project limit reached. You can only create {settings.project_limit_per_user} projects.",
                )

    # If team_id is provided, check if user is member of that team
    if project_in.team_id:
        team = await db.teams.find_one(
            {"_id": project_in.team_id, "members.user_id": str(current_user.id)}
        )
        if not team:
            raise HTTPException(
                status_code=403, detail="You are not a member of the specified team"
            )

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
        retention_days=(
            project_in.retention_days if project_in.retention_days is not None else 90
        ),
        members=[ProjectMember(user_id=str(current_user.id), role="admin")],
    )

    # api_key_hash is excluded from dict() by default in the model, so we must add it manually
    project_data = project.dict(by_alias=True)
    project_data["api_key_hash"] = api_key_hash

    await db.projects.insert_one(project_data)

    return ProjectApiKeyResponse(project_id=project_id, api_key=api_key)


@router.post(
    "/{project_id}/rotate-key",
    response_model=ProjectApiKeyResponse,
    summary="Rotate Project API Key",
)
async def rotate_api_key(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
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
        {"_id": project_id}, {"$set": {"api_key_hash": api_key_hash}}
    )

    return ProjectApiKeyResponse(project_id=project_id, api_key=api_key)


@router.get("/", response_model=ProjectList, summary="List all projects")
async def read_projects(
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 20,
    sort_by: str = "created_at",
    sort_order: str = "desc",
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
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

    if (
        "*" not in current_user.permissions
        and "project:read_all" not in current_user.permissions
    ):
        if "project:read" not in current_user.permissions:
            raise HTTPException(status_code=403, detail="Not enough permissions")

        # Get teams user is member of
        user_teams = await db.teams.find(
            {"members.user_id": str(current_user.id)}
        ).to_list(None)
        team_ids = [t["_id"] for t in user_teams]

        # Find projects where user is owner OR is in members list OR project belongs to one of user's teams
        permission_query = {
            "$or": [
                {"owner_id": str(current_user.id)},
                {"members.user_id": str(current_user.id)},
                {"team_id": {"$in": team_ids}},
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
        "risk_score": "stats.risk_score",
    }

    sort_field = allowed_sort_fields.get(sort_by, "created_at")

    total = await db.projects.count_documents(final_query)
    cursor = (
        db.projects.find(final_query)
        .sort(sort_field, direction)
        .skip(skip)
        .limit(limit)
    )
    projects = await cursor.to_list(length=limit)

    return {
        "items": projects,
        "total": total,
        "page": (skip // limit) + 1 if limit > 0 else 1,
        "size": limit,
        "pages": (total + limit - 1) // limit if limit > 0 else 0,
    }





@router.get(
    "/scans",
    response_model=List[RecentScan],
    summary="List scans across all accessible projects",
)
async def read_all_scans(
    limit: int = 20,
    skip: int = 0,
    sort_by: str = "created_at",
    sort_order: str = "desc",
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Retrieve scans for all projects the user has access to.
    Supports pagination and sorting.
    """
    # 1. Get accessible project IDs
    if (
        "*" in current_user.permissions
        or "project:read_all" in current_user.permissions
    ):
        # Admin sees all
        project_cursor = db.projects.find({}, {"_id": 1, "name": 1})
    elif "project:read" in current_user.permissions:
        # Get teams user is member of
        user_teams = await db.teams.find(
            {"members.user_id": str(current_user.id)}
        ).to_list(1000)
        team_ids = [t["_id"] for t in user_teams]

        # Find projects where user is owner OR is in members list OR project belongs to one of user's teams
        project_cursor = db.projects.find(
            {
                "$or": [
                    {"owner_id": str(current_user.id)},
                    {"members.user_id": str(current_user.id)},
                    {"team_id": {"$in": team_ids}},
                ]
            },
            {"_id": 1, "name": 1},
        )
    else:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    projects = await project_cursor.to_list(10000)
    project_map: Dict[str, str] = {
        str(p["_id"]): str(p.get("name", "")) for p in projects
    }
    project_ids = list(project_map.keys())

    if not project_ids:
        return []

    # Determine sort direction
    direction = -1 if sort_order.lower() == "desc" else 1

    # Validate sort_by
    allowed_sort_fields = {
        "created_at": "created_at",
        "pipeline_iid": "pipeline_iid",
        "branch": "branch",
        "status": "status",
    }
    sort_field = allowed_sort_fields.get(sort_by, "created_at")

    # 2. Get recent scans for these projects
    pipeline: List[Dict[str, Any]] = [
        {"$match": {"project_id": {"$in": project_ids}}},
        {"$sort": {sort_field: direction}},
        {"$skip": skip},
        {"$limit": limit},
        {
            "$lookup": {
                "from": "projects",
                "localField": "project_id",
                "foreignField": "_id",
                "as": "project_info",
            }
        },
        {"$unwind": "$project_info"},
        {"$addFields": {"project_name": "$project_info.name"}},
        {"$project": {"project_info": 0, "sboms": 0, "findings_summary": 0}},
    ]

    scans = await db.scans.aggregate(pipeline).to_list(limit)
    return scans


@router.get("/{project_id}", response_model=Project, summary="Get project details")
async def read_project(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get a specific project by ID.
    """
    # Optimized fetch with aggregation to avoid N+1 queries
    pipeline: List[Dict[str, Any]] = [
        {"$match": {"_id": project_id}},
        # Lookup Team
        {
            "$lookup": {
                "from": "teams",
                "localField": "team_id",
                "foreignField": "_id",
                "as": "team_data",
            }
        },
        {"$unwind": {"path": "$team_data", "preserveNullAndEmptyArrays": True}},
        # Lookup Users (for project members)
        {
            "$lookup": {
                "from": "users",
                "let": {"member_ids": "$members.user_id"},
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {"$in": [{"$toString": "$_id"}, "$$member_ids"]}
                        }
                    },
                    {"$project": {"_id": 1, "username": 1}},
                ],
                "as": "project_users",
            }
        },
        # Lookup Users (for team members)
        {
            "$lookup": {
                "from": "users",
                "let": {
                    "team_member_ids": {"$ifNull": ["$team_data.members.user_id", []]}
                },
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {
                                "$in": [{"$toString": "$_id"}, "$$team_member_ids"]
                            }
                        }
                    },
                    {"$project": {"_id": 1, "username": 1}},
                ],
                "as": "team_users",
            }
        },
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
                data["members"].append(
                    {
                        "user_id": uid,
                        "role": role,
                        "username": t_users.get(uid),
                        "inherited_from": f"Team: {team_data.get('name')}",
                    }
                )

    # Construct Project object
    # We need to remove aux fields that are not in Project model
    data.pop("team_data", None)
    data.pop("project_users", None)
    data.pop("team_users", None)

    project = Project(**data)

    # Verify Access (Logic from check_project_access but using loaded data)
    if (
        "*" in current_user.permissions
        or "project:read_all" in current_user.permissions
    ):
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
    db: AsyncIOMotorDatabase = Depends(get_database),
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
        project = await check_project_access(
            project_id, current_user, db, required_role="admin"
        )

    # If transferring to a team, verify membership
    if project_in.team_id and project_in.team_id != project.team_id:
        # Check if user is member of the new team
        # Exception: Superusers can transfer to any team
        if (
            "*" not in current_user.permissions
            and "project:update" not in current_user.permissions
        ):
            team = await db.teams.find_one(
                {"_id": project_in.team_id, "members.user_id": str(current_user.id)}
            )
            if not team:
                raise HTTPException(
                    status_code=403, detail="You are not a member of the target team"
                )

    update_data = {k: v for k, v in project_in.dict(exclude_unset=True).items()}

    # Check system settings for global enforcement
    system_settings = await db.system_settings.find_one({"_id": "current"})
    if system_settings:
        # Retention enforcement
        if system_settings.get("retention_mode") == "global":
            if "retention_days" in update_data:
                del update_data["retention_days"]

        # Rescan enforcement
        if system_settings.get("rescan_mode") == "global":
            if "rescan_enabled" in update_data:
                del update_data["rescan_enabled"]
            if "rescan_interval" in update_data:
                del update_data["rescan_interval"]

    if update_data:
        await db.projects.update_one({"_id": project_id}, {"$set": update_data})

    updated_project_data = await db.projects.find_one({"_id": project_id})
    if updated_project_data:
        return Project(**updated_project_data)
    raise HTTPException(status_code=404, detail="Project not found")


@router.get(
    "/{project_id}/branches", response_model=List[str], summary="List project branches"
)
async def read_project_branches(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get all unique branches for a project.
    """
    await check_project_access(project_id, current_user, db, required_role="viewer")

    branches = await db.scans.distinct("branch", {"project_id": project_id})
    return sorted(branches)


@router.get(
    "/{project_id}/scans", response_model=List[Scan], summary="List project scans"
)
async def read_project_scans(
    project_id: str,
    skip: int = 0,
    limit: int = 20,
    branch: Optional[str] = None,
    exclude_rescans: bool = False,
    sort_by: str = "created_at",
    sort_order: str = "desc",
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get scans for a project.
    """
    await check_project_access(project_id, current_user, db, required_role="viewer")

    query = {"project_id": project_id}
    if branch:
        query["branch"] = branch

    if exclude_rescans:
        query["is_rescan"] = {"$ne": True}

    # Determine sort direction
    direction = -1 if sort_order.lower() == "desc" else 1

    # Validate sort_by
    allowed_sort_fields = {
        "created_at": "created_at",
        "pipeline_iid": "pipeline_iid",
        "branch": "branch",
        "findings_count": "findings_count",
        "status": "status",
    }
    sort_field = allowed_sort_fields.get(sort_by, "created_at")

    scans = (
        await db.scans.find(query)
        .sort(sort_field, direction)
        .skip(skip)
        .limit(limit)
        .to_list(limit)
    )

    return scans


@router.post(
    "/{project_id}/scans/{scan_id}/rescan",
    response_model=Scan,
    summary="Trigger a manual re-scan",
)
async def trigger_rescan(
    project_id: str,
    scan_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Manually trigger a re-scan for a specific scan.
    This creates a new scan entry with the same SBOMs but runs the analysis again.
    """
    # Check permissions (Editor or Admin required)
    await check_project_access(project_id, current_user, db, required_role="editor")

    # Find the scan
    scan = await db.scans.find_one({"_id": scan_id, "project_id": project_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Ensure scan has SBOMs
    if not scan.get("sbom_refs"):
        raise HTTPException(
            status_code=400, detail="Cannot re-scan: No SBOMs found in the source scan."
        )

    # Determine original scan ID
    # If the source scan is already a re-scan, use its original_scan_id
    # If it's an original scan, use its ID
    original_scan_id = scan.get("original_scan_id") or scan_id

    # Create new scan document
    new_scan = Scan(
        project_id=project_id,
        branch=scan.get("branch", "unknown"),
        commit_hash=scan.get("commit_hash"),
        pipeline_id=None,  # Don't collide with ingest
        pipeline_iid=scan.get("pipeline_iid"),
        project_url=scan.get("project_url"),
        pipeline_url=scan.get("pipeline_url"),
        job_id=scan.get("job_id"),
        job_started_at=scan.get("job_started_at"),
        project_name=scan.get("project_name"),
        commit_message=scan.get("commit_message"),
        commit_tag=scan.get("commit_tag"),
        sbom_refs=scan.get("sbom_refs", []),
        status="pending",
        created_at=datetime.now(timezone.utc),
        is_rescan=True,
        original_scan_id=original_scan_id,
    )

    await db.scans.insert_one(new_scan.dict(by_alias=True))

    # Update original scan to point to this new pending rescan
    # We update 'latest_run' to pending so the UI shows the spinner,
    # but we DO NOT change the original scan's own status (it remains 'completed').
    await db.scans.update_one(
        {"_id": original_scan_id},
        {
            "$set": {
                "latest_rescan_id": new_scan.id,
                "latest_run": {
                    "scan_id": new_scan.id,
                    "status": "pending",
                    "created_at": datetime.now(timezone.utc),
                },
            }
        },
    )

    # Trigger analysis worker
    if worker_manager:
        await worker_manager.add_job(new_scan.id)
    else:
        # Should not happen in normal operation
        raise HTTPException(status_code=500, detail="Worker manager not available")

    return new_scan


@router.get(
    "/{project_id}/scans/{scan_id}/history",
    response_model=List[Scan],
    summary="Get scan history",
)
async def read_scan_history(
    project_id: str,
    scan_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get the history of a scan (including re-scans).
    Returns the original scan and all subsequent re-scans, sorted by date.
    """
    await check_project_access(project_id, current_user, db, required_role="viewer")

    # 1. Get the requested scan to find the root
    scan = await db.scans.find_one({"_id": scan_id, "project_id": project_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Determine the root ID
    root_id = scan.get("original_scan_id") or scan_id

    # 2. Find all scans that are either the root OR have this root as original_scan_id
    history = (
        await db.scans.find(
            {
                "project_id": project_id,
                "$or": [{"_id": root_id}, {"original_scan_id": root_id}],
            }
        )
        .sort("created_at", -1)
        .to_list(100)
    )

    return history


@router.put(
    "/{project_id}/notifications",
    response_model=Project,
    summary="Update notification settings",
)
async def update_notification_settings(
    project_id: str,
    settings: ProjectNotificationSettings,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Update notification preferences for the current user in this project.
    """
    project = await check_project_access(project_id, current_user, db)

    is_owner = project.owner_id == str(current_user.id)
    has_update_perm = (
        "project:update" in current_user.permissions or "*" in current_user.permissions
    )

    update_data = {}

    # Handle enforcement setting (Owner/Admin only)
    if settings.enforce_notification_settings is not None:
        if is_owner or has_update_perm:
            update_data["enforce_notification_settings"] = (
                settings.enforce_notification_settings
            )

    if is_owner:
        update_data["owner_notification_preferences"] = (
            settings.notification_preferences
        )
        await db.projects.update_one({"_id": project_id}, {"$set": update_data})
    else:
        # If settings are enforced, regular members cannot update their preferences
        if project.enforce_notification_settings and not has_update_perm:
            raise HTTPException(
                status_code=403,
                detail="Notification settings are enforced by the project owner",
            )

        # Check if member
        member_found = False
        for i, member in enumerate(project.members):
            if member.user_id == str(current_user.id):
                # Update specific member in the array
                # Note: If we are updating enforcement, we might be an admin who is also a member.
                # But typically enforcement is set by owner.
                # If we have update_data (enforcement), we should apply it to the project root.
                if update_data:
                    await db.projects.update_one(
                        {"_id": project_id}, {"$set": update_data}
                    )

                # Also update member preferences
                await db.projects.update_one(
                    {"_id": project_id, "members.user_id": str(current_user.id)},
                    {
                        "$set": {
                            f"members.{i}.notification_preferences": settings.notification_preferences
                        }
                    },
                )
                member_found = True
                break

        if not member_found:
            # Occurs if superuser is not a member
            if has_update_perm:
                # Just update the project settings (enforcement) if provided
                if update_data:
                    await db.projects.update_one(
                        {"_id": project_id}, {"$set": update_data}
                    )
            else:
                # Superusers must be members to set preferences.
                raise HTTPException(
                    status_code=400,
                    detail="You must be a member or owner to set notification preferences",
                )

    # Return updated project
    updated_project_data = await db.projects.find_one({"_id": project_id})
    if updated_project_data:
        return Project(**updated_project_data)
    raise HTTPException(status_code=404, detail="Project not found")


@router.post(
    "/{project_id}/invite",
    response_model=ProjectInvitation,
    summary="Invite a user to project",
)
async def invite_user(
    project_id: str,
    invite_in: ProjectMemberInvite,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Invite a user to the project.

    If the user already exists, they are added immediately.
    Otherwise, an invitation record is created (email sending to be implemented).
    """
    project = await check_project_access(
        project_id, current_user, db, required_role="admin"
    )

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
            {"_id": project_id}, {"$push": {"members": member.dict()}}
        )
        return ProjectInvitation(
            project_id=project_id,
            email=invite_in.email,
            role=invite_in.role,
            token="auto-added",
            invited_by=str(current_user.id),
            expires_at=datetime.now(timezone.utc),
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
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        await db.invitations.insert_one(invitation.dict(by_alias=True))
        # In a real app, send email here
        return invitation


@router.get(
    "/{project_id}/scans", response_model=List[Scan], summary="List project scans"
)
async def read_scans(
    project_id: str,
    skip: int = 0,
    limit: int = 100,
    sort_by: str = "created_at",
    sort_order: str = "desc",
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get all scans for a project.
    """
    await check_project_access(project_id, current_user, db)

    sort_direction = -1 if sort_order == "desc" else 1

    # Exclude large SBOM fields for list view
    scans = (
        await db.scans.find({"project_id": project_id}, {"sboms": 0})
        .sort(sort_by, sort_direction)
        .skip(skip)
        .limit(limit)
        .to_list(limit)
    )
    return scans


@router.get(
    "/scans/{scan_id}/results",
    response_model=List[AnalysisResult],
    summary="Get analysis results",
)
async def read_analysis_results(
    scan_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get the results of all analyzers for a specific scan.
    Also includes results from other scans on the same commit to provide a complete view.
    """
    # Need to find project_id from scan to check permissions
    # Projection to avoid fetching large SBOMs
    scan = await db.scans.find_one(
        {"_id": scan_id}, {"project_id": 1, "commit_hash": 1}
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await check_project_access(scan["project_id"], current_user, db)

    # Find all scans for this commit to aggregate results
    # This ensures that if scanners ran in different jobs (creating different scan entries),
    # we still see all results for this commit.
    related_scans_cursor = db.scans.find(
        {"project_id": scan["project_id"], "commit_hash": scan["commit_hash"]},
        {"_id": 1},
    )
    related_scan_ids = [s["_id"] async for s in related_scans_cursor]

    if not related_scan_ids:
        related_scan_ids = [scan_id]

    results = await db.analysis_results.find(
        {"scan_id": {"$in": related_scan_ids}}
    ).to_list(1000)

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
                        if "Results" in other["result"] and isinstance(
                            other["result"]["Results"], list
                        ):
                            if "Results" not in base_result["result"]:
                                base_result["result"]["Results"] = []
                            base_result["result"]["Results"].extend(
                                other["result"]["Results"]
                            )

                    elif name == "grype":
                        if "matches" in other["result"] and isinstance(
                            other["result"]["matches"], list
                        ):
                            if "matches" not in base_result["result"]:
                                base_result["result"]["matches"] = []
                            base_result["result"]["matches"].extend(
                                other["result"]["matches"]
                            )

                    elif name == "osv":
                        if "results" in other["result"] and isinstance(
                            other["result"]["results"], list
                        ):
                            if "results" not in base_result["result"]:
                                base_result["result"]["results"] = []
                            base_result["result"]["results"].extend(
                                other["result"]["results"]
                            )

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
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get details of a specific scan.
    Note: SBOMs are stored in GridFS and not returned here for performance reasons.
    Use /scans/{scan_id}/sboms endpoint to fetch raw SBOM data.
    """
    scan_data = await db.scans.find_one({"_id": scan_id})
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    await check_project_access(scan_data["project_id"], current_user, db)

    # Don't resolve GridFS references here - use /sboms endpoint for that
    # Just return sbom_refs metadata for reference

    return scan_data


@router.get(
    "/scans/{scan_id}/sboms",
    response_model=List[Dict[str, Any]],
    summary="Get raw SBOMs for a scan",
)
async def read_scan_sboms(
    scan_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get raw SBOM data for a specific scan.
    SBOMs are stored in GridFS and resolved on demand.
    Returns a list of SBOM objects with metadata.
    """
    scan_data = await db.scans.find_one({"_id": scan_id})
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    await check_project_access(scan_data["project_id"], current_user, db)

    # Check both sboms and sbom_refs for backward compatibility
    sbom_items = scan_data.get("sboms") or scan_data.get("sbom_refs") or []

    if not sbom_items:
        return []

    resolved_sboms = []
    fs = AsyncIOMotorGridFSBucket(db)

    for index, item in enumerate(sbom_items):
        if isinstance(item, dict) and item.get("type") == "gridfs_reference":
            try:
                gridfs_id = item.get("gridfs_id") or item.get("file_id")
                if gridfs_id:
                    stream = await fs.open_download_stream(ObjectId(gridfs_id))
                    content = await stream.read()
                    sbom_data = json.loads(content)
                    # Add metadata about the source
                    resolved_sboms.append(
                        {
                            "index": index,
                            "filename": item.get("filename"),
                            "storage": "gridfs",
                            "sbom": sbom_data,
                        }
                    )
            except Exception as e:
                # Return error info instead of failing completely
                resolved_sboms.append(
                    {
                        "index": index,
                        "filename": item.get("filename"),
                        "storage": "gridfs",
                        "error": f"Failed to load SBOM: {str(e)}",
                        "sbom": None,
                    }
                )
        elif isinstance(item, dict):
            # Already inline SBOM data (legacy format)
            resolved_sboms.append(
                {"index": index, "filename": None, "storage": "inline", "sbom": item}
            )

    return resolved_sboms


@router.get(
    "/scans/{scan_id}/findings",
    response_model=Dict[str, Any],
    summary="Get scan findings with pagination",
)
async def read_scan_findings(
    scan_id: str,
    skip: int = 0,
    limit: int = 50,
    sort_by: str = "severity",  # severity, type, component
    sort_order: str = "desc",  # asc, desc
    type: Optional[str] = None,
    category: Optional[str] = None,  # security, secret, sast, compliance, quality
    severity: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
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
            {"description": {"$regex": search, "$options": "i"}},
        ]

    # Severity Ranking for sorting
    pipeline: List[Dict[str, Any]] = [
        {"$match": query},
        # Lookup dependency info to get source details
        {
            "$lookup": {
                "from": "dependencies",
                "let": {
                    "scan_id": "$scan_id",
                    "component": "$component",
                    "version": "$version",
                },
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {
                                "$and": [
                                    {"$eq": ["$scan_id", "$$scan_id"]},
                                    {"$eq": ["$name", "$$component"]},
                                    {"$eq": ["$version", "$$version"]},
                                ]
                            }
                        }
                    },
                    {"$limit": 1},
                    {
                        "$project": {
                            "source_type": 1,
                            "source_target": 1,
                            "layer_digest": 1,
                            "found_by": 1,
                            "locations": 1,
                            "purl": 1,
                            "direct": 1,
                        }
                    },
                ],
                "as": "dependency_info",
            }
        },
        {
            "$addFields": {
                "severity_rank": {
                    "$switch": {
                        "branches": [
                            {"case": {"$eq": ["$severity", "CRITICAL"]}, "then": 5},
                            {"case": {"$eq": ["$severity", "HIGH"]}, "then": 4},
                            {"case": {"$eq": ["$severity", "MEDIUM"]}, "then": 3},
                            {"case": {"$eq": ["$severity", "LOW"]}, "then": 2},
                            {"case": {"$eq": ["$severity", "INFO"]}, "then": 1},
                        ],
                        "default": 0,
                    }
                },
                # Map finding_id to id for frontend compatibility
                "id": "$finding_id",
                # Flatten dependency info
                "source_type": {"$arrayElemAt": ["$dependency_info.source_type", 0]},
                "source_target": {
                    "$arrayElemAt": ["$dependency_info.source_target", 0]
                },
                "layer_digest": {"$arrayElemAt": ["$dependency_info.layer_digest", 0]},
                "found_by": {"$arrayElemAt": ["$dependency_info.found_by", 0]},
                "locations": {"$arrayElemAt": ["$dependency_info.locations", 0]},
                "purl": {"$arrayElemAt": ["$dependency_info.purl", 0]},
                "direct": {"$arrayElemAt": ["$dependency_info.direct", 0]},
            }
        },
        # Remove the temporary lookup array
        {"$project": {"dependency_info": 0}},
    ]

    # Sorting
    sort_dir = -1 if sort_order == "desc" else 1
    if sort_by == "severity":
        pipeline.append({"$sort": {"severity_rank": sort_dir, "component": 1}})
    else:
        pipeline.append({"$sort": {sort_by: sort_dir}})

    # Pagination
    pipeline.append(
        {
            "$facet": {
                "metadata": [{"$count": "total"}],
                "data": [{"$skip": skip}, {"$limit": limit}],
            }
        }
    )

    result = await db.findings.aggregate(pipeline).to_list(1)

    data = result[0]["data"]
    metadata = result[0]["metadata"]
    total = metadata[0]["total"] if metadata else 0

    return {
        "items": data,
        "total": total,
        "page": (skip // limit) + 1,
        "size": limit,
        "pages": (total + limit - 1) // limit if limit > 0 else 0,
    }


@router.get("/scans/{scan_id}/stats")
async def get_scan_stats(
    scan_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get finding statistics by category for a scan.
    """
    # Check access
    scan = await db.scans.find_one({"_id": scan_id}, {"project_id": 1})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await check_project_access(scan["project_id"], current_user, db)

    pipeline: List[Dict[str, Any]] = [
        {"$match": {"scan_id": scan_id}},
        {"$group": {"_id": "$type", "count": {"$sum": 1}}},
    ]

    results = await db.findings.aggregate(pipeline).to_list(None)

    stats = {
        "security": 0,
        "secret": 0,
        "sast": 0,
        "compliance": 0,
        "quality": 0,
        "other": 0,
    }

    for r in results:
        type_ = r["_id"]
        count = r["count"]

        if type_ in ["vulnerability", "malware", "typosquatting"]:
            stats["security"] += count
        elif type_ == "secret":
            stats["secret"] += count
        elif type_ in ["sast", "iac"]:
            stats["sast"] += count
        elif type_ in ["license", "eol"]:
            stats["compliance"] += count
        elif type_ in ["outdated", "quality"]:
            stats["quality"] += count
        else:
            stats["other"] += count

    return stats


@router.put(
    "/{project_id}/members/{user_id}",
    response_model=Project,
    summary="Update project member role",
)
async def update_project_member(
    project_id: str,
    user_id: str,
    member_in: ProjectMemberUpdate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Update the role of a project member.
    Requires 'admin' role on the project.
    """
    project = await check_project_access(
        project_id, current_user, db, required_role="admin"
    )

    # Check if target user is a member
    member_index = -1
    for i, member in enumerate(project.members):
        if member.user_id == user_id:
            member_index = i
            break

    if member_index == -1:
        raise HTTPException(
            status_code=404, detail="User is not a member of this project"
        )

    # Prevent changing owner's role via this endpoint (though owner is not in members list usually, but just in case)
    if project.owner_id == user_id:
        raise HTTPException(
            status_code=400, detail="Cannot change role of project owner"
        )

    update_fields = {}
    if member_in.role:
        update_fields[f"members.{member_index}.role"] = member_in.role
    if member_in.notification_preferences:
        update_fields[f"members.{member_index}.notification_preferences"] = (
            member_in.notification_preferences
        )

    if update_fields:
        await db.projects.update_one(
            {"_id": project_id, "members.user_id": user_id}, {"$set": update_fields}
        )

    updated_project_data = await db.projects.find_one({"_id": project_id})
    if updated_project_data:
        return Project(**updated_project_data)
    raise HTTPException(status_code=404, detail="Project not found")


@router.delete(
    "/{project_id}/members/{user_id}",
    response_model=Project,
    summary="Remove user from project",
)
async def remove_project_member(
    project_id: str,
    user_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Remove a user from the project.
    Requires 'admin' role on the project.
    """
    project = await check_project_access(
        project_id, current_user, db, required_role="admin"
    )

    # Check if target user is a member
    member_exists = False
    for member in project.members:
        if member.user_id == user_id:
            member_exists = True
            break

    if not member_exists:
        raise HTTPException(
            status_code=404, detail="User is not a member of this project"
        )

    if project.owner_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot remove project owner")

    await db.projects.update_one(
        {"_id": project_id}, {"$pull": {"members": {"user_id": user_id}}}
    )

    updated_project_data = await db.projects.find_one({"_id": project_id})
    if updated_project_data:
        return Project(**updated_project_data)
    raise HTTPException(status_code=404, detail="Project not found")


@router.get("/{project_id}/export/csv", summary="Export latest scan results as CSV")
async def export_project_csv(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    await check_project_access(project_id, current_user, db, required_role="viewer")

    # Get latest scan
    scan_data = await db.scans.find_one(
        {"project_id": project_id, "status": "completed"}, sort=[("created_at", -1)]
    )

    if not scan_data:
        raise HTTPException(
            status_code=404, detail="No completed scans found for this project"
        )

    scan = Scan(**scan_data)

    # Prepare CSV
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(
        [
            "Component",
            "Version",
            "Type",
            "Vulnerability ID",
            "Severity",
            "Description",
            "Fixed Version",
        ]
    )

    # Iterate findings
    # Assuming findings_summary structure. Adjust based on actual data.
    if scan.findings_summary:
        for finding in scan.findings_summary:
            f_dict = finding.model_dump()
            writer.writerow(
                [
                    f_dict.get("component", ""),
                    f_dict.get("version", ""),
                    f_dict.get("type", ""),
                    f_dict.get("id", ""),
                    f_dict.get("severity", ""),
                    f_dict.get("description", ""),
                    f_dict.get("details", {}).get("fixed_version", ""),
                ]
            )

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=project_{project_id}_scan.csv"
        },
    )


@router.get("/{project_id}/export/sbom", summary="Export latest SBOM")
async def export_project_sbom(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    await check_project_access(project_id, current_user, db, required_role="viewer")

    scan_data = await db.scans.find_one(
        {"project_id": project_id, "status": "completed"}, sort=[("created_at", -1)]
    )

    if not scan_data:
        raise HTTPException(
            status_code=404, detail="No completed scans found for this project"
        )

    scan = Scan(**scan_data)

    sbom_content = None

    # Helper to load from GridFS
    async def load_from_gridfs(file_id_str):
        try:
            fs = AsyncIOMotorGridFSBucket(db)
            grid_out = await fs.open_download_stream(ObjectId(file_id_str))
            content = await grid_out.read()
            return json.loads(content)
        except Exception:
            return None

    # 1. Try to get from GridFS via sbom_refs
    if scan.sbom_refs and len(scan.sbom_refs) > 0:
        ref = scan.sbom_refs[0]
        if ref.get("storage") == "gridfs" and ref.get("file_id"):
            sbom_content = await load_from_gridfs(ref["file_id"])

    # 2. Fallback to legacy sboms array
    if not sbom_content and scan.sboms and len(scan.sboms) > 0:
        first_sbom = scan.sboms[0]
        # Check if it's a ref or raw data
        if (
            isinstance(first_sbom, dict)
            and first_sbom.get("storage") == "gridfs"
            and first_sbom.get("file_id")
        ):
            sbom_content = await load_from_gridfs(first_sbom["file_id"])
        else:
            # Assume it's the raw SBOM
            sbom_content = first_sbom

    if not sbom_content:
        raise HTTPException(
            status_code=404, detail="No SBOM data found for the latest scan"
        )

    return Response(
        content=json.dumps(sbom_content, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=project_{project_id}_sbom.json"
        },
    )


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Delete a project and all associated data (scans, results).
    Requires 'project:delete' permission or being the project owner.
    """
    project = await check_project_access(
        project_id, current_user, db, required_role="admin"
    )

    # Additional check: Only global admin or project owner can delete
    is_global_admin = (
        "*" in current_user.permissions or "project:delete" in current_user.permissions
    )
    is_owner = project.owner_id == str(current_user.id)

    if not (is_global_admin or is_owner):
        raise HTTPException(
            status_code=403,
            detail="Only project owner or administrator can delete a project",
        )

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
