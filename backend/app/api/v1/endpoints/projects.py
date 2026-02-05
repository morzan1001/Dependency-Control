import csv
import io
import json
import logging
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Response, status

from app.api.router import CustomAPIRouter
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.api.v1.helpers import (
    aggregate_stats_by_category,
    apply_system_settings_enforcement,
    build_pagination_response,
    build_user_project_query,
    check_project_access,
    delete_gridfs_files,
    generate_project_api_key,
    get_category_type_filter,
    get_sort_field,
    load_from_gridfs,
    parse_sort_direction,
    resolve_sbom_refs,
)
from app.core.permissions import has_permission
from app.core.worker import worker_manager
from app.db.mongodb import get_database
from app.models.invitation import ProjectInvitation
from app.models.project import AnalysisResult, Project, ProjectMember, Scan
from app.models.system import SystemSettings
from app.models.user import User
from app.models.waiver import Waiver
from app.repositories import (
    AnalysisResultRepository,
    CallgraphRepository,
    DependencyRepository,
    FindingRepository,
    InvitationRepository,
    ProjectRepository,
    ScanRepository,
    TeamRepository,
    UserRepository,
    WaiverRepository,
)
from app.schemas.project import (
    DashboardStats,
    ProjectApiKeyResponse,
    ProjectCreate,
    ProjectList,
    ProjectMemberInvite,
    ProjectMemberUpdate,
    ProjectNotificationSettings,
    ProjectUpdate,
    RecentScan,
    RiskyProject,
    ScanFindingsResponse,
)
from app.schemas.waiver import WaiverResponse

router = CustomAPIRouter()
logger = logging.getLogger(__name__)


@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.get_current_active_user),
):
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    # Filter projects user has access to
    query = await build_user_project_query(current_user, team_repo)

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

    result = await project_repo.aggregate(pipeline)

    empty_response = {
        "total_projects": 0,
        "total_critical": 0,
        "total_high": 0,
        "avg_risk_score": 0.0,
        "top_risky_projects": [],
    }

    if not result or len(result) == 0:
        return empty_response

    data = result[0]
    totals = data.get("totals", [])
    totals = totals[0] if totals else {}
    top_risky = data.get("top_risky", [])

    total_projects = totals.get("total_projects", 0)
    total_risk_score = totals.get("total_risk_score", 0.0)

    avg_risk = 0.0
    if total_projects > 0:
        avg_risk = round(total_risk_score / total_projects, 1)

    # Convert to RiskyProject models (handles ObjectId to string conversion)
    top_risky_converted = [
        RiskyProject(
            id=str(p.get("id", "")),
            name=p.get("name", ""),
            risk=p.get("risk", 0),
        )
        for p in top_risky
    ]

    return {
        "total_projects": total_projects,
        "total_critical": totals.get("total_critical", 0),
        "total_high": totals.get("total_high", 0),
        "avg_risk_score": avg_risk,
        "top_risky_projects": top_risky_converted,
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
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    # Check Project Limit
    if settings.project_limit_per_user > 0:
        # Users with system:manage permission are exempt from limits
        if not has_permission(current_user.permissions, "system:manage"):
            # Count projects owned by the user
            current_count = await project_repo.count({"owner_id": str(current_user.id)})
            if current_count >= settings.project_limit_per_user:
                raise HTTPException(
                    status_code=403,
                    detail=f"Project limit reached. You can only create {settings.project_limit_per_user} projects.",
                )

    # If team_id is provided, check if user is member of that team
    if project_in.team_id:
        is_member = await team_repo.is_member(project_in.team_id, str(current_user.id))
        if not is_member:
            raise HTTPException(
                status_code=403, detail="You are not a member of the specified team"
            )

    # Generate API Key
    project_id = str(uuid.uuid4())
    api_key, api_key_hash = generate_project_api_key(project_id)

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
    project_data = project.model_dump(by_alias=True)
    project_data["api_key_hash"] = api_key_hash

    await project_repo.create_raw(project_data)

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
    project_repo = ProjectRepository(db)

    if has_permission(current_user.permissions, "project:update"):
        project = await project_repo.get_by_id(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
    else:
        await check_project_access(project_id, current_user, db, required_role="admin")

    # Generate new key
    api_key, api_key_hash = generate_project_api_key(project_id)

    await project_repo.update(project_id, {"api_key_hash": api_key_hash})

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
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    # Check permission
    if not has_permission(
        current_user.permissions, ["project:read", "project:read_all"]
    ):
        raise HTTPException(status_code=403, detail="Not enough permissions")

    # Build search query
    search_query = {}
    if search:
        search_query["name"] = {"$regex": re.escape(search), "$options": "i"}

    # Build permission query
    permission_query = await build_user_project_query(current_user, team_repo)

    # Combine queries
    if search_query and permission_query:
        final_query = {"$and": [search_query, permission_query]}
    elif permission_query:
        final_query = permission_query
    else:
        final_query = search_query

    direction = parse_sort_direction(sort_order)
    sort_field = get_sort_field("projects", sort_by)

    total = await project_repo.count(final_query)
    projects = await project_repo.find_many(
        final_query,
        skip=skip,
        limit=limit,
        sort_by=sort_field,
        sort_order=direction,
    )

    return build_pagination_response(projects, total, skip, limit)


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
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)
    scan_repo = ScanRepository(db)

    # Check permission
    if not has_permission(
        current_user.permissions, ["project:read", "project:read_all"]
    ):
        raise HTTPException(status_code=403, detail="Not enough permissions")

    # 1. Get accessible project IDs
    permission_query = await build_user_project_query(current_user, team_repo)
    projects = await project_repo.find_all(
        permission_query,
        projection={"_id": 1, "name": 1},
    )

    project_map: Dict[str, str] = {
        str(p["_id"]): str(p.get("name", "")) for p in projects
    }
    project_ids = list(project_map.keys())

    if not project_ids:
        return []

    direction = parse_sort_direction(sort_order)
    sort_field = get_sort_field("scans", sort_by)

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

    scans = await scan_repo.aggregate(pipeline, limit)
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
    project_repo = ProjectRepository(db)

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

    result = await project_repo.aggregate(pipeline)
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
    data.pop("team_data", None)
    data.pop("project_users", None)
    data.pop("team_users", None)

    project = Project(**data)

    # Verify Access (Logic from check_project_access but using loaded data)
    if has_permission(current_user.permissions, "project:read_all"):
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
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    if has_permission(current_user.permissions, "project:update"):
        project = await project_repo.get_by_id(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
    else:
        project = await check_project_access(
            project_id, current_user, db, required_role="admin"
        )

    # If transferring to a team, verify membership
    if project_in.team_id and project_in.team_id != project.team_id:
        # Check if user is member of the new team
        # Exception: Users with project:update can transfer to any team
        if not has_permission(current_user.permissions, "project:update"):
            is_member = await team_repo.is_member(
                project_in.team_id, str(current_user.id)
            )
            if not is_member:
                raise HTTPException(
                    status_code=403, detail="You are not a member of the target team"
                )

    update_data = {k: v for k, v in project_in.model_dump(exclude_unset=True).items()}

    # Apply system settings enforcement
    system_settings = await deps.get_system_settings(db)
    update_data = apply_system_settings_enforcement(
        update_data,
        system_settings.retention_mode,
        system_settings.rescan_mode,
    )

    if update_data:
        await project_repo.update(project_id, update_data)

    updated_project = await project_repo.get_by_id(project_id)
    if updated_project:
        return updated_project
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

    scan_repo = ScanRepository(db)
    branches = await scan_repo.distinct("branch", {"project_id": project_id})
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

    scan_repo = ScanRepository(db)

    query: Dict[str, Any] = {"project_id": project_id}
    if branch:
        query["branch"] = branch

    if exclude_rescans:
        query["is_rescan"] = {"$ne": True}

    direction = parse_sort_direction(sort_order)
    sort_field = get_sort_field("project_scans", sort_by)

    scans = await scan_repo.find_many(
        query,
        sort=[(sort_field, direction)],
        skip=skip,
        limit=limit,
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

    scan_repo = ScanRepository(db)

    # Find the scan
    scan = await scan_repo.find_one({"_id": scan_id, "project_id": project_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Ensure scan has SBOMs
    if not scan.get("sbom_refs"):
        raise HTTPException(
            status_code=400, detail="Cannot re-scan: No SBOMs found in the source scan."
        )

    # Determine original scan ID
    # If the source scan is already a re-scan, trace back to find the original
    # This maintains proper scan lineage for history tracking
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

    await scan_repo.create(new_scan)

    # Update original scan to point to this new pending rescan
    await scan_repo.update_raw(
        original_scan_id,
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

    scan_repo = ScanRepository(db)

    # 1. Get the requested scan to find the root
    scan = await scan_repo.find_one({"_id": scan_id, "project_id": project_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Determine the root ID
    root_id = scan.get("original_scan_id") or scan_id

    # 2. Find all scans that are either the root OR have this root as original_scan_id
    history = await scan_repo.find_many(
        {
            "project_id": project_id,
            "$or": [{"_id": root_id}, {"original_scan_id": root_id}],
        },
        sort=[("created_at", -1)],
        limit=100,
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
    has_update_perm = has_permission(current_user.permissions, "project:update")

    update_data = {}

    # Handle enforcement setting (Owner/Admin only)
    if settings.enforce_notification_settings is not None:
        if is_owner or has_update_perm:
            update_data["enforce_notification_settings"] = (
                settings.enforce_notification_settings
            )

    project_repo = ProjectRepository(db)

    if is_owner:
        update_data["owner_notification_preferences"] = (
            settings.notification_preferences
        )
        await project_repo.update(project_id, update_data)
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
                if update_data:
                    await project_repo.update(project_id, update_data)

                # Also update member preferences
                await project_repo.update_member(
                    project_id,
                    str(current_user.id),
                    {
                        f"members.{i}.notification_preferences": settings.notification_preferences
                    },
                )
                member_found = True
                break

        if not member_found:
            # Occurs if superuser is not a member
            if has_update_perm:
                # Just update the project settings (enforcement) if provided
                if update_data:
                    await project_repo.update(project_id, update_data)
            else:
                # Superusers must be members to set preferences.
                raise HTTPException(
                    status_code=400,
                    detail="You must be a member or owner to set notification preferences",
                )

    # Return updated project
    updated_project = await project_repo.get_by_id(project_id)
    if updated_project:
        return updated_project
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

    user_repo = UserRepository(db)
    project_repo = ProjectRepository(db)
    invitation_repo = InvitationRepository(db)

    # Check if user already exists
    existing_user = await user_repo.get_raw_by_email(invite_in.email)
    if existing_user:
        # If user exists, add directly to project
        member = ProjectMember(user_id=str(existing_user["_id"]), role=invite_in.role)

        # Check if already member
        for m in project.members:
            if m.user_id == member.user_id:
                raise HTTPException(status_code=400, detail="User already a member")

        await project_repo.add_member(project_id, member.model_dump())
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
        await invitation_repo.create_project_invitation(invitation)
        # In a real app, send email here
        return invitation


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
    scan_repo = ScanRepository(db)
    analysis_repo = AnalysisResultRepository(db)

    # Need to find project_id from scan to check permissions
    scan = await scan_repo.get_minimal_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await check_project_access(scan.project_id, current_user, db)

    # Find all scans for this commit to aggregate results
    # Note: commit_hash not in ScanMinimal, use get_by_id for full model
    full_scan = await scan_repo.get_by_id(scan_id)
    related_scans = await scan_repo.find_many(
        {"project_id": scan.project_id, "commit_hash": full_scan.commit_hash if full_scan else None},
        projection={"_id": 1},
    )
    related_scan_ids = [s.id for s in related_scans]

    if not related_scan_ids:
        related_scan_ids = [scan_id]

    results = await analysis_repo.find_by_scan_ids(related_scan_ids)

    # Group results by analyzer_name
    grouped_results = {}
    for res in results:
        name = res.analyzer_name
        grouped_results.setdefault(name, []).append(res)

    final_results = []

    for name, group in grouped_results.items():
        # 1. Prefer results from the requested scan_id
        current_scan_results = [r for r in group if r.scan_id == scan_id]

        if current_scan_results:
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

    # Convert ObjectId to string for response validation
    for result in final_results:
        if "_id" in result:
            result["_id"] = str(result["_id"])
        if "scan_id" in result:
            result["scan_id"] = str(result["scan_id"])

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
    scan_repo = ScanRepository(db)

    scan_data = await scan_repo.get_by_id(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    await check_project_access(scan_data.project_id, current_user, db)

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
    scan_repo = ScanRepository(db)

    scan_data = await scan_repo.get_by_id(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    await check_project_access(scan_data.project_id, current_user, db)

    # Get SBOM refs from GridFS (legacy 'sboms' field removed)
    sbom_refs = scan_data.sbom_refs or []

    if not sbom_refs:
        raise HTTPException(
            status_code=404, detail="No SBOM data available for this scan"
        )

    return await resolve_sbom_refs(db, sbom_refs)


@router.get(
    "/scans/{scan_id}/findings",
    response_model=ScanFindingsResponse,
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
    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)

    # Check access
    scan = await scan_repo.get_by_id(scan_id, {"project_id": 1})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await check_project_access(scan.project_id, current_user, db)

    query = {"scan_id": scan_id}

    if type:
        query["type"] = type

    if category:
        type_filter = get_category_type_filter(category)
        if type_filter:
            query["type"] = type_filter

    if severity:
        query["severity"] = severity.upper()
    if search:
        escaped_search = re.escape(search)
        query["$or"] = [
            {"component": {"$regex": escaped_search, "$options": "i"}},
            {"finding_id": {"$regex": escaped_search, "$options": "i"}},
            {"description": {"$regex": escaped_search, "$options": "i"}},
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
        # Remove the temporary lookup array and exclude MongoDB _id
        {"$project": {"dependency_info": 0, "_id": 0}},
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

    result = await finding_repo.aggregate(pipeline)

    data = result[0]["data"] if result else []
    metadata = result[0]["metadata"] if result else []
    total = metadata[0]["total"] if metadata else 0

    return build_pagination_response(data, total, skip, limit)


@router.get("/scans/{scan_id}/stats")
async def get_scan_stats(
    scan_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get finding statistics by category for a scan.
    """
    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)

    # Check access
    scan = await scan_repo.get_by_id(scan_id, {"project_id": 1})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await check_project_access(scan.project_id, current_user, db)

    pipeline: List[Dict[str, Any]] = [
        {"$match": {"scan_id": scan_id}},
        {"$group": {"_id": "$type", "count": {"$sum": 1}}},
    ]

    results = await finding_repo.aggregate(pipeline)

    return aggregate_stats_by_category(results)


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

    project_repo = ProjectRepository(db)

    update_fields = {}
    if member_in.role:
        update_fields[f"members.{member_index}.role"] = member_in.role
    if member_in.notification_preferences:
        update_fields[f"members.{member_index}.notification_preferences"] = (
            member_in.notification_preferences
        )

    if update_fields:
        await project_repo.update_member(project_id, user_id, update_fields)

    updated_project = await project_repo.get_by_id(project_id)
    if updated_project:
        return updated_project
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

    project_repo = ProjectRepository(db)
    await project_repo.remove_member(project_id, user_id)

    updated_project = await project_repo.get_by_id(project_id)
    if updated_project:
        return updated_project
    raise HTTPException(status_code=404, detail="Project not found")


@router.get("/{project_id}/export/csv", summary="Export latest scan results as CSV")
async def export_project_csv(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    await check_project_access(project_id, current_user, db, required_role="viewer")

    scan_repo = ScanRepository(db)

    # Get latest scan
    scan_data = await scan_repo.get_latest_for_project(project_id, status="completed")

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

    scan_repo = ScanRepository(db)

    scan_data = await scan_repo.get_latest_for_project(project_id, status="completed")

    if not scan_data:
        raise HTTPException(
            status_code=404, detail="No completed scans found for this project"
        )

    scan = Scan(**scan_data)

    # Get SBOM from GridFS via sbom_refs
    # Legacy fallback removed - all SBOMs are stored in GridFS
    if not scan.sbom_refs or len(scan.sbom_refs) == 0:
        raise HTTPException(status_code=404, detail="No SBOM data found for this scan")

    ref = scan.sbom_refs[0]
    if ref.get("storage") != "gridfs" or not ref.get("file_id"):
        raise HTTPException(
            status_code=500, detail="Invalid SBOM reference (not GridFS)"
        )

    sbom_content = await load_from_gridfs(db, ref["file_id"])

    if not sbom_content:
        raise HTTPException(status_code=404, detail="SBOM file not found in GridFS")

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
    has_delete_perm = has_permission(current_user.permissions, "project:delete")
    is_owner = project.owner_id == str(current_user.id)

    if not (has_delete_perm or is_owner):
        raise HTTPException(
            status_code=403,
            detail="Only project owner or administrator can delete a project",
        )

    project_repo = ProjectRepository(db)
    scan_repo = ScanRepository(db)
    analysis_repo = AnalysisResultRepository(db)
    finding_repo = FindingRepository(db)
    dep_repo = DependencyRepository(db)
    waiver_repo = WaiverRepository(db)
    invitation_repo = InvitationRepository(db)
    callgraph_repo = CallgraphRepository(db)

    # 1. Find all scans and collect GridFS file IDs
    scans = await scan_repo.find_by_project(project_id, limit=10000)
    scan_ids = [doc["_id"] for doc in scans]
    gridfs_ids = []

    for scan in scans:
        # Collect GridFS file IDs from sbom_refs
        for ref in scan.get("sbom_refs", []):
            file_id = ref.get("file_id") or ref.get("gridfs_id")
            if file_id:
                gridfs_ids.append(file_id)

    # 2. Delete scan-related data
    if scan_ids:
        await analysis_repo.delete_many({"scan_id": {"$in": scan_ids}})
        await finding_repo.delete_many({"scan_id": {"$in": scan_ids}})
        await dep_repo.delete_many({"scan_id": {"$in": scan_ids}})

    # 3. Delete scans
    await scan_repo.delete_many({"project_id": project_id})

    # 4. Delete GridFS files
    await delete_gridfs_files(db, gridfs_ids)

    # 5. Delete waivers
    await waiver_repo.delete_many({"project_id": project_id})

    # 6. Delete project invitations
    await invitation_repo.delete_project_invitations_by_project(project_id)

    # 7. Delete callgraphs
    await callgraph_repo.delete_by_project(project_id)

    # 8. Delete project
    await project_repo.delete(project_id)


@router.get("/{project_id}/waivers", response_model=List[WaiverResponse])
async def get_project_waivers(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get all waivers for a specific project.
    """
    await check_project_access(project_id, current_user, db, required_role="viewer")

    waiver_repo = WaiverRepository(db)
    waivers = await waiver_repo.find_by_project(project_id)
    return [Waiver(**w) for w in waivers]
