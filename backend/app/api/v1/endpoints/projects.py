import csv
import io
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, HTTPException, Query, Response, status

from app.api.router import CustomAPIRouter

from app.api import deps
from app.api.deps import CurrentUserDep, DatabaseDep
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
    is_write_superuser,
    load_from_gridfs,
    parse_sort_direction,
    resolve_sbom_refs,
)
from app.api.v1.helpers.auth import send_project_member_added_email
from app.core.constants import SEVERITY_CALCULATED_RISK_SCORES
from app.core.permissions import Permissions, has_permission
from app.core.worker import worker_manager
from app.models.project import AnalysisResult, Project, ProjectMember, Scan
from app.models.system import SystemSettings
from app.models.user import User
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
    BranchInfo,
    DashboardStats,
    ProjectApiKeyResponse,
    ProjectCreate,
    ProjectListEnriched,
    ProjectWithTeam,
    ProjectMemberInvite,
    ProjectMemberUpdate,
    ProjectNotificationSettings,
    ProjectUpdate,
    RecentScan,
    RiskyProject,
    ScanFindingsResponse,
)
from app.api.v1.helpers.responses import (
    RESP_AUTH,
    RESP_AUTH_400_404,
    RESP_AUTH_400_404_500,
    RESP_AUTH_404,
    RESP_AUTH_404_500,
)

router = CustomAPIRouter()
logger = logging.getLogger(__name__)

MONGO_GROUP = "$group"

_MSG_PROJECT_NOT_FOUND = "Project not found"
_MSG_SCAN_NOT_FOUND = "Scan not found"
_MSG_NOT_ENOUGH_PERMISSIONS = "Not enough permissions"


@router.get("/dashboard/stats", response_model=DashboardStats, responses=RESP_AUTH)
async def get_dashboard_stats(
    db: DatabaseDep,
    current_user: CurrentUserDep,
) -> Dict[str, Any]:
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    query = await build_user_project_query(current_user, team_repo)

    # Aggregate rather than fetch all projects, for performance.
    pipeline: List[Dict[str, Any]] = [
        {"$match": query},
        {
            "$project": {
                "name": 1,
                "stats": 1,
                # Prefer persisted stats.risk_score; else the same severity-weighted
                # average of per-severity anchors used by calculate_comprehensive_stats.
                "calculated_risk": {
                    "$ifNull": [
                        "$stats.risk_score",
                        {
                            "$let": {
                                "vars": {
                                    "n": {
                                        "$add": [
                                            {"$ifNull": ["$stats.critical", 0]},
                                            {"$ifNull": ["$stats.high", 0]},
                                            {"$ifNull": ["$stats.medium", 0]},
                                            {"$ifNull": ["$stats.low", 0]},
                                        ]
                                    },
                                    "weighted": {
                                        "$add": [
                                            {
                                                "$multiply": [
                                                    {"$ifNull": ["$stats.critical", 0]},
                                                    SEVERITY_CALCULATED_RISK_SCORES["CRITICAL"],
                                                ]
                                            },
                                            {
                                                "$multiply": [
                                                    {"$ifNull": ["$stats.high", 0]},
                                                    SEVERITY_CALCULATED_RISK_SCORES["HIGH"],
                                                ]
                                            },
                                            {
                                                "$multiply": [
                                                    {"$ifNull": ["$stats.medium", 0]},
                                                    SEVERITY_CALCULATED_RISK_SCORES["MEDIUM"],
                                                ]
                                            },
                                            {
                                                "$multiply": [
                                                    {"$ifNull": ["$stats.low", 0]},
                                                    SEVERITY_CALCULATED_RISK_SCORES["LOW"],
                                                ]
                                            },
                                        ]
                                    },
                                },
                                "in": {
                                    "$cond": [
                                        {"$gt": ["$$n", 0]},
                                        {"$divide": ["$$weighted", "$$n"]},
                                        0,
                                    ]
                                },
                            }
                        },
                    ]
                },
            }
        },
        {
            "$facet": {
                "totals": [
                    {
                        MONGO_GROUP: {
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
    summary="Create a new project",
    status_code=201,
    responses=RESP_AUTH,
)
async def create_project(
    project_in: ProjectCreate,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.PROJECT_CREATE))],
    db: DatabaseDep,
    settings: Annotated[SystemSettings, Depends(deps.get_system_settings)],
) -> ProjectApiKeyResponse:
    """Create a new project and return the initial API Key, which is only returned once."""
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    if settings.project_limit_per_user > 0:
        if not has_permission(current_user.permissions, Permissions.SYSTEM_MANAGE):
            current_count = await project_repo.count(
                {"members": {"$elemMatch": {"user_id": str(current_user.id), "role": "admin"}}}
            )
            if current_count >= settings.project_limit_per_user:
                raise HTTPException(
                    status_code=403,
                    detail=f"Project limit reached. You can only create {settings.project_limit_per_user} projects.",
                )

    if project_in.team_id:
        is_member = await team_repo.is_member(project_in.team_id, str(current_user.id))
        if not is_member:
            raise HTTPException(status_code=403, detail="You are not a member of the specified team")

    project_id = str(uuid.uuid4())
    api_key, api_key_hash = generate_project_api_key(project_id)

    project = Project(
        id=project_id,
        name=project_in.name,
        team_id=project_in.team_id,
        # A user-chosen team is a manual assignment.
        team_source="manual" if project_in.team_id else None,
        api_key_hash=api_key_hash,
        active_analyzers=project_in.active_analyzers,
        retention_days=(project_in.retention_days if project_in.retention_days is not None else 90),
        members=[ProjectMember(user_id=str(current_user.id), role="admin")],
    )

    # api_key_hash is excluded from the model dump by default; add it back manually.
    project_data = project.model_dump(by_alias=True)
    project_data["api_key_hash"] = api_key_hash

    await project_repo.create_raw(project_data)

    return ProjectApiKeyResponse(project_id=project_id, api_key=api_key)


@router.post(
    "/{project_id}/rotate-key",
    summary="Rotate Project API Key",
    responses=RESP_AUTH_404,
)
async def rotate_api_key(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ProjectApiKeyResponse:
    """Invalidate the old API Key and generate a new one. Requires 'admin' role."""
    project_repo = ProjectRepository(db)

    # project:update holders pass via the write-superuser branch.
    await check_project_access(project_id, current_user, db, required_role="admin")

    api_key, api_key_hash = generate_project_api_key(project_id)

    await project_repo.update(project_id, {"api_key_hash": api_key_hash})

    return ProjectApiKeyResponse(project_id=project_id, api_key=api_key)


@router.get("/", response_model=ProjectListEnriched, summary="List all projects", responses=RESP_AUTH)
async def read_projects(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    search: Optional[str] = None,
    team_id: Optional[str] = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> Dict[str, Any]:
    """
    Retrieve projects.

    - **Superusers** see all projects.
    - **Regular users** see projects they own or are members of.
    - **team_id** optional filter to show only projects of a specific team.
    """
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    if not has_permission(current_user.permissions, [Permissions.PROJECT_READ, Permissions.PROJECT_READ_ALL]):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    search_query: Dict[str, Any] = {}
    if search:
        search_query["name"] = {"$regex": re.escape(search), "$options": "i"}
    if team_id:
        search_query["team_id"] = team_id

    permission_query = await build_user_project_query(current_user, team_repo)

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

    team_ids = [p.team_id for p in projects if p.team_id]
    team_name_map = {}
    if team_ids:
        teams = await team_repo.find_many({"_id": {"$in": team_ids}}, limit=len(team_ids))
        team_name_map = {t.id: t.name for t in teams}

    enriched_projects = []
    for p in projects:
        p_data = p.model_dump()
        p_data["team_name"] = team_name_map.get(p.team_id) if p.team_id else None
        enriched_projects.append(ProjectWithTeam(**p_data))

    return build_pagination_response(enriched_projects, total, skip, limit)


@router.get(
    "/scans",
    response_model=List[RecentScan],
    summary="List scans across all accessible projects",
    responses=RESP_AUTH,
)
async def read_all_scans(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    skip: Annotated[int, Query(ge=0)] = 0,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> List[Dict[str, Any]]:
    """Retrieve scans for all projects the user has access to, with pagination and sorting."""
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)
    scan_repo = ScanRepository(db)

    if not has_permission(current_user.permissions, [Permissions.PROJECT_READ, Permissions.PROJECT_READ_ALL]):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    permission_query = await build_user_project_query(current_user, team_repo)
    projects = await project_repo.find_many_minimal(permission_query)

    project_map: Dict[str, str] = {str(p.id): str(p.name) for p in projects}
    project_ids = list(project_map.keys())

    if not project_ids:
        return []

    direction = parse_sort_direction(sort_order)
    sort_field = get_sort_field("scans", sort_by)

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


def _merge_team_members(data: Dict[str, Any], t_users: Dict[str, str]) -> None:
    """Merge team members into project members list, skipping duplicates."""
    team_data = data.get("team_data")
    if not team_data:
        return

    existing_ids = set(m["user_id"] for m in data["members"])
    for tm in team_data.get("members", []):
        uid = tm["user_id"]
        if uid in existing_ids:
            continue
        role = "admin" if tm.get("role") in ["admin"] else "viewer"
        data["members"].append(
            {
                "user_id": uid,
                "role": role,
                "username": t_users.get(uid),
                "inherited_from": f"Team: {team_data.get('name')}",
            }
        )


@router.get("/{project_id}", summary="Get project details", responses=RESP_AUTH_404)
async def read_project(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Project:
    """Get a specific project by ID."""
    project_repo = ProjectRepository(db)

    # Single aggregation to avoid N+1 team/user lookups.
    pipeline: List[Dict[str, Any]] = [
        {"$match": {"_id": project_id}},
        {
            "$lookup": {
                "from": "teams",
                "localField": "team_id",
                "foreignField": "_id",
                "as": "team_data",
            }
        },
        {"$unwind": {"path": "$team_data", "preserveNullAndEmptyArrays": True}},
        {
            "$lookup": {
                "from": "users",
                "let": {"member_ids": "$members.user_id"},
                "pipeline": [
                    {"$match": {"$expr": {"$in": [{"$toString": "$_id"}, "$$member_ids"]}}},
                    {"$project": {"_id": 1, "username": 1}},
                ],
                "as": "project_users",
            }
        },
        {
            "$lookup": {
                "from": "users",
                "let": {"team_member_ids": {"$ifNull": ["$team_data.members.user_id", []]}},
                "pipeline": [
                    {"$match": {"$expr": {"$in": [{"$toString": "$_id"}, "$$team_member_ids"]}}},
                    {"$project": {"_id": 1, "username": 1}},
                ],
                "as": "team_users",
            }
        },
    ]

    result = await project_repo.aggregate(pipeline)
    if not result:
        raise HTTPException(status_code=404, detail=_MSG_PROJECT_NOT_FOUND)

    data = result[0]

    p_users = {str(u["_id"]): u["username"] for u in data.get("project_users", [])}
    t_users = {str(u["_id"]): u["username"] for u in data.get("team_users", [])}

    for m in data.get("members", []):
        m["username"] = p_users.get(m["user_id"])

    _merge_team_members(data, t_users)

    data.pop("team_data", None)
    data.pop("project_users", None)
    data.pop("team_users", None)

    project = Project(**data)

    # Inline access check against the already-loaded data.
    if not has_permission(current_user.permissions, Permissions.PROJECT_READ_ALL):
        is_member = any(m.user_id == str(current_user.id) for m in project.members)

        if not is_member:
            raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

        if Permissions.PROJECT_READ not in current_user.permissions:
            raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    return project


async def _load_project_for_update(
    project_id: str,
    current_user: User,
    db: Any,
) -> Project:
    """Load the project for an update and verify the caller can edit it."""
    return await check_project_access(project_id, current_user, db, required_role="admin")


async def _assert_can_transfer_team(
    project: Project,
    project_in: ProjectUpdate,
    current_user: User,
    team_repo: TeamRepository,
) -> None:
    """Block team transfers unless the actor is a global admin or member of the target team."""
    if not project_in.team_id or project_in.team_id == project.team_id:
        return
    if is_write_superuser(current_user):
        return
    is_member = await team_repo.is_member(project_in.team_id, str(current_user.id))
    if not is_member:
        raise HTTPException(status_code=403, detail="You are not a member of the target team")


async def _assert_gitlab_mr_token_present(
    project: Project,
    update_data: Dict[str, Any],
    db: Any,
) -> None:
    """Reject MR-decoration enablement when the linked GitLab instance lacks a token."""
    mr_enabled = update_data.get("gitlab_mr_comments_enabled", project.gitlab_mr_comments_enabled)
    instance_id = update_data.get("gitlab_instance_id", project.gitlab_instance_id)
    if not (mr_enabled and instance_id):
        return
    from app.repositories.gitlab_instances import GitLabInstanceRepository

    instance_repo = GitLabInstanceRepository(db)
    gitlab_instance = await instance_repo.get_by_id(instance_id)
    if gitlab_instance and not gitlab_instance.access_token:
        raise HTTPException(
            status_code=400,
            detail="Cannot enable MR decoration: the linked GitLab instance has no access token configured",
        )


async def _audit_license_policy_change(
    db: Any,
    project_id: str,
    old_license_policy: Optional[Dict[str, Any]],
    updated_project: Project,
    actor: User,
) -> None:
    """Record a best-effort license-policy audit entry; never blocks the caller."""
    try:
        new_license_policy = _resolve_license_policy(updated_project)
        if old_license_policy == new_license_policy:
            return
        from app.schemas.policy_audit import PolicyAuditAction
        from app.services.audit.history import record_license_policy_change

        action = PolicyAuditAction.CREATE if not old_license_policy else PolicyAuditAction.UPDATE
        await record_license_policy_change(
            db,
            project_id=project_id,
            old_policy=old_license_policy,
            new_policy=new_license_policy,
            action=action,
            actor=actor,
            comment=None,
        )
    except Exception:  # pragma: no cover - defensive
        logging.getLogger(__name__).exception("License-policy audit for project %s failed (non-blocking)", project_id)


@router.put("/{project_id}", summary="Update project details", responses=RESP_AUTH_404)
async def update_project(
    project_id: str,
    project_in: ProjectUpdate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Project:
    """Update project details (name, team, active analyzers). Requires 'admin' role."""
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    project = await _load_project_for_update(project_id, current_user, db)
    await _assert_can_transfer_team(project, project_in, current_user, team_repo)

    update_data = dict(project_in.model_dump(exclude_unset=True))
    # Stamp manual provenance only when the team actually changes, so an unrelated
    # edit can't flip a sync-assigned project to "manual".
    if "team_id" in update_data and update_data["team_id"] != project.team_id:
        update_data["team_source"] = "manual"
    await _assert_gitlab_mr_token_present(project, update_data, db)

    system_settings = await deps.get_system_settings(db)
    update_data = apply_system_settings_enforcement(
        update_data,
        system_settings.retention_mode,
        system_settings.rescan_mode,
    )

    # Capture the pre-update license policy so we can audit transitions.
    old_license_policy = _resolve_license_policy(project)

    if update_data:
        await project_repo.update(project_id, update_data)

    updated_project = await project_repo.get_by_id(project_id)
    if not updated_project:
        raise HTTPException(status_code=404, detail=_MSG_PROJECT_NOT_FOUND)

    await _audit_license_policy_change(db, project_id, old_license_policy, updated_project, current_user)
    return updated_project


def _resolve_license_policy(project: Project) -> Optional[Dict[str, Any]]:
    """Return the project's license policy, preferring analyzer_settings['license_compliance'] over the legacy top-level field."""
    settings = (
        (project.analyzer_settings or {}).get("license_compliance")
        if getattr(project, "analyzer_settings", None)
        else None
    )
    if settings:
        return dict(settings)
    legacy = getattr(project, "license_policy", None)
    if legacy:
        return dict(legacy) if isinstance(legacy, dict) else legacy.model_dump()
    return None


@router.get(
    "/{project_id}/branches",
    summary="List project branches",
    responses=RESP_AUTH_404,
)
async def read_project_branches(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> List[BranchInfo]:
    """Get all unique branches for a project with their active/deleted status."""
    await check_project_access(project_id, current_user, db, required_role="viewer")

    scan_repo = ScanRepository(db)
    project_repo = ProjectRepository(db)

    branches = await scan_repo.distinct("branch", {"project_id": project_id})
    project = await project_repo.get_by_id(project_id)
    deleted_set = set(project.deleted_branches) if project else set()

    pipeline: List[Dict[str, Any]] = [
        {"$match": {"project_id": project_id}},
        {MONGO_GROUP: {"_id": "$branch", "last_scan_at": {"$max": "$created_at"}}},
    ]
    last_scans = {}
    async for doc in db.scans.aggregate(pipeline):
        last_scans[doc["_id"]] = doc["last_scan_at"]

    result = [
        BranchInfo(
            name=b,
            is_active=b not in deleted_set,
            last_scan_at=last_scans.get(b),
        )
        for b in sorted(branches)
    ]
    return result


@router.post(
    "/{project_id}/sync-branches",
    summary="Sync branch status from VCS",
    responses=RESP_AUTH_400_404,
)
async def sync_project_branches_endpoint(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> List[BranchInfo]:
    """Trigger branch status sync against the VCS provider for a project."""
    await check_project_access(project_id, current_user, db, required_role="editor")

    project_repo = ProjectRepository(db)
    project = await project_repo.get_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail=_MSG_PROJECT_NOT_FOUND)

    if not project.gitlab_instance_id and not project.github_instance_id:
        raise HTTPException(status_code=400, detail="Project has no VCS connection configured")

    from app.core.housekeeping import sync_project_branches

    project_data = await project_repo.get_raw_by_id(project_id)
    if project_data:
        await sync_project_branches(project_data, db)

    return await read_project_branches(project_id, current_user, db)


@router.get("/{project_id}/scans", summary="List project scans", responses=RESP_AUTH_404)
async def read_project_scans(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    branch: Optional[str] = None,
    exclude_deleted_branches: bool = False,
    exclude_rescans: bool = False,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> List[Scan]:
    """Get scans for a project."""
    await check_project_access(project_id, current_user, db, required_role="viewer")

    scan_repo = ScanRepository(db)
    project_repo = ProjectRepository(db)

    query: Dict[str, Any] = {"project_id": project_id}
    if branch:
        query["branch"] = branch
    elif exclude_deleted_branches:
        project = await project_repo.get_by_id(project_id)
        if project and project.deleted_branches:
            query["branch"] = {"$nin": project.deleted_branches}

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
    summary="Trigger a manual re-scan",
    responses=RESP_AUTH_400_404_500,
)
async def trigger_rescan(
    project_id: str,
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Scan:
    """Manually trigger a re-scan: a new scan entry with the same SBOMs, re-analysed."""
    await check_project_access(project_id, current_user, db, required_role="editor")

    scan_repo = ScanRepository(db)

    scan = await scan_repo.find_one({"_id": scan_id, "project_id": project_id})
    if not scan:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)

    if not scan.get("sbom_refs"):
        raise HTTPException(status_code=400, detail="Cannot re-scan: No SBOMs found in the source scan.")

    # Trace back to the original scan so lineage stays intact.
    original_scan_id = scan.get("original_scan_id") or scan_id

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

    if worker_manager:
        await worker_manager.add_job(new_scan.id)
    else:
        raise HTTPException(status_code=500, detail="Worker manager not available")

    return new_scan


@router.get(
    "/{project_id}/scans/{scan_id}/history",
    summary="Get scan history",
    responses=RESP_AUTH_404,
)
async def read_scan_history(
    project_id: str,
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> List[Scan]:
    """Get a scan's history (original plus all re-scans), sorted by date."""
    await check_project_access(project_id, current_user, db, required_role="viewer")

    scan_repo = ScanRepository(db)

    scan = await scan_repo.find_one({"_id": scan_id, "project_id": project_id})
    if not scan:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)

    root_id = scan.get("original_scan_id") or scan_id

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
    summary="Update notification settings",
    responses=RESP_AUTH_400_404,
)
async def update_notification_settings(
    project_id: str,
    settings: ProjectNotificationSettings,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Project:
    """Update notification preferences for the current user in this project."""
    project = await check_project_access(project_id, current_user, db)

    is_admin = any(m.user_id == str(current_user.id) and m.role == "admin" for m in project.members)
    has_update_perm = has_permission(current_user.permissions, Permissions.PROJECT_UPDATE)

    update_data: Dict[str, Any] = {}

    if settings.enforce_notification_settings is not None:
        if is_admin or has_update_perm:
            update_data["enforce_notification_settings"] = settings.enforce_notification_settings

    project_repo = ProjectRepository(db)

    if is_admin:
        # Persist enforcement changes and the admin's own per-project preferences.
        if update_data:
            await project_repo.update(project_id, update_data)
        for i, member in enumerate(project.members):
            if member.user_id == str(current_user.id):
                await project_repo.update_member(
                    project_id,
                    str(current_user.id),
                    {f"members.{i}.notification_preferences": settings.notification_preferences},
                )
                break
    else:
        if project.enforce_notification_settings and not has_update_perm:
            raise HTTPException(
                status_code=403,
                detail="Notification settings are enforced by the project admin",
            )

        member_found = False
        for i, member in enumerate(project.members):
            if member.user_id == str(current_user.id):
                if update_data:
                    await project_repo.update(project_id, update_data)

                await project_repo.update_member(
                    project_id,
                    str(current_user.id),
                    {f"members.{i}.notification_preferences": settings.notification_preferences},
                )
                member_found = True
                break

        if not member_found:
            # A superuser who is not a member can still update enforcement, not preferences.
            if has_update_perm:
                if update_data:
                    await project_repo.update(project_id, update_data)
            else:
                raise HTTPException(
                    status_code=400,
                    detail="You must be a member or admin to set notification preferences",
                )

    updated_project = await project_repo.get_by_id(project_id)
    if updated_project:
        return updated_project
    raise HTTPException(status_code=404, detail=_MSG_PROJECT_NOT_FOUND)


@router.post(
    "/{project_id}/invite",
    summary="Add a user to project by email",
    responses=RESP_AUTH_400_404,
)
async def invite_user(
    project_id: str,
    invite_in: ProjectMemberInvite,
    background_tasks: BackgroundTasks,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Dict[str, Any]:
    """Add an existing user to the project by email (404 if no account exists; use system invitations for new users)."""
    project = await check_project_access(project_id, current_user, db, required_role="admin")

    user_repo = UserRepository(db)
    project_repo = ProjectRepository(db)

    user_to_add = await user_repo.get_raw_by_email(invite_in.email)
    if not user_to_add:
        raise HTTPException(status_code=404, detail="User with this email not found")

    member = ProjectMember(user_id=str(user_to_add["_id"]), role=invite_in.role)

    for m in project.members:
        if m.user_id == member.user_id:
            raise HTTPException(status_code=400, detail="User already a member")

    await project_repo.add_member(project_id, member.model_dump())

    try:
        system_config = await deps.get_system_settings(db)
        send_project_member_added_email(
            background_tasks=background_tasks,
            email=invite_in.email,
            project_name=project.name,
            project_id=project_id,
            inviter_name=current_user.username,
            role=invite_in.role,
            system_settings=system_config,
        )
    except Exception as e:
        logger.exception("Failed to send project member notification email: %s", e)

    return {"message": f"User added to project as {invite_in.role}"}


@router.get(
    "/scans/{scan_id}/results",
    summary="Get analysis results",
    responses=RESP_AUTH_404,
)
async def read_analysis_results(
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> List[AnalysisResult]:
    """Get the results of all analyzers for a specific scan."""
    scan_repo = ScanRepository(db)
    analysis_repo = AnalysisResultRepository(db)

    scan = await scan_repo.get_minimal_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)

    if not scan.project_id:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)
    await check_project_access(scan.project_id, current_user, db)

    return await analysis_repo.find_by_scan(scan_id)


@router.get("/scans/{scan_id}", summary="Get scan details", responses=RESP_AUTH_404)
async def read_scan(
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Scan:
    """Get details of a specific scan; SBOMs are excluded (fetch them via /scans/{scan_id}/sboms)."""
    scan_repo = ScanRepository(db)

    scan_data = await scan_repo.get_by_id(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)

    await check_project_access(scan_data.project_id, current_user, db)

    return scan_data


@router.get(
    "/scans/{scan_id}/sboms",
    summary="Get raw SBOMs for a scan",
    responses=RESP_AUTH_404,
)
async def read_scan_sboms(
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> List[Dict[str, Any]]:
    """Get raw SBOM data for a scan, resolved from GridFS on demand."""
    scan_repo = ScanRepository(db)

    scan_data = await scan_repo.get_by_id(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)

    await check_project_access(scan_data.project_id, current_user, db)

    sbom_refs = scan_data.sbom_refs or []

    if not sbom_refs:
        raise HTTPException(status_code=404, detail="No SBOM data available for this scan")

    return await resolve_sbom_refs(db, sbom_refs)


def _build_scan_findings_match(
    scan_id: str,
    *,
    type: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    license_category: Optional[str] = None,
    hide_info: Optional[bool] = None,
    waived: Optional[bool] = None,
) -> Dict[str, Any]:
    """Compose the $match stage for the scan-findings aggregation."""
    query: Dict[str, Any] = {"scan_id": scan_id}

    if type:
        query["type"] = type

    if category:
        type_filter = get_category_type_filter(category)
        if type_filter:
            query["type"] = type_filter

    if severity:
        sev = severity.upper()
        # An explicit INFO filter combined with hide_info is contradictory: match nothing.
        if hide_info and sev == "INFO":
            query["severity"] = {"$in": []}
        else:
            query["severity"] = sev
    elif hide_info:
        query["severity"] = {"$ne": "INFO"}
    if license_category:
        query["details.category"] = license_category
    if waived is not None:
        # Explicit True/False splits active vs waived; None returns both.
        query["waived"] = waived
    if search:
        escaped_search = re.escape(search)
        query["$or"] = [
            {"component": {"$regex": escaped_search, "$options": "i"}},
            {"finding_id": {"$regex": escaped_search, "$options": "i"}},
            {"description": {"$regex": escaped_search, "$options": "i"}},
        ]
    return query


def _scan_findings_lookup_stage() -> Dict[str, Any]:
    """The ``$lookup`` stage that pulls dependency info into each finding."""
    return {
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
                        "direct_inferred": 1,
                    }
                },
            ],
            "as": "dependency_info",
        }
    }


def _scan_findings_add_fields_stage() -> Dict[str, Any]:
    """The ``$addFields`` stage that ranks severity and flattens dependency info."""
    return {
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
            # Map finding_id to id for frontend compatibility.
            "id": "$finding_id",
            # Deterministic scalar for sorting by scanner (scanners is a list).
            "first_scanner": {"$arrayElemAt": ["$scanners", 0]},
            "source_type": {"$arrayElemAt": ["$dependency_info.source_type", 0]},
            "source_target": {"$arrayElemAt": ["$dependency_info.source_target", 0]},
            "layer_digest": {"$arrayElemAt": ["$dependency_info.layer_digest", 0]},
            "found_by": {"$arrayElemAt": ["$dependency_info.found_by", 0]},
            "locations": {"$arrayElemAt": ["$dependency_info.locations", 0]},
            "purl": {"$arrayElemAt": ["$dependency_info.purl", 0]},
            "direct": {"$arrayElemAt": ["$dependency_info.direct", 0]},
            "direct_inferred": {"$arrayElemAt": ["$dependency_info.direct_inferred", 0]},
        }
    }


# Sort keys the API accepts mapped to real document fields; unlisted keys fall back
# to severity so an unrecognised sort_by can't yield an unstably-paginated result.
_SCAN_FINDINGS_SORT_FIELDS: Dict[str, str] = {
    "severity": "severity",
    "component": "component",
    "type": "type",
    "source_type": "source_type",
    "finding_id": "finding_id",
    "vuln_id": "finding_id",  # UI alias -> real field
    "scanner": "first_scanner",  # UI alias -> computed scalar
}


def _scan_findings_sort_stage(sort_by: str, sort_order: str) -> Dict[str, Any]:
    """Compose the $sort stage, always ending with the unique _id tiebreaker so skip/limit pagination is stable (finding_id is not unique within a scan)."""
    sort_dir = -1 if sort_order == "desc" else 1
    field = _SCAN_FINDINGS_SORT_FIELDS.get(sort_by, "severity")
    if field == "severity":
        return {"$sort": {"severity_rank": sort_dir, "component": 1, "_id": 1}}
    sort_spec: Dict[str, Any] = {field: sort_dir}
    if field != "_id":
        sort_spec["_id"] = 1
    return {"$sort": sort_spec}


def _build_scan_findings_pipeline(
    query: Dict[str, Any],
    *,
    sort_by: str,
    sort_order: str,
    skip: int,
    limit: int,
) -> List[Dict[str, Any]]:
    """Compose the full aggregation pipeline used by ``read_scan_findings``."""
    return [
        {"$match": query},
        _scan_findings_lookup_stage(),
        _scan_findings_add_fields_stage(),
        # Keep _id through the $sort as the unique tiebreaker; it's dropped from output in the $facet below.
        {"$project": {"dependency_info": 0}},
        _scan_findings_sort_stage(sort_by, sort_order),
        {
            "$facet": {
                "metadata": [{"$count": "total"}],
                # Drop the _id tiebreaker and first_scanner sort-helper from the output.
                "data": [{"$skip": skip}, {"$limit": limit}, {"$project": {"_id": 0, "first_scanner": 0}}],
            }
        },
    ]


def _unpack_scan_findings_facet(result: List[Dict[str, Any]]) -> tuple:
    """Pull ``(data, total)`` out of the ``$facet`` result envelope."""
    if not result:
        return [], 0
    bucket = result[0]
    data = bucket.get("data") or []
    metadata = bucket.get("metadata") or []
    total = metadata[0]["total"] if metadata else 0
    return data, total


async def _resolve_scan_for_findings(
    scan_id: str,
    current_user: User,
    db: Any,
) -> None:
    """Look up the scan and verify the caller can access its project."""
    scan_repo = ScanRepository(db)
    scan = await scan_repo.get_minimal_by_id(scan_id)
    if not scan or not scan.project_id:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)
    await check_project_access(scan.project_id, current_user, db)


@router.get(
    "/scans/{scan_id}/findings",
    response_model=ScanFindingsResponse,
    summary="Get scan findings with pagination",
    responses=RESP_AUTH_404,
)
async def read_scan_findings(
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    skip: Annotated[int, Query(ge=0)] = 0,
    # Cap at 500 (higher than the 100 used elsewhere) for deep-link and per-component drilldowns.
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    sort_by: str = "severity",  # severity, type, component
    sort_order: str = "desc",  # asc, desc
    type: Optional[str] = None,
    category: Optional[str] = None,  # security, secret, sast, compliance, quality
    severity: Optional[str] = None,
    search: Optional[str] = None,
    license_category: Optional[str] = None,  # permissive, weak_copyleft, strong_copyleft, etc.
    hide_info: Optional[bool] = None,  # Hide INFO severity findings
    waived: Optional[bool] = None,  # True: only waived; False: only active; None: both
) -> Dict[str, Any]:
    """Get paginated findings for a scan."""
    await _resolve_scan_for_findings(scan_id, current_user, db)

    query = _build_scan_findings_match(
        scan_id,
        type=type,
        category=category,
        severity=severity,
        search=search,
        license_category=license_category,
        hide_info=hide_info,
        waived=waived,
    )
    pipeline = _build_scan_findings_pipeline(
        query,
        sort_by=sort_by,
        sort_order=sort_order,
        skip=skip,
        limit=limit,
    )

    finding_repo = FindingRepository(db)
    result = await finding_repo.aggregate(pipeline)
    data, total = _unpack_scan_findings_facet(result)

    return build_pagination_response(data, total, skip, limit)


@router.get("/scans/{scan_id}/stats", responses=RESP_AUTH_404)
async def get_scan_stats(
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Dict[str, Any]:
    """Get finding statistics by category for a scan."""
    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)

    scan = await scan_repo.get_minimal_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)
    if not scan.project_id:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)
    await check_project_access(scan.project_id, current_user, db)

    pipeline: List[Dict[str, Any]] = [
        {"$match": {"scan_id": scan_id}},
        {MONGO_GROUP: {"_id": "$type", "count": {"$sum": 1}}},
    ]

    results = await finding_repo.aggregate(pipeline)

    return aggregate_stats_by_category(results)


def _find_project_member_index(project: Project, user_id: str) -> int:
    """Return the index of ``user_id`` within ``project.members`` or raise 404."""
    for i, member in enumerate(project.members):
        if member.user_id == user_id:
            return i
    raise HTTPException(status_code=404, detail="User is not a member of this project")


async def _count_team_admins(project: Project, db: Any) -> int:
    """Return the number of admins on the project's owning team (0 if no team)."""
    if not project.team_id:
        return 0
    team_repo = TeamRepository(db)
    team = await team_repo.get_raw_by_id(project.team_id)
    if not team:
        return 0
    return sum(1 for m in team.get("members", []) if m.get("role") == "admin")


async def _assert_not_demoting_last_admin(
    project: Project,
    member_index: int,
    member_in: ProjectMemberUpdate,
    db: Any,
) -> None:
    """Refuse to demote the final admin across direct and team membership."""
    current_member = project.members[member_index]
    is_demotion = current_member.role == "admin" and member_in.role and member_in.role != "admin"
    if not is_demotion:
        return
    direct_admin_count = sum(1 for m in project.members if m.role == "admin")
    team_admin_count = await _count_team_admins(project, db)
    if direct_admin_count + team_admin_count <= 1:
        raise HTTPException(
            status_code=400,
            detail="Cannot demote the last admin. Add another admin first.",
        )


def _build_member_update_fields(
    member_index: int,
    member_in: ProjectMemberUpdate,
) -> Dict[str, Any]:
    """Compose the Mongo ``$set`` payload for an in-place member update."""
    update_fields: Dict[str, Any] = {}
    if member_in.role:
        update_fields[f"members.{member_index}.role"] = member_in.role
    if member_in.notification_preferences:
        update_fields[f"members.{member_index}.notification_preferences"] = member_in.notification_preferences
    return update_fields


@router.put(
    "/{project_id}/members/{user_id}",
    summary="Update project member role",
    responses=RESP_AUTH_400_404,
)
async def update_project_member(
    project_id: str,
    user_id: str,
    member_in: ProjectMemberUpdate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Project:
    """Update the role of a project member. Requires 'admin' role."""
    project = await check_project_access(project_id, current_user, db, required_role="admin")

    member_index = _find_project_member_index(project, user_id)
    await _assert_not_demoting_last_admin(project, member_index, member_in, db)

    update_fields = _build_member_update_fields(member_index, member_in)
    project_repo = ProjectRepository(db)
    if update_fields:
        await project_repo.update_member(project_id, user_id, update_fields)

    updated_project = await project_repo.get_by_id(project_id)
    if not updated_project:
        raise HTTPException(status_code=404, detail=_MSG_PROJECT_NOT_FOUND)
    return updated_project


@router.delete(
    "/{project_id}/members/{user_id}",
    summary="Remove user from project",
    responses=RESP_AUTH_400_404,
)
async def remove_project_member(
    project_id: str,
    user_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Project:
    """Remove a user from the project. Requires 'admin' role."""
    project = await check_project_access(project_id, current_user, db, required_role="admin")

    member_exists = False
    for member in project.members:
        if member.user_id == user_id:
            member_exists = True
            break

    if not member_exists:
        raise HTTPException(status_code=404, detail="User is not a member of this project")

    # Block removing the last admin, counting both direct and team admins.
    member_role = next((m.role for m in project.members if m.user_id == user_id), None)
    if member_role == "admin":
        direct_admin_count = sum(1 for m in project.members if m.role == "admin")
        team_admin_count = 0
        if project.team_id:
            team_repo = TeamRepository(db)
            team = await team_repo.get_raw_by_id(project.team_id)
            if team:
                team_admin_count = sum(1 for m in team.get("members", []) if m.get("role") in ("admin"))
        total_admins = direct_admin_count + team_admin_count
        if total_admins <= 1:
            raise HTTPException(status_code=400, detail="Cannot remove the last admin. Add another admin first.")

    project_repo = ProjectRepository(db)
    await project_repo.remove_member(project_id, user_id)

    updated_project = await project_repo.get_by_id(project_id)
    if updated_project:
        return updated_project
    raise HTTPException(status_code=404, detail=_MSG_PROJECT_NOT_FOUND)


@router.get("/{project_id}/export/csv", summary="Export latest scan results as CSV", responses=RESP_AUTH_404)
async def export_project_csv(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Response:
    await check_project_access(project_id, current_user, db, required_role="viewer")

    scan_repo = ScanRepository(db)

    # Get latest scan
    scan = await scan_repo.get_latest_for_project(project_id, status="completed")

    if not scan:
        raise HTTPException(status_code=404, detail="No completed scans found for this project")

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

    # Stream from the complete findings collection, not the capped vulnerability-only
    # findings_summary, so no findings are dropped and memory stays bounded.
    finding_repo = FindingRepository(db)
    async for f_dict in finding_repo.iterate_raw(
        {"scan_id": scan.id},
        {
            "finding_id": 1,
            "component": 1,
            "version": 1,
            "type": 1,
            "severity": 1,
            "description": 1,
            "details.fixed_version": 1,
        },
    ):
        details = f_dict.get("details") or {}
        writer.writerow(
            [
                f_dict.get("component", ""),
                f_dict.get("version", ""),
                f_dict.get("type", ""),
                f_dict.get("finding_id", ""),
                f_dict.get("severity", ""),
                f_dict.get("description", ""),
                details.get("fixed_version", ""),
            ]
        )

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=project_{project_id}_scan.csv"},
    )


@router.get("/{project_id}/export/sbom", summary="Export latest SBOM", responses=RESP_AUTH_404_500)
async def export_project_sbom(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Response:
    await check_project_access(project_id, current_user, db, required_role="viewer")

    scan_repo = ScanRepository(db)

    scan = await scan_repo.get_latest_for_project(project_id, status="completed")

    if not scan:
        raise HTTPException(status_code=404, detail="No completed scans found for this project")

    if not scan.sbom_refs or len(scan.sbom_refs) == 0:
        raise HTTPException(status_code=404, detail="No SBOM data found for this scan")

    ref = scan.sbom_refs[0]
    if ref.get("storage") != "gridfs" or not ref.get("file_id"):
        raise HTTPException(status_code=500, detail="Invalid SBOM reference (not GridFS)")

    sbom_content = await load_from_gridfs(db, ref["file_id"])

    if not sbom_content:
        raise HTTPException(status_code=404, detail="SBOM file not found in GridFS")

    return Response(
        content=json.dumps(sbom_content, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=project_{project_id}_sbom.json"},
    )


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT, responses=RESP_AUTH_404)
async def delete_project(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> None:
    """Delete a project and all associated data (scans, results). Requires 'admin' role."""
    await check_project_access(project_id, current_user, db, required_role="admin")

    project_repo = ProjectRepository(db)
    scan_repo = ScanRepository(db)
    analysis_repo = AnalysisResultRepository(db)
    finding_repo = FindingRepository(db)
    dep_repo = DependencyRepository(db)
    waiver_repo = WaiverRepository(db)
    invitation_repo = InvitationRepository(db)
    callgraph_repo = CallgraphRepository(db)

    # Stream scans to collect IDs and GridFS files without loading them all at once.
    scan_ids = []
    gridfs_ids = []
    async for scan in scan_repo.iterate({"project_id": project_id}, {"_id": 1, "sbom_refs": 1}):
        scan_ids.append(scan["_id"])
        for ref in scan.get("sbom_refs", []):
            file_id = ref.get("file_id") or ref.get("gridfs_id")
            if file_id:
                gridfs_ids.append(file_id)

    if scan_ids:
        await analysis_repo.delete_many({"scan_id": {"$in": scan_ids}})
        await finding_repo.delete_many({"scan_id": {"$in": scan_ids}})
        await dep_repo.delete_many({"scan_id": {"$in": scan_ids}})

    await scan_repo.delete_many({"project_id": project_id})
    await delete_gridfs_files(db, gridfs_ids)
    await waiver_repo.delete_many({"project_id": project_id})
    await invitation_repo.delete_project_invitations_by_project(project_id)
    await callgraph_repo.delete_by_project(project_id)
    await project_repo.delete(project_id)
