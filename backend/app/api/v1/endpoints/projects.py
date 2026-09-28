import io
import json
import logging
import re
import uuid
import zipfile
from typing import Annotated, Any

from fastapi import BackgroundTasks, Depends, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from pymongo.errors import DuplicateKeyError

from app.api import deps
from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers import (
    aggregate_stats_by_category,
    apply_system_settings_enforcement,
    build_pagination_response,
    build_user_project_query,
    check_project_access,
    generate_project_api_key,
    get_category_type_filter,
    get_sort_field,
    is_write_superuser,
    last_admin_guard,
    load_from_gridfs,
    may_read_projects,
    parse_sort_direction,
    resolve_sbom_refs,
    resolve_team_names,
    team_refs,
)
from app.api.v1.helpers.auth import send_project_member_added_email
from app.api.v1.helpers.projects import (
    direct_member_role,
    effective_project_role,
    max_project_role,
    team_grant_role,
)
from app.api.v1.helpers.responses import (
    RESP_AUTH,
    RESP_AUTH_400_404,
    RESP_AUTH_400_404_409,
    RESP_AUTH_400_404_500,
    RESP_AUTH_404,
    RESP_AUTH_404_500,
)
from app.core.constants import (
    MAX_PROJECT_TEAMS,
    PROJECT_ROLE_ADMIN,
    PROJECT_ROLE_EDITOR,
    PROJECT_ROLE_VIEWER,
    SCAN_USABLE_STATUSES,
    TEAM_SOURCE_MANUAL,
    ProjectRole,
)
from app.core.log_utils import sanitize_for_log
from app.core.permissions import Permissions, has_permission
from app.core.risk_scoring import risk_score_expr
from app.core.trufflehog import SECRET_DESCRIPTION_PREFIX, resolve_detector_name
from app.core.worker import worker_manager
from app.models.project import AnalysisResult, Project, ProjectMember, Scan
from app.models.release import Release
from app.models.system import SystemSettings
from app.models.user import User
from app.repositories import (
    AnalysisResultRepository,
    CallgraphRepository,
    CryptoPolicyRepository,
    FindingRepository,
    GitHubInstanceRepository,
    InvitationRepository,
    ProjectRepository,
    ReleaseRepository,
    ScanRepository,
    TeamRepository,
    UserRepository,
    WaiverRepository,
    WebhookRepository,
)
from app.repositories.base import and_filters
from app.repositories.gitlab_instances import GitLabInstanceRepository
from app.repositories.projects import (
    literal_set_stage,
    ownership_fields,
    set_owners_pipeline,
)
from app.schemas.project import (
    BranchInfo,
    BranchTip,
    DashboardStats,
    ProjectApiKeyResponse,
    ProjectBranchTips,
    ProjectCreate,
    ProjectListEnriched,
    ProjectMemberInvite,
    ProjectMemberUpdate,
    ProjectNotificationSettings,
    ProjectUpdate,
    ProjectWithTeam,
    RecentScan,
    RiskyProject,
    ScanFindingsResponse,
    ScanHistoryResponse,
    ScanReleaseRef,
    ScanWithReleases,
)
from app.services.aggregation.components import component_match_expr
from app.services.analytics.scopes import ensure_whole_scope, scope_probe_limit
from app.services.branches import resolve_default_branch
from app.services.gitlab import GitLabService
from app.services.inventory.csv_stream import csv_response, export_filename
from app.services.inventory.findings_export import FINDINGS_COLUMNS, iter_findings_rows
from app.services.inventory.scan_resolution import latest_completed_scans_by_branch
from app.services.scan_cascade import delete_scans_and_related_data
from app.services.scan_manager import queue_rescan

router = CustomAPIRouter()
logger = logging.getLogger(__name__)

MONGO_GROUP = "$group"

_MSG_PROJECT_NOT_FOUND = "Project not found"
_MSG_TEAM_NOT_FOUND = "Team not found"
_MSG_SCAN_NOT_FOUND = "Scan not found"
_MSG_NOT_ENOUGH_PERMISSIONS = "Not enough permissions"
_MSG_ALREADY_A_MEMBER = "User already a member"
_MSG_LAST_ADMIN_REMOVE = "Cannot remove the last admin. Add another admin first."
_MSG_LAST_ADMIN_DEMOTE = "Cannot demote the last admin. Add another admin first."
_MSG_LAST_ADMIN_OWNER = "This would leave the project without an admin; add one first"
_MSG_NO_VERIFIED_USER = "No user has verified this email address"

_SCAN_HISTORY_PAGE_SIZE = 100


def _release_refs(releases: list[Release]) -> list[ScanReleaseRef]:
    return [
        ScanReleaseRef(environment=rel.environment, version=rel.version, released_at=rel.released_at)
        for rel in releases
    ]


@router.get("/dashboard/stats", response_model=DashboardStats, responses=RESP_AUTH)
async def get_dashboard_stats(
    db: DatabaseDep,
    current_user: CurrentUserDep,
) -> dict[str, Any]:
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    query = await build_user_project_query(current_user, team_repo)

    # Aggregate rather than fetch all projects, for performance.
    pipeline: list[dict[str, Any]] = [
        {"$match": query},
        {
            "$project": {
                "name": 1,
                "stats": 1,
                # Prefer persisted stats.risk_score; else the same saturating
                # severity-weighted formula used by calculate_comprehensive_stats.
                "calculated_risk": {
                    "$ifNull": [
                        "$stats.risk_score",
                        risk_score_expr(
                            {
                                "critical": "$stats.critical",
                                "high": "$stats.high",
                                "medium": "$stats.medium",
                                "low": "$stats.low",
                            }
                        ),
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

    if settings.project_limit_per_user > 0 and not has_permission(current_user.permissions, Permissions.SYSTEM_MANAGE):
        current_count = await project_repo.count(
            {"members": {"$elemMatch": {"user_id": str(current_user.id), "role": PROJECT_ROLE_ADMIN}}}
        )
        if current_count >= settings.project_limit_per_user:
            raise HTTPException(
                status_code=403,
                detail=f"Project limit reached. You can only create {settings.project_limit_per_user} projects.",
            )

    if project_in.team_id:
        await _assert_may_grant_teams({project_in.team_id}, current_user, team_repo)

    project_id = str(uuid.uuid4())
    api_key, api_key_hash = generate_project_api_key(project_id)

    # A None here would fail Project validation instead of falling back to the model default.
    retention = apply_system_settings_enforcement(
        project_in.model_dump(include={"retention_days", "retention_action"}, exclude_none=True),
        settings.retention_mode,
        settings.rescan_mode,
    )
    project = Project(
        id=project_id,
        name=project_in.name,
        # A user-chosen team is a manual assignment.
        **ownership_fields([project_in.team_id] if project_in.team_id else [], TEAM_SOURCE_MANUAL),
        api_key_hash=api_key_hash,
        active_analyzers=project_in.active_analyzers,
        analyzer_settings=project_in.analyzer_settings,
        **retention,
        members=[ProjectMember(user_id=str(current_user.id), role=PROJECT_ROLE_ADMIN)],
    )

    # api_key_hash is excluded from the model dump by default; add it back manually.
    project_data = project.model_dump(by_alias=True)
    project_data["api_key_hash"] = api_key_hash

    await project_repo.create_raw(project_data)
    await _audit_license_policy_change(db, project_id, None, project, current_user)

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

    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)

    api_key, api_key_hash = generate_project_api_key(project_id)

    await project_repo.update(project_id, {"api_key_hash": api_key_hash})

    return ProjectApiKeyResponse(project_id=project_id, api_key=api_key)


@router.get("/", response_model=ProjectListEnriched, summary="List all projects", responses=RESP_AUTH)
async def read_projects(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    search: str | None = None,
    team_id: str | None = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> dict[str, Any]:
    """Retrieve projects; superusers see all, everyone else those they are a member of or that a team of theirs owns."""
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    if not may_read_projects(current_user):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    search_query: dict[str, Any] = {}
    if search:
        search_query["name"] = {"$regex": re.escape(search), "$options": "i"}
    if team_id:
        search_query["team_ids"] = team_id

    final_query = and_filters(search_query, await build_user_project_query(current_user, team_repo))

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

    team_name_map = await resolve_team_names(db, {team_id for p in projects for team_id in p.team_ids})

    enriched_projects = []
    for p in projects:
        p_data = p.model_dump()
        p_data["teams"] = team_refs(p.team_ids, team_name_map)
        enriched_projects.append(ProjectWithTeam(**p_data))

    return build_pagination_response(enriched_projects, total, skip, limit)


@router.get(
    "/scans",
    response_model=list[RecentScan],
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
) -> list[dict[str, Any]]:
    """Retrieve scans for all projects the user has access to, with pagination and sorting."""
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)
    scan_repo = ScanRepository(db)

    if not may_read_projects(current_user):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    permission_query = await build_user_project_query(current_user, team_repo)
    projects = ensure_whole_scope(await project_repo.find_many_minimal(permission_query, limit=scope_probe_limit()))
    project_ids = [str(p.id) for p in projects]

    if not project_ids:
        return []

    direction = parse_sort_direction(sort_order)
    sort_field = get_sort_field("scans", sort_by)

    pipeline: list[dict[str, Any]] = [
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

    return await scan_repo.aggregate(pipeline, limit)


# Every owning team's member ids as one flat list. A field path across two array levels answers
# an array per team, which the $in below can never match an id against.
_OWNING_TEAM_MEMBER_IDS = {
    "$reduce": {
        "input": {"$ifNull": ["$team_data", []]},
        "initialValue": [],
        "in": {
            "$setUnion": [
                "$$value",
                {"$map": {"input": {"$ifNull": ["$$this.members", []]}, "as": "m", "in": "$$m.user_id"}},
            ]
        },
    }
}


def _merge_team_members(data: dict[str, Any], t_users: dict[str, str]) -> None:
    """Add the members the owning teams bring in, each named with every owner it comes from, and
    give every row the role check_project_access grants as ``effective_role``.

    A team role counts at the strongest any owner grants: ``team_ids`` is in whatever order the last
    writer left it and the join answers in the teams collection's, so a first-wins merge would hand a
    user who is an admin of one owner and a plain member of another a different role from one
    request to the next. Someone already named in the project's own members keeps that entry — it is
    theirs to be removed from — with its stored role.
    """
    team_roles: dict[str, ProjectRole | None] = {}
    owners: dict[str, set[str]] = {}

    # Teams by id and their names sorted below, so the same owners answer the same rows in the same
    # order and spell the same string however the join ordered them.
    for team in sorted(data.get("team_data") or [], key=lambda team: str(team.get("_id"))):
        for tm in team.get("members", []):
            uid = tm["user_id"]
            team_roles[uid] = max_project_role(team_roles.get(uid), team_grant_role(tm.get("role")))
            owners.setdefault(uid, set()).add(str(team.get("name")))

    for member in data["members"]:
        direct_role = member.get("role", PROJECT_ROLE_VIEWER)
        member["effective_role"] = max_project_role(direct_role, team_roles.pop(member["user_id"], None))

    overrides = data.get("notification_overrides") or {}
    data["members"].extend(
        {
            "user_id": uid,
            "role": role,
            "effective_role": role,
            "username": t_users.get(uid),
            "inherited_from": "Team: " + ", ".join(sorted(owners[uid])),
            "notification_preferences": overrides.get(uid) or {},
        }
        for uid, role in team_roles.items()
    )


@router.get("/{project_id}", summary="Get project details", responses=RESP_AUTH_404)
async def read_project(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Project:
    """Get a specific project by ID."""
    await check_project_access(project_id, current_user, db)
    project_repo = ProjectRepository(db)

    # Single aggregation to avoid N+1 team/user lookups. The owning teams stay an array: an array
    # localField joins many, and unwinding them would answer one copy of the project per owner.
    pipeline: list[dict[str, Any]] = [
        {"$match": {"_id": project_id}},
        {
            "$lookup": {
                "from": "teams",
                "localField": "team_ids",
                "foreignField": "_id",
                "as": "team_data",
            }
        },
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
                "let": {"team_member_ids": _OWNING_TEAM_MEMBER_IDS},
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

    return Project(**data)


async def _assert_may_grant_teams(gained: set[str], current_user: User, team_repo: TeamRepository) -> None:
    """Refuse handing the project to a team that does not exist (404) or, short of a write
    superuser, that the caller is not a member of (403).

    An id nothing resolves to grants nobody anything and no sync would ever reap it, so it is
    refused whoever asks.
    """
    teams = await team_repo.members_by_team(sorted(gained))
    for team_id in sorted(gained):
        if team_id not in teams:
            raise HTTPException(status_code=404, detail=_MSG_TEAM_NOT_FOUND)
        if not is_write_superuser(current_user) and all(
            m.get("user_id") != str(current_user.id) for m in teams[team_id]
        ):
            raise HTTPException(status_code=403, detail="You are not a member of the target team")


_GITLAB_BINDING_KEYS = ("gitlab_instance_id", "gitlab_project_id")


def _may_bind_gitlab(user: User) -> bool:
    return is_write_superuser(user) or has_permission(user.permissions, Permissions.SYSTEM_MANAGE)


async def _vet_gitlab_binding(
    project: Project,
    update_data: dict[str, Any],
    current_user: User,
    db: Any,
) -> None:
    """OIDC ingest resolves a pipeline's project by this binding alone, so setting one is an estate admin's call."""
    # Clients resend the stored binding with every update, so only a changed value counts.
    changed = [
        update_data[key]
        for key in _GITLAB_BINDING_KEYS
        if key in update_data and update_data[key] != getattr(project, key)
    ]
    if not changed:
        return
    if any(value is not None for value in changed) and not _may_bind_gitlab(current_user):
        raise HTTPException(status_code=403, detail="Only administrators can bind a project to a GitLab project")

    instance_id = update_data.get("gitlab_instance_id", project.gitlab_instance_id)
    gitlab_project_id = update_data.get("gitlab_project_id", project.gitlab_project_id)
    if instance_id is None and gitlab_project_id is None:
        return
    if instance_id is None or gitlab_project_id is None:
        raise HTTPException(
            status_code=400,
            detail="A GitLab binding needs both the instance and the project id; clear both to unbind",
        )

    instance = await GitLabInstanceRepository(db).get_by_id(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail=f"GitLab instance with ID {instance_id} not found")
    details = await GitLabService(instance).get_project_details(gitlab_project_id)
    if details and details.path_with_namespace:
        update_data["gitlab_project_path"] = details.path_with_namespace


async def _assert_gitlab_mr_token_present(
    project: Project,
    update_data: dict[str, Any],
    db: Any,
) -> None:
    """Reject MR-decoration enablement when the linked GitLab instance lacks a token."""
    mr_enabled = update_data.get("gitlab_mr_comments_enabled", project.gitlab_mr_comments_enabled)
    instance_id = update_data.get("gitlab_instance_id", project.gitlab_instance_id)
    if not (mr_enabled and instance_id):
        return
    gitlab_instance = await GitLabInstanceRepository(db).get_by_id(instance_id)
    if gitlab_instance and not gitlab_instance.access_token:
        raise HTTPException(
            status_code=400,
            detail="Cannot enable MR decoration: the linked GitLab instance has no access token configured",
        )


async def _assert_github_pr_token_present(
    project: Project,
    update_data: dict[str, Any],
    db: Any,
) -> None:
    """Reject PR-decoration enablement when the linked GitHub instance lacks a token."""
    # The link is set by OIDC ingest, never by an update body, so unlike its GitLab twin this has no
    # in-UI escape hatch: reading a stored true back would lock the project out of every unrelated
    # edit. Only an explicit enable is refused; decorate_github_pr re-checks the token at scan time.
    if not (update_data.get("github_pr_comments_enabled") and project.github_instance_id):
        return

    github_instance = await GitHubInstanceRepository(db).get_by_id(project.github_instance_id)
    if github_instance and not github_instance.access_token:
        raise HTTPException(
            status_code=400,
            detail="Cannot enable PR decoration: the linked GitHub instance has no access token configured",
        )


async def _audit_license_policy_change(
    db: Any,
    project_id: str,
    old_license_policy: dict[str, Any] | None,
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
        logging.getLogger(__name__).exception(
            "License-policy audit for project %s failed (non-blocking)", sanitize_for_log(project_id)
        )


@router.put("/{project_id}", summary="Update project details", responses=RESP_AUTH_400_404_409)
async def update_project(
    project_id: str,
    project_in: ProjectUpdate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Project:
    """Update project details (name, owning teams, active analyzers). Requires 'admin' role."""
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    project = await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)

    update_data = dict(project_in.model_dump(exclude_unset=True))
    # The picker sends every owner it showed, a sync's included, so the write keeps each retained
    # owner's provenance rather than claiming the lot as hand-assigned.
    ownership_stages: list[dict] = []
    guard: dict[str, Any] = {}
    if "team_ids" in update_data:
        chosen = set(update_data.pop("team_ids") or [])
        if len(chosen) > MAX_PROJECT_TEAMS:
            raise HTTPException(status_code=400, detail=f"A project may be owned by at most {MAX_PROJECT_TEAMS} teams")
        # An owner the project already holds was granted by an earlier write; re-checking it would
        # stop an admin of one owner from editing the rest.
        await _assert_may_grant_teams(chosen - set(project.team_ids), current_user, team_repo)
        ownership_stages = set_owners_pipeline(sorted(chosen))
        guard = await last_admin_guard(project, current_user, team_repo, surviving_owners=chosen)
    await _vet_gitlab_binding(project, update_data, current_user, db)
    await _assert_gitlab_mr_token_present(project, update_data, db)
    await _assert_github_pr_token_present(project, update_data, db)

    system_settings = await deps.get_system_settings(db)
    update_data = apply_system_settings_enforcement(
        update_data,
        system_settings.retention_mode,
        system_settings.rescan_mode,
    )

    # Capture the pre-update license policy so we can audit transitions.
    old_license_policy = _resolve_license_policy(project)

    stages = ([literal_set_stage(update_data)] if update_data else []) + ownership_stages
    try:
        written = not stages or await project_repo.update_raw(project_id, stages, guard)
    except DuplicateKeyError as exc:
        # The GitLab binding is the only unique key an update body can write.
        bound_id = update_data.get("gitlab_project_id", project.gitlab_project_id)
        raise HTTPException(
            status_code=409, detail=f"GitLab project {bound_id} is already bound to another project"
        ) from exc
    # An unguarded write matching nothing means the project is gone, which the read below answers.
    if not written and guard:
        raise HTTPException(status_code=400, detail=_MSG_LAST_ADMIN_OWNER)

    updated_project = await project_repo.get_by_id_strong(project_id)
    if not updated_project:
        raise HTTPException(status_code=404, detail=_MSG_PROJECT_NOT_FOUND)

    await _audit_license_policy_change(db, project_id, old_license_policy, updated_project, current_user)
    return updated_project


def _resolve_license_policy(project: Project) -> dict[str, Any] | None:
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


async def _branch_infos(db: Any, project: Project) -> list[BranchInfo]:
    """Every branch the project has scans on, with its active/deleted status and the default."""
    times = await ScanRepository(db).branch_scan_times(str(project.id))
    deleted = set(project.deleted_branches)
    default_branch = resolve_default_branch(
        project.default_branch,
        [b for b in times if b not in deleted],
        {branch: last_usable for branch, (_, last_usable) in times.items()},
    )
    return [
        BranchInfo(name=b, is_active=b not in deleted, last_scan_at=times[b][0], is_default=b == default_branch)
        for b in sorted(times)
    ]


@router.get(
    "/{project_id}/branches",
    summary="List project branches",
    responses=RESP_AUTH_404,
)
async def read_project_branches(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> list[BranchInfo]:
    """Get all unique branches for a project with their active/deleted status."""
    return await _branch_infos(db, await check_project_access(project_id, current_user, db))


@router.post(
    "/{project_id}/sync-branches",
    summary="Sync branch status from VCS",
    responses=RESP_AUTH_400_404,
)
async def sync_project_branches_endpoint(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> list[BranchInfo]:
    """Trigger branch status sync against the VCS provider for a project."""
    project = await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_EDITOR)

    if not project.gitlab_instance_id and not project.github_instance_id:
        raise HTTPException(status_code=400, detail="Project has no VCS connection configured")

    from app.core.housekeeping import sync_project_branches

    await sync_project_branches(project.model_dump(by_alias=True), db)

    # The sync rewrote deleted_branches and default_branch, so the listing reads the result.
    synced = await ProjectRepository(db).get_by_id_strong(project_id)
    if not synced:
        raise HTTPException(status_code=404, detail=_MSG_PROJECT_NOT_FOUND)
    return await _branch_infos(db, synced)


async def _with_releases(db: Any, docs: list[dict[str, Any]]) -> list[ScanWithReleases]:
    """The scans, each carrying the environments it was released to."""
    by_scan = await ReleaseRepository(db).group_by_scan([doc["_id"] for doc in docs])
    return [ScanWithReleases(**{**doc, "releases": _release_refs(by_scan.get(doc["_id"], []))}) for doc in docs]


@router.get("/{project_id}/scans", summary="List project scans", responses=RESP_AUTH_404)
async def read_project_scans(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    branch: str | None = None,
    exclude_deleted_branches: bool = False,
    exclude_rescans: bool = False,
    is_release: bool | None = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> list[ScanWithReleases]:
    """Get scans for a project, each carrying the environments it was released to."""
    project = await check_project_access(project_id, current_user, db)

    scan_repo = ScanRepository(db)

    query: dict[str, Any] = {"project_id": project_id}
    if branch:
        query["branch"] = branch
    elif exclude_deleted_branches and project.deleted_branches:
        query["branch"] = {"$nin": project.deleted_branches}

    if exclude_rescans:
        query["is_rescan"] = {"$ne": True}

    if is_release is not None:
        # Tri-state: scans predating the mark carry no field and are not releases.
        query["is_release"] = True if is_release else {"$ne": True}

    direction = parse_sort_direction(sort_order)
    sort_field = get_sort_field("project_scans", sort_by)

    scan_docs = await scan_repo.find_many_raw(
        query,
        sort=[(sort_field, direction)],
        skip=skip,
        limit=limit,
    )

    return await _with_releases(db, scan_docs)


@router.get("/{project_id}/scans/branch-tips", summary="Branch tips and scan counts", responses=RESP_AUTH_404)
async def read_project_branch_tips(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ProjectBranchTips:
    """Every branch's representative scan and scan count, plus the newest release-flagged scan.

    A page of the scan list answers neither: a branch whose newest scan fell off the page
    disappears from it, and a release marked before the page begins reads as no release.
    """
    project = await check_project_access(project_id, current_user, db)

    deleted = list(project.deleted_branches or [])
    scan_repo = ScanRepository(db)
    tips = await scan_repo.branch_tips(project_id, deleted)

    flagged_query: dict[str, Any] = {
        "project_id": project_id,
        "is_release": True,
        "status": {"$in": SCAN_USABLE_STATUSES},
    }
    if deleted:
        flagged_query["branch"] = {"$nin": deleted}
    flagged_doc = await scan_repo.find_one(flagged_query, sort=[("created_at", -1), ("_id", 1)])

    flagged = (await _with_releases(db, [flagged_doc]))[0] if flagged_doc else None

    return ProjectBranchTips(
        branches=[
            BranchTip(branch=branch, scan_count=count, tip=Scan(**tip) if tip else None) for branch, count, tip in tips
        ],
        flagged_release_scan=flagged,
    )


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
    """Re-analyse the scan's SBOMs as a new scan, or return the rescan of its lineage already queued."""
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_EDITOR)

    scan = await ScanRepository(db).find_one({"_id": scan_id, "project_id": project_id})
    if not scan:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)

    if not scan.get("sbom_refs"):
        raise HTTPException(status_code=400, detail="Cannot re-scan: No SBOMs found in the source scan.")

    if not worker_manager:
        raise HTTPException(status_code=500, detail="Worker manager not available")
    return await queue_rescan(db, scan, project_id, worker_manager)


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
) -> ScanHistoryResponse:
    """Get a scan's history (original plus all re-scans), newest first.

    Housekeeping re-scans a branch tip every ``global_rescan_interval`` hours, so a
    long-lived scan outgrows one page; ``total`` is counted over the lineage.
    """
    await check_project_access(project_id, current_user, db)

    scan_repo = ScanRepository(db)

    scan = await scan_repo.find_one({"_id": scan_id, "project_id": project_id})
    if not scan:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)

    root_id = scan.get("original_scan_id") or scan_id
    lineage: dict[str, Any] = {
        "project_id": project_id,
        "$or": [{"_id": root_id}, {"original_scan_id": root_id}],
    }

    return ScanHistoryResponse(
        runs=await scan_repo.find_many(lineage, sort=[("created_at", -1)], limit=_SCAN_HISTORY_PAGE_SIZE),
        total=await scan_repo.count(lineage),
        page_size=_SCAN_HISTORY_PAGE_SIZE,
    )


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
    project_repo = ProjectRepository(db)
    user_id = str(current_user.id)

    role = await effective_project_role(project, current_user, TeamRepository(db))
    may_enforce = role == PROJECT_ROLE_ADMIN or is_write_superuser(current_user)

    if settings.enforce_notification_settings is not None and may_enforce:
        await project_repo.update_raw(
            project_id, {"$set": {"enforce_notification_settings": settings.enforce_notification_settings}}
        )
    elif project.enforce_notification_settings and not may_enforce:
        raise HTTPException(status_code=403, detail="Notification settings are enforced by the project admin")

    if direct_member_role(project, user_id) is not None:
        await project_repo.update_member(
            project_id, user_id, {"notification_preferences": settings.notification_preferences}
        )
    elif role is not None:
        # A team grants the access, so the preferences live beside the members rather than in a
        # member entry that would outlive the team membership.
        await project_repo.update_raw(
            project_id, {"$set": {f"notification_overrides.{user_id}": settings.notification_preferences}}
        )
    elif not may_enforce:
        raise HTTPException(status_code=400, detail="You must be a member or admin to set notification preferences")

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
) -> dict[str, Any]:
    """Add the existing user that verified this email (404 if none did; use system invitations for new users)."""
    project = await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)

    user_repo = UserRepository(db)
    project_repo = ProjectRepository(db)

    user_to_add = await user_repo.get_raw_by_verified_email(invite_in.email)
    if not user_to_add:
        raise HTTPException(status_code=404, detail=_MSG_NO_VERIFIED_USER)

    member = ProjectMember(user_id=str(user_to_add["_id"]), role=invite_in.role)

    if not await project_repo.add_member(project_id, member.model_dump()):
        raise HTTPException(status_code=400, detail=_MSG_ALREADY_A_MEMBER)

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
) -> list[AnalysisResult]:
    """Get the results of all analyzers for a specific scan."""
    await _require_scan_access(scan_id, current_user, db)
    return await AnalysisResultRepository(db).find_by_scan(scan_id)


@router.get("/scans/{scan_id}", summary="Get scan details", responses=RESP_AUTH_404)
async def read_scan(
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ScanWithReleases:
    """Get details of a specific scan and the environments it runs in; SBOMs are excluded
    (fetch them via /scans/{scan_id}/sboms)."""
    scan = await _load_scan_with_access(scan_id, current_user, db)
    return (await _with_releases(db, [scan.model_dump(by_alias=True)]))[0]


@router.get(
    "/scans/{scan_id}/sboms",
    summary="Get raw SBOMs for a scan",
    responses=RESP_AUTH_404,
)
async def read_scan_sboms(
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> list[dict[str, Any]]:
    """Get raw SBOM data for a scan, resolved from GridFS on demand."""
    sbom_refs = (await _load_scan_with_access(scan_id, current_user, db)).sbom_refs or []

    if not sbom_refs:
        raise HTTPException(status_code=404, detail="No SBOM data available for this scan")

    return await resolve_sbom_refs(db, sbom_refs)


def _build_scan_findings_match(
    scan_id: str,
    *,
    type: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    license_category: str | None = None,
    hide_info: bool | None = None,
    waived: bool | None = None,
    hide_historical_secrets: bool | None = None,
) -> dict[str, Any]:
    """Compose the $match stage for the scan-findings aggregation."""
    query: dict[str, Any] = {"scan_id": scan_id}

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
    if hide_historical_secrets:
        # Drop secrets no longer in the current tree; unknown-tree (field absent) stays visible.
        query["$nor"] = [{"type": "secret", "details.in_current_tree": False}]
    if search:
        escaped_search = re.escape(search)
        query["$or"] = [
            {"component": {"$regex": escaped_search, "$options": "i"}},
            {"finding_id": {"$regex": escaped_search, "$options": "i"}},
            {"description": {"$regex": escaped_search, "$options": "i"}},
        ]
    return query


def _scan_findings_lookup_stage() -> dict[str, Any]:
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
                                component_match_expr("$name", "$$component"),
                                {"$eq": ["$version", "$$version"]},
                            ]
                        }
                    }
                },
                # Exact spelling first so a qualified finding never takes a same-artifact
                # sibling's row when both are present.
                {"$addFields": {"_exact": {"$eq": ["$name", "$$component"]}}},
                {"$sort": {"_exact": -1}},
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


def _scan_findings_add_fields_stage() -> dict[str, Any]:
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
_SCAN_FINDINGS_SORT_FIELDS: dict[str, str] = {
    "severity": "severity",
    "component": "component",
    "type": "type",
    "source_type": "source_type",
    "finding_id": "finding_id",
    "vuln_id": "finding_id",  # UI alias -> real field
    "scanner": "first_scanner",  # UI alias -> computed scalar
}


def _scan_findings_sort_stage(sort_by: str, sort_order: str) -> dict[str, Any]:
    """Compose the $sort stage, always ending with the unique _id tiebreaker so skip/limit pagination is stable (finding_id is not unique within a scan)."""
    sort_dir = -1 if sort_order == "desc" else 1
    field = _SCAN_FINDINGS_SORT_FIELDS.get(sort_by, "severity")
    if field == "severity":
        return {"$sort": {"severity_rank": sort_dir, "component": 1, "_id": 1}}
    sort_spec: dict[str, Any] = {field: sort_dir}
    if field != "_id":
        sort_spec["_id"] = 1
    return {"$sort": sort_spec}


def _build_scan_findings_pipeline(
    query: dict[str, Any],
    *,
    sort_by: str,
    sort_order: str,
    skip: int,
    limit: int,
    direct_only: bool = False,
) -> list[dict[str, Any]]:
    """Compose the full aggregation pipeline used by ``read_scan_findings``."""
    stages: list[dict[str, Any]] = [
        {"$match": query},
        _scan_findings_lookup_stage(),
        _scan_findings_add_fields_stage(),
    ]
    if direct_only:
        # Drop known-transitive findings; direct=null (code findings / unmatched packages) stays visible.
        stages.append({"$match": {"direct": {"$ne": False}}})
    stages += [
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
    return stages


def _resolve_secret_detectors(rows: list[dict[str, Any]]) -> None:
    """Show trufflehog detector names instead of the stored DetectorType ordinals.

    Resolved for display only: the ordinal is baked into ``finding_id`` and into every
    secret waiver's ``match.rule_key``, so rewriting it in place would un-suppress them.
    """
    for row in rows:
        details = row.get("details")
        if not isinstance(details, dict):
            continue
        raw = details.get("detector")
        name = resolve_detector_name(raw)
        if name is None:
            continue
        details["detector"] = name
        if row.get("description") == f"{SECRET_DESCRIPTION_PREFIX}{raw}":
            row["description"] = f"{SECRET_DESCRIPTION_PREFIX}{name}"


def _unpack_scan_findings_facet(result: list[dict[str, Any]]) -> tuple:
    """Pull ``(data, total)`` out of the ``$facet`` result envelope."""
    if not result:
        return [], 0
    bucket = result[0]
    data = bucket.get("data") or []
    metadata = bucket.get("metadata") or []
    total = metadata[0]["total"] if metadata else 0
    return data, total


async def _require_scan_access(scan_id: str, current_user: User, db: Any) -> None:
    """404 for an unknown scan, else the caller must be able to read its project."""
    scan = await ScanRepository(db).get_minimal_by_id(scan_id)
    if not scan or not scan.project_id:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)
    await check_project_access(scan.project_id, current_user, db)


async def _load_scan_with_access(scan_id: str, current_user: User, db: Any) -> Scan:
    """The whole scan, once the caller is shown to read its project."""
    scan = await ScanRepository(db).get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)
    await check_project_access(scan.project_id, current_user, db)
    return scan


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
    type: str | None = None,
    category: str | None = None,  # security, secret, sast, compliance, quality
    severity: str | None = None,
    search: str | None = None,
    license_category: str | None = None,  # permissive, weak_copyleft, strong_copyleft, etc.
    hide_info: bool | None = None,  # Hide INFO severity findings
    waived: bool | None = None,  # True: only waived; False: only active; None: both
    direct_only: bool | None = None,  # Hide findings on transitive dependencies
    hide_historical_secrets: bool | None = None,  # Hide secrets no longer in the current git tree
) -> dict[str, Any]:
    """Get paginated findings for a scan."""
    await _require_scan_access(scan_id, current_user, db)

    query = _build_scan_findings_match(
        scan_id,
        type=type,
        category=category,
        severity=severity,
        search=search,
        license_category=license_category,
        hide_info=hide_info,
        waived=waived,
        hide_historical_secrets=hide_historical_secrets,
    )
    pipeline = _build_scan_findings_pipeline(
        query,
        sort_by=sort_by,
        sort_order=sort_order,
        skip=skip,
        limit=limit,
        direct_only=bool(direct_only),
    )

    finding_repo = FindingRepository(db)
    result = await finding_repo.aggregate(pipeline)
    data, total = _unpack_scan_findings_facet(result)
    _resolve_secret_detectors(data)

    return build_pagination_response(data, total, skip, limit)


@router.get("/scans/{scan_id}/stats", responses=RESP_AUTH_404)
async def get_scan_stats(
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Get finding statistics by category for a scan."""
    await _require_scan_access(scan_id, current_user, db)
    finding_repo = FindingRepository(db)

    pipeline: list[dict[str, Any]] = [
        {"$match": {"scan_id": scan_id}},
        {MONGO_GROUP: {"_id": "$type", "count": {"$sum": 1}}},
    ]

    results = await finding_repo.aggregate(pipeline)

    return aggregate_stats_by_category(results)


def _ensure_direct_member(project: Project, user_id: str) -> None:
    if direct_member_role(project, user_id) is None:
        raise HTTPException(status_code=404, detail="User is not a member of this project")


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
    project = await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)
    _ensure_direct_member(project, user_id)

    leaving = user_id if member_in.role != PROJECT_ROLE_ADMIN else None
    guard = await last_admin_guard(project, current_user, TeamRepository(db), leaving_member=leaving)
    project_repo = ProjectRepository(db)
    if not await project_repo.update_member(project_id, user_id, {"role": member_in.role}, guard):
        raise HTTPException(status_code=400, detail=_MSG_LAST_ADMIN_DEMOTE)

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
    project = await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)
    _ensure_direct_member(project, user_id)

    guard = await last_admin_guard(project, current_user, TeamRepository(db), leaving_member=user_id)
    project_repo = ProjectRepository(db)
    if not await project_repo.remove_member(project_id, user_id, guard):
        raise HTTPException(status_code=400, detail=_MSG_LAST_ADMIN_REMOVE)

    updated_project = await project_repo.get_by_id(project_id)
    if updated_project:
        return updated_project
    raise HTTPException(status_code=404, detail=_MSG_PROJECT_NOT_FOUND)


@router.get(
    "/{project_id}/export/csv",
    summary="Export findings of the latest scan per active branch as CSV",
    responses=RESP_AUTH_404,
)
async def export_project_csv(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> StreamingResponse:
    project = await check_project_access(project_id, current_user, db)

    scans = await latest_completed_scans_by_branch(db, project)
    if not scans:
        raise HTTPException(status_code=404, detail="No completed scans found on any active branch")

    return csv_response(
        export_filename(project.name, "findings"),
        FINDINGS_COLUMNS,
        iter_findings_rows(db, scans),
    )


@router.get("/{project_id}/export/sbom", summary="Export latest SBOM", responses=RESP_AUTH_404_500)
async def export_project_sbom(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Response:
    project = await check_project_access(project_id, current_user, db)

    scan = await ScanRepository(db).get_latest_active_scan(project)

    if not scan:
        raise HTTPException(status_code=404, detail="No completed scans found for this project")

    if not scan.sbom_refs or len(scan.sbom_refs) == 0:
        raise HTTPException(status_code=404, detail="No SBOM data found for this scan")

    sbom_contents: list[Any] = []
    for ref in scan.sbom_refs:
        if ref.get("storage") != "gridfs" or not ref.get("file_id"):
            raise HTTPException(status_code=500, detail="Invalid SBOM reference (not GridFS)")
        sbom_content = await load_from_gridfs(db, ref["file_id"])
        if not sbom_content:
            raise HTTPException(status_code=404, detail="SBOM file not found in GridFS")
        sbom_contents.append(sbom_content)

    if len(sbom_contents) == 1:
        return Response(
            content=json.dumps(sbom_contents[0], indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=project_{project_id}_sbom.json"},
        )

    # Multi-SBOM scans export every SBOM, not just the first upload.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for index, sbom_content in enumerate(sbom_contents):
            archive.writestr(f"sbom-{index + 1}.json", json.dumps(sbom_content, indent=2))
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=project_{project_id}_sboms.zip"},
    )


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT, responses=RESP_AUTH_404)
async def delete_project(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> None:
    """Delete a project and all associated data (scans, results). Requires 'admin' role or project:delete."""
    await check_project_access(
        project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN, global_permission=Permissions.PROJECT_DELETE
    )

    project_repo = ProjectRepository(db)
    scan_repo = ScanRepository(db)
    waiver_repo = WaiverRepository(db)
    invitation_repo = InvitationRepository(db)
    callgraph_repo = CallgraphRepository(db)
    release_repo = ReleaseRepository(db)

    # Streamed rather than read whole; the shared cascade owns which collections a scan takes with it.
    scan_ids = [scan["_id"] async for scan in scan_repo.iterate({"project_id": project_id}, {"_id": 1})]
    await delete_scans_and_related_data(db, scan_ids)

    await waiver_repo.delete_many({"project_id": project_id})
    await release_repo.delete_many({"project_id": project_id})
    await invitation_repo.delete_project_invitations_by_project(project_id)
    await callgraph_repo.delete_by_project(project_id)
    await WebhookRepository(db).delete_many({"project_id": project_id})
    await CryptoPolicyRepository(db).delete_project_policy(project_id)
    await project_repo.delete(project_id)
