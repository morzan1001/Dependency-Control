import logging
import re
import uuid
import zipfile
from contextlib import ExitStack
from functools import partial
from tempfile import SpooledTemporaryFile
from typing import Annotated, Any

from bson import ObjectId
from fastapi import BackgroundTasks, Depends, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from gridfs import DEFAULT_CHUNK_SIZE
from gridfs.errors import NoFile
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pymongo.errors import DuplicateKeyError
from starlette.background import BackgroundTask

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
    get_user_project_ids,
    is_write_superuser,
    last_admin_guard,
    may_read_projects,
    parse_sort_direction,
    resolve_team_names,
    team_refs,
)
from app.api.v1.helpers.auth import send_project_member_added_email
from app.api.v1.helpers.projects import (
    direct_member_role,
    effective_project_role,
    load_project_with_members,
    reject_unknown_analyzers,
)
from app.api.v1.helpers.sorting import SortOrderQuery
from app.api.v1.helpers.responses import (
    RESP_AUTH,
    RESP_AUTH_400_404,
    RESP_AUTH_400_404_409,
    RESP_AUTH_400_404_409_500,
    RESP_AUTH_404,
    RESP_AUTH_404_500,
    RESP_502,
)
from app.core.constants import (
    MAX_PROJECT_TEAMS,
    PROJECT_ROLE_ADMIN,
    PROJECT_ROLE_EDITOR,
    SCAN_ACTIVE_STATUSES,
    SEVERITY_ORDER,
    TEAM_SOURCE_MANUAL,
)
from app.core.log_utils import sanitize_for_log
from app.core.permissions import Permissions, has_permission
from app.core.risk_scoring import risk_score_expr
from app.core.worker import worker_manager
from app.db.mongodb import open_gridfs_download_with_retry
from app.models.project import AnalysisResult, Project, ProjectMember, Scan
from app.models.release import Release
from app.models.system import SystemSettings
from app.models.user import User
from app.repositories.analysis_results import RESULT_PROJECTION, AnalysisResultRepository
from app.repositories.base import and_filters
from app.repositories.callgraphs import CallgraphRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.repositories.findings import FindingRepository
from app.repositories.github_instances import GitHubInstanceRepository
from app.repositories.invitations import InvitationRepository
from app.repositories.projects import ProjectRepository
from app.repositories.releases import ReleaseRepository
from app.repositories.scans import BRANCH_SCAN_FILTER, ScanRepository
from app.repositories.teams import TeamRepository
from app.repositories.users import UserRepository
from app.repositories.waivers import WaiverRepository
from app.repositories.webhooks import WebhookRepository
from app.repositories.gitlab_instances import GitLabInstanceRepository
from app.repositories.projects import (
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
    license_policy_from_settings,
)
from app.services.branch_sync import sync_project_branches
from app.services.component_identity import component_match_expr
from app.services.gitlab import GitLabService
from app.services.gridfs_maintenance import (
    extract_gridfs_ids_from_refs,
    gridfs_lengths,
    gridfs_ref_id,
    iter_gridfs_chunks,
)
from app.services.inventory.csv_stream import csv_response, export_filename
from app.services.inventory.findings_export import FINDINGS_COLUMNS, ExportedScan, iter_findings_rows
from app.services.rescan import create_rescan
from app.services.scan_cascade import delete_scans_and_related_data

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
_EXPORT_SPOOL_MAX_MEMORY = 8 * 1024 * 1024


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
    reject_unknown_analyzers(project_in.active_analyzers)
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

    await project_repo.update_raw(project_id, {"$set": {"api_key_hash": api_key_hash}})

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
    sort_order: SortOrderQuery = "desc",
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
    sort_order: SortOrderQuery = "desc",
) -> list[dict[str, Any]]:
    """Retrieve scans for all projects the user has access to, with pagination and sorting."""
    if not may_read_projects(current_user):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    project_ids = await get_user_project_ids(current_user, db)
    if not project_ids:
        return []

    direction = parse_sort_direction(sort_order)
    sort_field = get_sort_field("scans", sort_by)

    pipeline: list[dict[str, Any]] = [
        # A rescan carries an old pipeline number under today's date, so it would read as a fresh run.
        {"$match": {"project_id": {"$in": project_ids}, "is_rescan": {"$ne": True}}},
        {"$sort": dict(_scan_page_sort(sort_field, direction))},
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

    return await ScanRepository(db).aggregate(pipeline, limit)


@router.get("/{project_id}", summary="Get project details", responses=RESP_AUTH_404)
async def read_project(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Project:
    """Get a specific project by ID."""
    await check_project_access(project_id, current_user, db)
    data = await load_project_with_members(db, project_id)
    if data is None:
        raise HTTPException(status_code=404, detail=_MSG_PROJECT_NOT_FOUND)
    return Project(**data)


async def _reload_project(project_repo: ProjectRepository, project_id: str) -> Project:
    """The stored project a write endpoint answers with."""
    project = await project_repo.get_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail=_MSG_PROJECT_NOT_FOUND)
    return project


async def _assert_may_grant_teams(gained: set[str], current_user: User, team_repo: TeamRepository) -> None:
    """404 for a team that does not exist (whoever asks); 403 unless the caller is a member or a write superuser."""
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
    old_project: Project | None,
    updated_project: Project,
    actor: User,
) -> None:
    """Record a best-effort license-policy audit entry; never blocks the caller."""
    try:
        from app.schemas.policy_audit import PolicyAuditAction
        from app.services.audit.history import record_license_policy_change

        old_entry = (old_project.analyzer_settings or {}).get("license_compliance") if old_project else None
        new_entry = (updated_project.analyzer_settings or {}).get("license_compliance")
        await record_license_policy_change(
            db,
            project_id=project_id,
            old_policy=license_policy_from_settings(old_entry).model_dump(),
            new_policy=license_policy_from_settings(new_entry).model_dump(),
            action=PolicyAuditAction.UPDATE if old_entry else PolicyAuditAction.CREATE,
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
    reject_unknown_analyzers(update_data.get("active_analyzers"))
    # The picker sends every owner it showed, a sync's included, so the write keeps each retained
    # owner's provenance rather than claiming the lot as hand-assigned.
    ownership_stages: list[dict] = []
    guard: dict[str, Any] = {}
    if "team_ids" in update_data:
        chosen = set(update_data.pop("team_ids") or [])
        if len(chosen) > MAX_PROJECT_TEAMS:
            raise HTTPException(status_code=400, detail=f"A project may be owned by at most {MAX_PROJECT_TEAMS} teams")
        # Re-checking owners already held would stop an admin of one owner from editing the rest.
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

    try:
        written = await project_repo.update_fields_and_owners(project_id, update_data, ownership_stages, guard)
    except DuplicateKeyError as exc:
        # The GitLab binding is the only unique key an update body can write.
        bound_id = update_data.get("gitlab_project_id", project.gitlab_project_id)
        raise HTTPException(
            status_code=409, detail=f"GitLab project {bound_id} is already bound to another project"
        ) from exc
    # An unguarded write matching nothing means the project is gone, which the read below answers.
    if not written and guard:
        raise HTTPException(status_code=400, detail=_MSG_LAST_ADMIN_OWNER)

    updated_project = await _reload_project(project_repo, project_id)
    if updated_project.default_branch != project.default_branch:
        await ScanRepository(db).sync_project_head(project_id)
        updated_project = await _reload_project(project_repo, project_id)
    await _audit_license_policy_change(db, project_id, project, updated_project, current_user)
    return updated_project


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
    """Every branch the project's scans name, with its active/deleted status; the default is the
    branch head resolves to, so the view opens on what the project tile reports."""
    project = await check_project_access(project_id, current_user, db)
    scan_repo = ScanRepository(db)

    rows = await scan_repo.aggregate(
        [
            {"$match": {"project_id": project_id, **BRANCH_SCAN_FILTER}},
            {MONGO_GROUP: {"_id": "$branch", "last_scan_at": {"$max": "$created_at"}}},
        ]
    )
    last_scans = {row["_id"]: row["last_scan_at"] for row in rows if isinstance(row["_id"], str) and row["_id"]}
    deleted = set(project.deleted_branches or [])
    active = [branch for branch in sorted(last_scans) if branch not in deleted]

    head = await scan_repo.get_latest_active_scan(project)
    default_branch = head.branch if head and head.branch in active else next(iter(active), None)

    return [
        BranchInfo(
            name=branch,
            is_active=branch not in deleted,
            last_scan_at=last_scans[branch],
            is_default=branch == default_branch,
        )
        for branch in sorted(last_scans)
    ]


@router.post(
    "/{project_id}/sync-branches",
    summary="Sync branch status from VCS",
    responses={**RESP_AUTH_400_404, **RESP_502},
)
async def sync_project_branches_endpoint(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> list[BranchInfo]:
    """Trigger branch status sync against the VCS provider for a project."""
    project = await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_EDITOR)
    linked_gitlab = project.gitlab_instance_id and project.gitlab_project_id
    if not linked_gitlab and not (project.github_instance_id and project.github_repository_path):
        raise HTTPException(status_code=400, detail="Project has no VCS connection configured")

    if not await sync_project_branches(project.model_dump(by_alias=True), db):
        raise HTTPException(status_code=502, detail="The VCS could not be reached or listed no branches")

    return await read_project_branches(project_id, current_user, db)


async def _with_releases(db: Any, docs: list[dict[str, Any]]) -> list[ScanWithReleases]:
    """The scans, each carrying the environments it was released to."""
    by_scan = await ReleaseRepository(db).group_by_scan([doc["_id"] for doc in docs])
    return [ScanWithReleases(**{**doc, "releases": _release_refs(by_scan.get(doc["_id"], []))}) for doc in docs]


def _scan_page_sort(field: str, direction: int) -> list[tuple[str, int]]:
    """Break ties so pages neither repeat nor skip scans, on keys an existing index already serves."""
    if field == "created_at":
        return [("created_at", direction)]
    if field == "status":
        # SCANS_TIP_INDEX_KEY walks (status, created_at desc, _id asc) in either direction.
        return [("status", direction), ("created_at", -direction), ("_id", direction)]
    if field == "branch":
        return [("branch", direction), ("created_at", -direction)]
    # Nothing indexes these, so the sort is blocking anyway and the extra keys cost nothing.
    return [(field, direction), ("created_at", -1), ("_id", 1)]


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
    sort_order: SortOrderQuery = "desc",
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

    scan_docs = await scan_repo.find_many_raw(
        query,
        sort=_scan_page_sort(get_sort_field("project_scans", sort_by), parse_sort_direction(sort_order)),
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
    """Every branch's representative scan and scan count.

    A page of the scan list cannot answer this: a branch whose newest scan fell off the page
    disappears from it.
    """
    project = await check_project_access(project_id, current_user, db)
    tips = await ScanRepository(db).branch_tips(project_id, list(project.deleted_branches or []))
    return ProjectBranchTips(
        branches=[
            BranchTip(branch=branch, scan_count=count, tip=Scan(**tip) if tip else None) for branch, count, tip in tips
        ]
    )


@router.post(
    "/{project_id}/scans/{scan_id}/rescan",
    summary="Trigger a manual re-scan",
    responses=RESP_AUTH_400_404_409_500,
)
async def trigger_rescan(
    project_id: str,
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Scan:
    """Manually trigger a re-scan: a new scan entry with the same SBOMs, re-analysed."""
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_EDITOR)

    scan = await ScanRepository(db).find_one({"_id": scan_id, "project_id": project_id})
    if not scan:
        raise HTTPException(status_code=404, detail=_MSG_SCAN_NOT_FOUND)

    if not scan.get("sbom_refs"):
        raise HTTPException(status_code=400, detail="Cannot re-scan: No SBOMs found in the source scan.")

    # Scanner results may still be arriving, and a rescan would copy the SBOM set as it stands.
    if scan.get("status") in SCAN_ACTIVE_STATUSES:
        raise HTTPException(status_code=409, detail="Cannot re-scan: the scan is still being analysed.")

    if not worker_manager:
        raise HTTPException(status_code=500, detail="Worker manager not available")

    rescan = await create_rescan(db, scan, worker_manager)
    if rescan is None:
        raise HTTPException(status_code=409, detail="A re-scan of this scan is already under way.")
    return rescan


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
        fields: dict[str, Any] = {"enforce_notification_settings": settings.enforce_notification_settings}
        if settings.enforce_notification_settings:
            fields["enforced_notification_preferences"] = settings.notification_preferences
        await project_repo.update_raw(project_id, {"$set": fields})
    elif project.enforce_notification_settings and not may_enforce:
        raise HTTPException(status_code=403, detail="Notification settings are enforced by the project admin")

    if direct_member_role(project, user_id) is not None:
        await project_repo.update_member(
            project_id, user_id, {"notification_preferences": settings.notification_preferences}
        )
    elif role is not None:
        # Beside the members, so no member entry outlives the team membership that granted access.
        await project_repo.update_raw(
            project_id, {"$set": {f"notification_overrides.{user_id}": settings.notification_preferences}}
        )
    elif not may_enforce:
        raise HTTPException(status_code=400, detail="You must be a member or admin to set notification preferences")

    return await _reload_project(project_repo, project_id)


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
    """List the analyzer result rows of a scan, without the results themselves."""
    await _require_scan_access(scan_id, current_user, db)
    return await AnalysisResultRepository(db).find_by_scan(scan_id, limit=1000)


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


def _attachment(filename: str) -> dict[str, str]:
    return {"Content-Disposition": f'attachment; filename="{filename}"'}


def _stream_json(stream: Any, filename: str) -> StreamingResponse:
    return StreamingResponse(iter_gridfs_chunks(stream), media_type="application/json", headers=_attachment(filename))


async def _open_sbom(db: Any, ref: Any) -> Any:
    """An open download stream of one stored SBOM, or the HTTP error, raised before any byte is sent."""
    gridfs_id = gridfs_ref_id(ref)
    if not gridfs_id:
        raise HTTPException(status_code=500, detail="Invalid SBOM reference (not GridFS)")
    try:
        return await open_gridfs_download_with_retry(AsyncIOMotorGridFSBucket(db), ObjectId(gridfs_id))
    except NoFile as exc:
        raise HTTPException(status_code=404, detail="SBOM file not found in GridFS") from exc


@router.get(
    "/scans/{scan_id}/sboms",
    summary="List the SBOMs of a scan",
    responses=RESP_AUTH_404,
)
async def read_scan_sboms(
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> list[dict[str, Any]]:
    """Index, filename and stored size of each SBOM; size is None when its file is gone."""
    sbom_refs = (await _load_scan_with_access(scan_id, current_user, db)).sbom_refs

    if not sbom_refs:
        raise HTTPException(status_code=404, detail="No SBOM data available for this scan")

    sizes = await gridfs_lengths(db, extract_gridfs_ids_from_refs(sbom_refs))
    return [
        {"index": index, "filename": ref.get("filename"), "size": sizes.get(gridfs_ref_id(ref) or "")}
        for index, ref in enumerate(sbom_refs)
    ]


@router.get(
    "/scans/{scan_id}/sboms/{index}",
    summary="Download one SBOM of a scan",
    responses=RESP_AUTH_404_500,
)
async def download_scan_sbom(
    scan_id: str,
    index: int,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> StreamingResponse:
    """The stored SBOM at ``index`` (0-based), streamed as uploaded."""
    sbom_refs = (await _load_scan_with_access(scan_id, current_user, db)).sbom_refs
    if not 0 <= index < len(sbom_refs):
        raise HTTPException(status_code=404, detail="SBOM not found")
    return _stream_json(await _open_sbom(db, sbom_refs[index]), f"scan_{scan_id}_sbom_{index + 1}.json")


@router.get(
    "/scans/{scan_id}/results/{result_id}",
    summary="Download one raw analysis result",
    responses=RESP_AUTH_404,
)
async def download_analysis_result(
    scan_id: str,
    result_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Response:
    """The stored result of one row of the scan, as the analyzer produced it."""
    await _require_scan_access(scan_id, current_user, db)
    row = await AnalysisResultRepository(db).find_one_raw({"_id": result_id, "scan_id": scan_id}, RESULT_PROJECTION)
    if not row:
        raise HTTPException(status_code=404, detail="Analysis result not found")
    name = "_".join(filter(None, ("scan", scan_id, row["analyzer_name"], row.get("source"))))
    filename = re.sub(r"[^\w.-]+", "_", name) + ".json"
    if file_id := row.get("result_gridfs_id"):
        stream = await open_gridfs_download_with_retry(AsyncIOMotorGridFSBucket(db), ObjectId(file_id))
        return _stream_json(stream, filename)
    # Legacy rows in live data carry the result inline.
    return JSONResponse(row["result"], headers=_attachment(filename))


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


def _scan_findings_dependency_join() -> list[dict[str, Any]]:
    fields = (
        "source_type",
        "source_target",
        "layer_digest",
        "found_by",
        "locations",
        "purl",
        "direct",
        "direct_inferred",
    )
    lookup = {
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
                {"$project": dict.fromkeys(fields, 1)},
            ],
            "as": "dependency_info",
        }
    }
    flatten = {"$addFields": {field: {"$arrayElemAt": [f"$dependency_info.{field}", 0]} for field in fields}}
    return [lookup, flatten, {"$project": {"dependency_info": 0}}]


def _scan_findings_add_fields_stage() -> dict[str, Any]:
    return {
        "$addFields": {
            "severity_rank": {
                "$switch": {
                    "branches": [
                        {"case": {"$eq": ["$severity", severity]}, "then": rank}
                        for severity, rank in SEVERITY_ORDER.items()
                        if rank
                    ],
                    "default": 0,
                }
            },
            # Map finding_id to id for frontend compatibility.
            "id": "$finding_id",
            # Deterministic scalar for sorting by scanner (scanners is a list).
            "first_scanner": {"$arrayElemAt": ["$scanners", 0]},
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


def _scan_findings_sort_stage(sort_by: str, sort_dir: int) -> dict[str, Any]:
    """Compose the $sort stage, always ending with the unique _id tiebreaker so skip/limit pagination is stable (finding_id is not unique within a scan)."""
    field = _SCAN_FINDINGS_SORT_FIELDS.get(sort_by, "severity")
    if field == "severity":
        return {"$sort": {"severity_rank": sort_dir, "component": 1, "_id": 1}}
    return {"$sort": {field: sort_dir, "_id": 1}}


def _build_scan_findings_pipeline(
    query: dict[str, Any],
    *,
    sort_by: str,
    sort_dir: int,
    skip: int,
    limit: int,
    direct_only: bool = False,
) -> list[dict[str, Any]]:
    """Compose the full aggregation pipeline used by ``read_scan_findings``."""
    join = _scan_findings_dependency_join()
    # The join runs one dependency query per finding, so only the page is joined unless the filter or sort reads it.
    early_join, page_join = (join, []) if direct_only or sort_by == "source_type" else ([], join)
    stages: list[dict[str, Any]] = [{"$match": query}, _scan_findings_add_fields_stage(), *early_join]
    if direct_only:
        # Drop known-transitive findings; direct=null (code findings / unmatched packages) stays visible.
        stages.append({"$match": {"direct": {"$ne": False}}})
    stages += [
        _scan_findings_sort_stage(sort_by, sort_dir),
        {
            "$facet": {
                "metadata": [{"$count": "total"}],
                "data": [
                    {"$skip": skip},
                    {"$limit": limit},
                    *page_join,
                    {"$project": {"_id": 0, "first_scanner": 0}},
                ],
            }
        },
    ]
    return stages


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
    sort_order: SortOrderQuery = "desc",
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
        sort_dir=parse_sort_direction(sort_order),
        skip=skip,
        limit=limit,
        direct_only=bool(direct_only),
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
    return await _reload_project(project_repo, project_id)


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
    return await _reload_project(project_repo, project_id)


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

    tips = await ScanRepository(db).branch_tips(project_id, list(project.deleted_branches or []))
    scans = [
        ExportedScan(tip["_id"], branch, tip.get("created_at"), tip.get("commit_hash"))
        for branch, _, tip in tips
        if tip
    ]
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

    if not scan.sbom_refs:
        raise HTTPException(status_code=404, detail="No SBOM data found for this scan")

    if len(scan.sbom_refs) == 1:
        return _stream_json(await _open_sbom(db, scan.sbom_refs[0]), f"project_{project_id}_sbom.json")

    with ExitStack() as close_on_error:
        spool = close_on_error.enter_context(SpooledTemporaryFile(max_size=_EXPORT_SPOOL_MAX_MEMORY))
        with zipfile.ZipFile(spool, "w", zipfile.ZIP_DEFLATED) as archive:
            for index, ref in enumerate(scan.sbom_refs):
                stream = await _open_sbom(db, ref)
                with archive.open(f"sbom-{index + 1}.json", "w", force_zip64=True) as entry:
                    async for chunk in iter_gridfs_chunks(stream):
                        entry.write(chunk)
        close_on_error.pop_all()
    spool.seek(0)
    return StreamingResponse(
        iter(partial(spool.read, DEFAULT_CHUNK_SIZE), b""),
        media_type="application/zip",
        headers=_attachment(f"project_{project_id}_sboms.zip"),
        background=BackgroundTask(spool.close),
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
    scan_ids = [scan["_id"] async for scan in scan_repo.iterate_raw({"project_id": project_id}, {"_id": 1})]
    await delete_scans_and_related_data(db, scan_ids)

    await waiver_repo.delete_many({"project_id": project_id})
    await release_repo.delete_many({"project_id": project_id})
    await invitation_repo.delete_project_invitations_by_project(project_id)
    await callgraph_repo.delete_by_project(project_id)
    await WebhookRepository(db).delete_many({"project_id": project_id})
    await CryptoPolicyRepository(db).delete_project_policy(project_id)
    await project_repo.delete(project_id)
