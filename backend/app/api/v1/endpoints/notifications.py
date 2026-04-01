import html
import logging
import re
from datetime import datetime
from typing import Annotated, Any, Dict, List, Set

import markdown
from fastapi import BackgroundTasks, Depends, HTTPException, Query

from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_400
from packaging.version import parse as parse_version

from app.api import deps
from app.api.deps import DatabaseDep
from app.core.config import settings
from app.core.permissions import Permissions
from app.models.broadcast import Broadcast
from app.models.project import Project
from app.models.user import User
from app.repositories import (
    BroadcastRepository,
    DependencyRepository,
    ProjectRepository,
    TeamRepository,
    UserRepository,
)
from app.schemas.notification import (
    BroadcastHistoryItem,
    BroadcastRequest,
    BroadcastResult,
)
from app.services.notifications.service import notification_service
from app.services.notifications.mattermost_formatter import build_advisory_props as mm_advisory_props
from app.services.notifications.slack_formatter import build_advisory_blocks
from app.services.notifications.templates import get_announcement_template

router = CustomAPIRouter()
logger = logging.getLogger(__name__)


@router.get("/history", responses=RESP_AUTH)
async def get_broadcast_history(
    db: DatabaseDep,
    current_user: Annotated[
        User, Depends(deps.PermissionChecker([Permissions.NOTIFICATIONS_BROADCAST, Permissions.SYSTEM_MANAGE]))
    ],
) -> List[BroadcastHistoryItem]:
    """
    Get history of sent broadcasts
    """
    broadcast_repo = BroadcastRepository(db)
    user_repo = UserRepository(db)
    history = await broadcast_repo.get_history(limit=50)

    # Resolve creator user IDs to usernames
    creator_ids = list({h.created_by for h in history if h.created_by})
    creators_map: dict[str, str] = {}
    if creator_ids:
        creator_users = await user_repo.find_many({"_id": {"$in": creator_ids}}, limit=len(creator_ids))
        creators_map = {str(u.id): u.username for u in creator_users}

    # Resolve team IDs to team names
    all_team_ids: list[str] = []
    for h in history:
        if h.teams:
            all_team_ids.extend(h.teams)
    teams_map: dict[str, str] = {}
    if all_team_ids:
        team_repo = TeamRepository(db)
        found_teams = await team_repo.find_many({"_id": {"$in": list(set(all_team_ids))}}, limit=100)
        teams_map = {str(t.id): t.name for t in found_teams}

    return [
        BroadcastHistoryItem(
            id=str(h.id),
            type=h.type,
            target_type=h.target_type,
            subject=h.subject,
            created_at=(h.created_at.isoformat() if isinstance(h.created_at, datetime) else str(h.created_at)),
            created_by=creators_map.get(h.created_by, h.created_by),
            recipient_count=h.recipient_count,
            project_count=h.project_count,
            unique_user_count=h.recipient_count,
            teams=[teams_map.get(tid, tid) for tid in h.teams] if h.teams else None,
        )
        for h in history
    ]


@router.get("/packages/suggest", responses=RESP_AUTH)
async def suggest_packages(
    db: DatabaseDep,
    current_user: Annotated[
        User, Depends(deps.PermissionChecker([Permissions.NOTIFICATIONS_BROADCAST, Permissions.SYSTEM_MANAGE]))
    ],
    q: Annotated[str, Query(min_length=2, description="Search query for package name")],
) -> List[str]:
    """
    Suggest package names for advisories based on existing dependencies.
    """
    dep_repo = DependencyRepository(db)

    pipeline: List[Dict[str, Any]] = [
        {"$match": {"name": {"$regex": re.escape(q), "$options": "i"}}},
        {"$group": {"_id": "$name"}},
        {"$sort": {"_id": 1}},
        {"$limit": 20},
        {"$project": {"_id": 0, "name": "$_id"}},
    ]

    results = await dep_repo.aggregate(pipeline, limit=20)
    return [r["name"] for r in results]


def _queue_announcement(
    background_tasks: BackgroundTasks,
    users: List[User],
    subject: str,
    message: str,
    message_html: str,
    frontend_url: str,
    db: Any,
    forced_channels: Any,
) -> None:
    """Queue an announcement notification for a list of users."""
    html_msg = get_announcement_template(message=message_html, link=frontend_url)
    blocks = build_advisory_blocks(subject=subject, message=message, dashboard_link=frontend_url)
    mm_props = mm_advisory_props(subject=subject, message=message, dashboard_link=frontend_url)
    background_tasks.add_task(
        notification_service.notify_users,
        users, "analysis_completed", subject, message,
        db=db, forced_channels=forced_channels,
        html_message=html_msg, slack_blocks=blocks, mattermost_props=mm_props,
    )


async def _handle_global_broadcast(
    payload: "BroadcastRequest",
    background_tasks: BackgroundTasks,
    user_repo: UserRepository,
    message_html: str,
    frontend_url: str,
    db: Any,
    forced_channels: Any,
) -> tuple[int, int]:
    """Handle global broadcast. Returns (unique_user_count, project_count)."""
    users = await user_repo.find_many({"is_active": True}, limit=10000)
    if users and not payload.dry_run:
        _queue_announcement(background_tasks, users, payload.subject, payload.message, message_html, frontend_url, db, forced_channels)
    return len(users), 0


async def _handle_teams_broadcast(
    payload: "BroadcastRequest",
    background_tasks: BackgroundTasks,
    user_repo: UserRepository,
    team_repo: "TeamRepository",
    message_html: str,
    frontend_url: str,
    db: Any,
    forced_channels: Any,
) -> tuple[int, int]:
    """Handle teams broadcast. Returns (unique_user_count, project_count)."""
    if not payload.target_teams:
        return 0, 0

    teams = await team_repo.find_many({"_id": {"$in": payload.target_teams}}, limit=100)
    user_ids: Set[str] = set()
    for t in teams:
        for m in t.members:
            user_ids.add(m.user_id)

    if not user_ids:
        return 0, 0

    users = await user_repo.find_many({"_id": {"$in": list(user_ids)}, "is_active": True}, limit=10000)
    if users and not payload.dry_run:
        _queue_announcement(background_tasks, users, payload.subject, payload.message, message_html, frontend_url, db, forced_channels)
    return len(users), 0


async def _build_advisory_scan_map(
    project_repo: "ProjectRepository",
    db: Any,
) -> Dict[str, Project]:
    """Build scan_id -> Project map for advisory broadcasts, handling deleted branches."""
    scan_map: Dict[str, Project] = {}
    projects_needing_lookup: list = []

    async for p in project_repo.iterate({"latest_scan_id": {"$exists": True}}):
        if not p or not p.latest_scan_id:
            continue
        if p.deleted_branches:
            projects_needing_lookup.append(p)
        else:
            scan_map[p.latest_scan_id] = p

    if projects_needing_lookup:
        or_conditions = [
            {"project_id": p.id, "branch": {"$nin": p.deleted_branches}, "status": "completed"}
            for p in projects_needing_lookup
        ]
        pipeline: List[Dict[str, Any]] = [
            {"$match": {"$or": or_conditions}},
            {"$sort": {"created_at": -1}},
            {"$group": {"_id": "$project_id", "scan_id": {"$first": "$_id"}}},
        ]
        proj_map = {p.id: p for p in projects_needing_lookup}
        async for doc in db.scans.aggregate(pipeline):
            proj = proj_map.get(doc["_id"])
            if proj:
                scan_map[doc["scan_id"]] = proj

    return scan_map


def _find_affected_projects(
    dep: Any,
    payload_packages: list,
    scan_map: Dict[str, Project],
    affected_projects_map: Dict[str, Project],
    project_findings: Dict[str, List[str]],
) -> None:
    """Check if a dependency is affected by any advisory package rule."""
    dep_name = dep.name
    dep_version = dep.version

    matching_rule = None
    for pkg_rule in payload_packages:
        if pkg_rule.name == dep_name:
            if pkg_rule.type and dep.type != pkg_rule.type:
                continue
            matching_rule = pkg_rule
            break

    if not matching_rule:
        return

    is_affected = False
    if matching_rule.version:
        try:
            target_ver = parse_version(matching_rule.version)
            dep_ver = parse_version(dep_version)
            is_affected = dep_ver <= target_ver
        except Exception:
            is_affected = True
    else:
        is_affected = True

    if not is_affected:
        return

    p_data = scan_map.get(dep.scan_id)
    if not p_data:
        return

    project_id = str(p_data.id)
    if project_id not in affected_projects_map:
        affected_projects_map[project_id] = p_data
    if project_id not in project_findings:
        project_findings[project_id] = []

    finding_str = f"{dep_name} ({dep_version})"
    if finding_str not in project_findings[project_id]:
        project_findings[project_id].append(finding_str)


def _build_advisory_html(
    message_html: str, projects_data: list, frontend_url: str,
) -> tuple[str, str]:
    """Build HTML and plain-text messages for an advisory notification. Returns (html, text)."""
    projects_html_parts = []
    projects_text_parts = []

    for p in projects_data:
        safe_name = html.escape(p["name"])
        safe_findings = html.escape(", ".join(p["findings"]))
        p_link = f"{frontend_url}/projects/{p['id']}"
        projects_html_parts.append(f"<li><strong><a href='{p_link}'>{safe_name}</a></strong>: {safe_findings}</li>")
        projects_text_parts.append(f"- {p['name']}: {', '.join(p['findings'])}")

    findings_list_html = "<ul>" + "".join(projects_html_parts) + "</ul>"
    findings_text_block = "\n".join(projects_text_parts)

    btn_style = "background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;"
    div_style = "background-color: #fff3cd; border: 1px solid #ffeeba; padding: 15px; margin-bottom: 20px; border-radius: 4px;"
    dashboard_button = f'<p style="margin-top: 20px;"><a href="{frontend_url}" style="{btn_style}">View Dashboard</a></p>'

    final_html = f"""
    <div style="font-family: Arial, sans-serif; color: #333;">
        <h2>Security Advisory</h2>
        <div style="{div_style}">{message_html}</div>
        <h3>Your Affected Projects ({len(projects_data)})</h3>
        <p>The following projects you own are using the affected package versions:</p>
        {findings_list_html}
        {dashboard_button}
    </div>
    """
    return final_html, findings_text_block


async def _notify_advisory_owners(
    affected_projects_map: Dict[str, Project],
    project_findings: Dict[str, List[str]],
    user_repo: UserRepository,
    payload: "BroadcastRequest",
    background_tasks: BackgroundTasks,
    message_html: str,
    frontend_url: str,
    db: Any,
    forced_channels: Any,
) -> int:
    """Group affected projects by owner and queue advisory notifications. Returns unique user count."""
    all_owner_ids = {p.owner_id for p in affected_projects_map.values()}
    owner_users = await user_repo.find_many({"_id": {"$in": list(all_owner_ids)}, "is_active": True}, limit=10000)
    users_dict = {str(u.id): u for u in owner_users}

    # Group projects by owner
    user_notification_map: Dict[str, Dict] = {}
    for pid, project in affected_projects_map.items():
        uid = project.owner_id
        if uid not in users_dict:
            continue
        if uid not in user_notification_map:
            user_notification_map[uid] = {"user": users_dict[uid], "projects": []}
        user_notification_map[uid]["projects"].append(
            {"id": pid, "name": project.name, "findings": project_findings.get(pid, [])},
        )

    if not payload.dry_run:
        for uid, data in user_notification_map.items():
            projects_data = data["projects"]
            final_html, findings_text = _build_advisory_html(message_html, projects_data, frontend_url)
            context_message = f"{payload.message}\n\n--- Affected Projects ---\n{findings_text}\n"

            advisory_subject = f"ACTION REQUIRED: {payload.subject}"
            advisory_blocks = build_advisory_blocks(
                subject=advisory_subject, message=payload.message,
                affected_projects=projects_data, dashboard_link=frontend_url,
            )
            advisory_mm = mm_advisory_props(
                subject=advisory_subject, message=payload.message,
                affected_projects=projects_data, dashboard_link=frontend_url,
            )

            background_tasks.add_task(
                notification_service.notify_users,
                [data["user"]], "vulnerability_found", advisory_subject, context_message,
                db=db, forced_channels=forced_channels,
                html_message=final_html, slack_blocks=advisory_blocks, mattermost_props=advisory_mm,
            )

    return len(user_notification_map)


@router.post("/broadcast", responses=RESP_AUTH_400)
async def broadcast_message(
    payload: BroadcastRequest,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    current_user: Annotated[
        User, Depends(deps.PermissionChecker([Permissions.NOTIFICATIONS_BROADCAST, Permissions.SYSTEM_MANAGE]))
    ],
) -> BroadcastResult:
    """
    Send a broadcast message to all users, specific teams, or owners of projects affecting a specific dependency.
    """
    # Initialize repositories
    user_repo = UserRepository(db)
    team_repo = TeamRepository(db)
    project_repo = ProjectRepository(db)
    dep_repo = DependencyRepository(db)
    broadcast_repo = BroadcastRepository(db)

    project_count = 0
    unique_user_count = 0

    frontend_url = settings.FRONTEND_BASE_URL.rstrip("/")

    # Determine forced channels
    forced_channels = payload.channels if payload.channels else None

    # Validate target_type
    valid_target_types: List[str] = ["global", "teams", "advisory"]
    if payload.target_type not in valid_target_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target_type. Must be one of: {', '.join(valid_target_types)}",
        )

    # Convert Markdown to HTML for the message body
    # Escape raw HTML in the input first to prevent XSS via embedded tags
    safe_message = html.escape(payload.message)
    message_html_content = markdown.markdown(safe_message)

    if payload.target_type == "global":
        unique_user_count, project_count = await _handle_global_broadcast(
            payload, background_tasks, user_repo, message_html_content, frontend_url, db, forced_channels,
        )

    elif payload.target_type == "teams":
        unique_user_count, project_count = await _handle_teams_broadcast(
            payload, background_tasks, user_repo, team_repo, message_html_content, frontend_url, db, forced_channels,
        )

    elif payload.target_type == "advisory":
        if not payload.packages:
            raise HTTPException(status_code=400, detail="At least one package required for advisory")

        scan_map = await _build_advisory_scan_map(project_repo, db)
        if not scan_map:
            return BroadcastResult(recipient_count=0)

        affected_projects_map: Dict[str, Project] = {}
        project_findings: Dict[str, List[str]] = {}

        # Build match query for affected dependencies
        package_names = [pkg.name for pkg in payload.packages]
        match_query: Dict[str, Any] = {
            "scan_id": {"$in": list(scan_map.keys())},
            "name": {"$in": package_names},
        }
        unique_types = {pkg.type for pkg in payload.packages if pkg.type}
        if len(unique_types) == 1:
            match_query["type"] = list(unique_types)[0]

        # Stream dependencies and find affected projects
        dep_count = 0
        async for dep in dep_repo.iterate(match_query):
            dep_count += 1
            _find_affected_projects(dep, payload.packages, scan_map, affected_projects_map, project_findings)

        logger.info(f"Advisory broadcast: Processed {dep_count} dependencies matching {len(package_names)} packages")

        project_count = len(affected_projects_map)

        # Group affected projects by owner and notify
        unique_user_count = await _notify_advisory_owners(
            affected_projects_map, project_findings, user_repo,
            payload, background_tasks, message_html_content, frontend_url, db, forced_channels,
        )

    # 5. Save History
    if not payload.dry_run:
        history_entry = Broadcast(
            type=payload.type,
            target_type=payload.target_type,
            subject=payload.subject,
            message=payload.message,
            created_by=str(current_user.id),
            recipient_count=unique_user_count,
            project_count=project_count,
            packages=([p.model_dump() for p in payload.packages] if payload.packages else None),
            channels=payload.channels,
            teams=payload.target_teams,
        )
        await broadcast_repo.create(history_entry)

    return BroadcastResult(
        recipient_count=unique_user_count,
        project_count=project_count,
        unique_user_count=unique_user_count,
    )
