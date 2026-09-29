import html
import logging
import re
from collections import defaultdict
from datetime import datetime
from typing import Annotated, Any

import markdown
from fastapi import BackgroundTasks, Depends, HTTPException, Query
from pymongo.errors import ExecutionTimeout

from app.api import deps
from app.api.deps import DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.projects import project_admin_ids
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_400
from app.core.config import settings
from app.core.constants import NOTIFICATION_EVENT_ANALYSIS_COMPLETED, NOTIFICATION_EVENT_VULNERABILITY_FOUND
from app.core.permissions import Permissions
from app.core.purl import package_identity, pep503_normalize
from app.models.broadcast import Broadcast
from app.models.project import Project
from app.models.user import User
from app.repositories.broadcasts import BroadcastRepository
from app.repositories.dependencies import DependencyRepository
from app.repositories.projects import ProjectRepository
from app.repositories.teams import TeamRepository
from app.repositories.users import UserRepository
from app.schemas.notification import (
    ECOSYSTEM_STORED_TYPES,
    AdvisoryPackage,
    BroadcastHistoryItem,
    BroadcastRequest,
    BroadcastResult,
    PackageSuggestions,
)
from app.services.notifications.mattermost_formatter import build_advisory_props as mm_advisory_props
from app.services.notifications.service import notification_service
from app.services.notifications.slack_formatter import build_advisory_blocks
from app.services.component_identity import artifact_segment
from app.services.notifications.templates import get_announcement_template
from app.services.releases import resolve_scan_ids

router = CustomAPIRouter()
logger = logging.getLogger(__name__)

_PACKAGE_SUGGESTION_LIMIT = 20
# Keystrokes outpace a slow typeahead; past this the query has to narrow instead.
_PACKAGE_SUGGESTION_TIME_LIMIT_MS = 2000


@router.get("/history", responses=RESP_AUTH)
async def get_broadcast_history(
    db: DatabaseDep,
    current_user: Annotated[
        User, Depends(deps.PermissionChecker([Permissions.NOTIFICATIONS_BROADCAST, Permissions.SYSTEM_MANAGE]))
    ],
) -> list[BroadcastHistoryItem]:
    """Get history of sent broadcasts."""
    broadcast_repo = BroadcastRepository(db)
    user_repo = UserRepository(db)
    history = await broadcast_repo.get_history(limit=50)

    creator_ids = list({h.created_by for h in history if h.created_by})
    creators_map: dict[str, str] = {}
    if creator_ids:
        creator_users = await user_repo.find_many({"_id": {"$in": creator_ids}}, limit=len(creator_ids))
        creators_map = {str(u.id): u.username for u in creator_users}

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
) -> PackageSuggestions:
    """Suggest package names for advisories from the head scans an advisory reaches.

    The field takes free text, so a short list costs nothing but a hint; one row past the
    limit is read so the answer can say the query still has to narrow.
    """
    head_scan_ids = list((await resolve_scan_ids(db, None)).values())
    probe = _PACKAGE_SUGGESTION_LIMIT + 1
    pipeline: list[dict[str, Any]] = [
        # Substring matching finds scoped and path-named packages; the scan_id bound keeps it on head rows.
        {"$match": {"scan_id": {"$in": head_scan_ids}, "name": {"$regex": re.escape(q), "$options": "i"}}},
        {"$group": {"_id": "$name"}},
        {"$sort": {"_id": 1}},
        {"$limit": probe},
        {"$project": {"_id": 0, "name": "$_id"}},
    ]

    try:
        cursor = DependencyRepository(db).collection.aggregate(pipeline, maxTimeMS=_PACKAGE_SUGGESTION_TIME_LIMIT_MS)
        results = await cursor.to_list(probe)
    except ExecutionTimeout:
        return PackageSuggestions(names=[], more=True)
    return PackageSuggestions(
        names=[r["name"] for r in results[:_PACKAGE_SUGGESTION_LIMIT]],
        more=len(results) > _PACKAGE_SUGGESTION_LIMIT,
    )


def _queue_announcement(
    background_tasks: BackgroundTasks,
    users: list[User],
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
        users,
        NOTIFICATION_EVENT_ANALYSIS_COMPLETED,
        subject,
        message,
        db=db,
        forced_channels=forced_channels,
        html_message=html_msg,
        slack_blocks=blocks,
        mattermost_props=mm_props,
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
    users = await user_repo.find_many({"is_active": True}, limit=2000)
    if users and not payload.dry_run:
        _queue_announcement(
            background_tasks, users, payload.subject, payload.message, message_html, frontend_url, db, forced_channels
        )
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
    user_ids: set[str] = set()
    for t in teams:
        for m in t.members:
            user_ids.add(m.user_id)

    if not user_ids:
        return 0, 0

    users = await user_repo.find_many({"_id": {"$in": list(user_ids)}, "is_active": True}, limit=2000)
    if users and not payload.dry_run:
        _queue_announcement(
            background_tasks, users, payload.subject, payload.message, message_html, frontend_url, db, forced_channels
        )
    return len(users), 0


def _segment_key(name: str) -> str:
    """Lookup key a rule and a dependency share: the last name segment, blind to case and separators."""
    return pep503_normalize(re.split(r"[/:]", name)[-1])


def _rule_matches(rule: AdvisoryPackage, dep_type: str, dep_path: str) -> bool:
    """Whether a dependency with package identity ``(dep_type, dep_path)`` is the package ``rule`` names."""
    if rule.type and dep_type != rule.type and dep_type not in ECOSYSTEM_STORED_TYPES.get(rule.type, ()):
        return False
    rule_name = rule.name.strip().replace(":", "/")
    # The rule's name is read under the dependency's own ecosystem rules, as its identity was.
    _, rule_path = package_identity(f"pkg:{dep_type}/{rule_name}", rule_name, dep_type, None)
    qualified = artifact_segment(rule_path) != rule_path
    return (dep_path if qualified else artifact_segment(dep_path)).lower() == rule_path.lower()


async def _find_affected_projects(db: Any, rules: list[AdvisoryPackage]) -> dict[str, dict[str, bool]]:
    """project_id -> "name (version)" of each matched head-scan dependency -> covered (False: not comparable)."""
    project_by_scan = {scan_id: project_id for project_id, scan_id in (await resolve_scan_ids(db, None)).items()}
    if not project_by_scan:
        return {}

    rules_by_segment: dict[str, list[AdvisoryPackage]] = defaultdict(list)
    for rule in rules:
        rules_by_segment[_segment_key(rule.name.strip())].append(rule)
    # A case- and separator-blind prefilter; the package identity decides below.
    names = "|".join("[-_.]+".join(map(re.escape, key.split("-"))) for key in rules_by_segment)
    query = {"scan_id": {"$in": list(project_by_scan)}, "name": {"$regex": f"(^|[/:])({names})$", "$options": "i"}}

    affected: dict[str, dict[str, bool]] = {}
    projection = {"_id": 0, "scan_id": 1, "name": 1, "version": 1, "type": 1, "purl": 1, "group": 1}
    async for dep in DependencyRepository(db).iterate_raw(query, projection):
        dep_type, dep_path = package_identity(dep.get("purl"), dep["name"], dep.get("type"), dep.get("group"))
        candidates = rules_by_segment.get(_segment_key(dep_path), [])
        version = dep.get("version") or ""
        verdicts = {r.covers(version) for r in candidates if _rule_matches(r, dep_type, dep_path)}
        if verdicts - {False}:
            findings = affected.setdefault(project_by_scan[dep["scan_id"]], {})
            entry = f"{dep['name']} ({version})"
            findings[entry] = findings.get(entry, False) or True in verdicts
    return affected


def _build_advisory_html(
    message_html: str,
    projects_data: list,
    frontend_url: str,
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

    btn_style = (
        "background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;"
    )
    div_style = (
        "background-color: #fff3cd; border: 1px solid #ffeeba; padding: 15px; margin-bottom: 20px; border-radius: 4px;"
    )
    dashboard_button = (
        f'<p style="margin-top: 20px;"><a href="{frontend_url}" style="{btn_style}">View Dashboard</a></p>'
    )

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


def _group_projects_by_admin(
    projects: list[Project],
    admins_by_project: dict[str, set[str]],
    affected: dict[str, dict[str, bool]],
    users_dict: dict[str, Any],
) -> dict[str, dict]:
    """Group affected projects under each admin user that should be notified."""
    user_notification_map: dict[str, dict] = {}
    for project in projects:
        for uid in sorted(admins_by_project[project.id]):
            if uid not in users_dict:
                continue
            if uid not in user_notification_map:
                user_notification_map[uid] = {"user": users_dict[uid], "projects": []}
            user_notification_map[uid]["projects"].append(
                {
                    "id": str(project.id),
                    "name": project.name,
                    "findings": [
                        entry if covered else f"{entry}: version could not be compared"
                        for entry, covered in affected[str(project.id)].items()
                    ],
                },
            )
    return user_notification_map


def _queue_advisory_for_user(
    data: dict,
    payload: "BroadcastRequest",
    background_tasks: BackgroundTasks,
    message_html: str,
    frontend_url: str,
    db: Any,
    forced_channels: Any,
) -> None:
    """Build and queue an advisory notification background task for a single user."""
    projects_data = data["projects"]
    final_html, findings_text = _build_advisory_html(message_html, projects_data, frontend_url)
    context_message = f"{payload.message}\n\n--- Affected Projects ---\n{findings_text}\n"

    advisory_subject = f"ACTION REQUIRED: {payload.subject}"
    advisory_blocks = build_advisory_blocks(
        subject=advisory_subject,
        message=payload.message,
        affected_projects=projects_data,
        dashboard_link=frontend_url,
    )
    advisory_mm = mm_advisory_props(
        subject=advisory_subject,
        message=payload.message,
        affected_projects=projects_data,
        dashboard_link=frontend_url,
    )

    background_tasks.add_task(
        notification_service.notify_users,
        [data["user"]],
        NOTIFICATION_EVENT_VULNERABILITY_FOUND,
        advisory_subject,
        context_message,
        db=db,
        forced_channels=forced_channels,
        html_message=final_html,
        slack_blocks=advisory_blocks,
        mattermost_props=advisory_mm,
    )


async def _notify_advisory_admins(
    projects: list[Project],
    affected: dict[str, dict[str, bool]],
    user_repo: UserRepository,
    payload: "BroadcastRequest",
    background_tasks: BackgroundTasks,
    message_html: str,
    frontend_url: str,
    db: Any,
    forced_channels: Any,
) -> int:
    """Group affected projects by admin members and queue advisory notifications. Returns unique user count."""
    admins_by_project = await project_admin_ids(projects, TeamRepository(db))
    all_admin_ids = set().union(*admins_by_project.values())

    admin_users = await user_repo.find_many({"_id": {"$in": list(all_admin_ids)}, "is_active": True}, limit=2000)
    users_dict = {str(u.id): u for u in admin_users}

    user_notification_map = _group_projects_by_admin(projects, admins_by_project, affected, users_dict)

    if not payload.dry_run:
        for data in user_notification_map.values():
            _queue_advisory_for_user(
                data,
                payload,
                background_tasks,
                message_html,
                frontend_url,
                db,
                forced_channels,
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
    """Send a broadcast to all users, specific teams, or admins of projects affected by a dependency."""
    user_repo = UserRepository(db)
    team_repo = TeamRepository(db)
    project_repo = ProjectRepository(db)
    broadcast_repo = BroadcastRepository(db)

    project_count = 0
    unique_user_count = 0
    uncomparable: list[str] = []

    frontend_url = settings.FRONTEND_BASE_URL.rstrip("/")

    forced_channels = payload.channels if payload.channels else None

    # Escape raw HTML before Markdown to prevent XSS via embedded tags.
    safe_message = html.escape(payload.message)
    message_html_content = markdown.markdown(safe_message)

    if payload.target_type == "global":
        unique_user_count, project_count = await _handle_global_broadcast(
            payload,
            background_tasks,
            user_repo,
            message_html_content,
            frontend_url,
            db,
            forced_channels,
        )

    elif payload.target_type == "teams":
        unique_user_count, project_count = await _handle_teams_broadcast(
            payload,
            background_tasks,
            user_repo,
            team_repo,
            message_html_content,
            frontend_url,
            db,
            forced_channels,
        )

    elif payload.target_type == "advisory":
        if not payload.packages:
            raise HTTPException(status_code=400, detail="At least one package required for advisory")

        affected = await _find_affected_projects(db, payload.packages)
        project_count = sum(any(findings.values()) for findings in affected.values())
        uncomparable = sorted({entry for f in affected.values() for entry, covered in f.items() if not covered})
        if affected:
            projects = await project_repo.find_many({"_id": {"$in": list(affected)}}, limit=len(affected))
            unique_user_count = await _notify_advisory_admins(
                projects,
                affected,
                user_repo,
                payload,
                background_tasks,
                message_html_content,
                frontend_url,
                db,
                forced_channels,
            )

    if not payload.dry_run:
        history_entry = Broadcast(
            type="advisory" if payload.target_type == "advisory" else "general",
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
        uncomparable_versions=uncomparable,
    )
