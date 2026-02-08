import html
import logging
from datetime import datetime
from typing import Any, Dict, List, Set

import markdown
from fastapi import BackgroundTasks, Depends, HTTPException, Query

from app.api.router import CustomAPIRouter
from motor.motor_asyncio import AsyncIOMotorDatabase
from packaging.version import parse as parse_version

from app.api import deps
from app.db.mongodb import get_database
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
from app.services.notifications.templates import get_announcement_template

router = CustomAPIRouter()
logger = logging.getLogger(__name__)


@router.get("/history", response_model=List[BroadcastHistoryItem])
async def get_broadcast_history(
    current_user: User = Depends(
        deps.PermissionChecker(["notifications:broadcast", "system:manage"])
    ),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get history of sent broadcasts
    """
    broadcast_repo = BroadcastRepository(db)
    history = await broadcast_repo.get_history(limit=50)

    return [
        BroadcastHistoryItem(
            id=str(h.id),
            type=h.type,
            target_type=h.target_type,
            subject=h.subject,
            created_at=(
                h.created_at.isoformat()
                if isinstance(h.created_at, datetime)
                else str(h.created_at)
            ),
            recipient_count=h.recipient_count,
            project_count=h.project_count,
        )
        for h in history
    ]


@router.get("/packages/suggest", response_model=List[str])
async def suggest_packages(
    q: str = Query(..., min_length=2, description="Search query for package name"),
    current_user: User = Depends(
        deps.PermissionChecker(["notifications:broadcast", "system:manage"])
    ),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Suggest package names for advisories based on existing dependencies.
    """
    dep_repo = DependencyRepository(db)

    pipeline: List[Dict[str, Any]] = [
        {"$match": {"name": {"$regex": q, "$options": "i"}}},
        {"$group": {"_id": "$name"}},
        {"$sort": {"_id": 1}},
        {"$limit": 20},
        {"$project": {"_id": 0, "name": "$_id"}},
    ]

    results = await dep_repo.aggregate(pipeline, limit=20)
    return [r["name"] for r in results]


@router.post("/broadcast", response_model=BroadcastResult)
async def broadcast_message(
    payload: BroadcastRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(
        deps.PermissionChecker(["notifications:broadcast", "system:manage"])
    ),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Send a broadcast message to all users, specific teams, or owners of projects affecting a specific dependency.
    """
    # Initialize repositories
    user_repo = UserRepository(db)
    team_repo = TeamRepository(db)
    project_repo = ProjectRepository(db)
    dep_repo = DependencyRepository(db)
    broadcast_repo = BroadcastRepository(db)

    users_to_notify: List[User] = []
    project_count = 0
    unique_user_count = 0

    # 0. Check settings for dashboard url
    system_settings = await deps.get_system_settings(db)
    dashboard_url = system_settings.dashboard_url
    if not dashboard_url:
        logger.warning(
            "Dashboard URL not configured; notifications will omit dashboard links"
        )

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
    message_html_content = markdown.markdown(payload.message)

    if payload.target_type == "global":
        # All active users
        users_to_notify = await user_repo.find_many({"is_active": True}, limit=10000)
        unique_user_count = len(users_to_notify)

        if users_to_notify and not payload.dry_run:
            html_msg = get_announcement_template(
                message=message_html_content,
                link=dashboard_url,
            )
            background_tasks.add_task(
                notification_service.notify_users,
                users_to_notify,
                "analysis_completed",
                payload.subject,
                payload.message,
                db=db,
                forced_channels=forced_channels,
                html_message=html_msg,
            )

    elif payload.target_type == "teams":
        if not payload.target_teams:
            return BroadcastResult(recipient_count=0)

        # Find teams -> members -> users
        teams = await team_repo.find_many(
            {"_id": {"$in": payload.target_teams}}, limit=100
        )
        user_ids: Set[str] = set()

        for t in teams:
            for m in t.get("members", []):
                user_ids.add(m["user_id"])

        if user_ids:
            users_to_notify = await user_repo.find_many(
                {"_id": {"$in": list(user_ids)}, "is_active": True}, limit=10000
            )
            unique_user_count = len(users_to_notify)

            if users_to_notify and not payload.dry_run:
                html_msg = get_announcement_template(
                    message=message_html_content,
                    link=dashboard_url,
                )
                background_tasks.add_task(
                    notification_service.notify_users,
                    users_to_notify,
                    "analysis_completed",
                    payload.subject,
                    payload.message,
                    db=db,
                    forced_channels=forced_channels,
                    html_message=html_msg,
                )

    elif payload.target_type == "advisory":
        if not payload.packages:
            raise HTTPException(
                status_code=400, detail="At least one package required for advisory"
            )

        # 1. Get all projects with latest_scan_id
        projects_list = await project_repo.find_many(
            {"latest_scan_id": {"$exists": True}}, limit=10000
        )

        # Map scan_id -> Project Data
        scan_map = {
            p["latest_scan_id"]: p for p in projects_list if p.get("latest_scan_id")
        }

        if not scan_map:
            return BroadcastResult(recipient_count=0)

        # project_id -> Project
        affected_projects_map: Dict[str, Project] = {}
        # project_id -> list of strings "PackageName (Version)"
        project_findings: Dict[str, List[str]] = {}

        # 2. Use AGGREGATED query for better performance
        # Build match conditions for all packages
        package_names = [pkg.name for pkg in payload.packages]

        # Single aggregation query to find all affected dependencies
        match_query: Dict[str, Any] = {
            "scan_id": {"$in": list(scan_map.keys())},
            "name": {"$in": package_names},
        }

        # Add type filter if all packages have the same type
        unique_types = set(pkg.type for pkg in payload.packages if pkg.type)
        if len(unique_types) == 1:
            match_query["type"] = list(unique_types)[0]

        # Fetch all potentially affected dependencies in ONE query
        dependencies = await dep_repo.find_many(match_query, limit=100000)

        logger.info(
            f"Advisory broadcast: Found {len(dependencies)} dependencies "
            f"matching {len(package_names)} packages"
        )

        # Process dependencies and check version ranges
        for dep in dependencies:
            dep_name = dep.name
            dep_version = dep.version

            # Find matching package rule
            matching_rule = None
            for pkg_rule in payload.packages:
                if pkg_rule.name == dep_name:
                    # Type match (if specified)
                    if pkg_rule.type and dep.type != pkg_rule.type:
                        continue
                    matching_rule = pkg_rule
                    break

            if not matching_rule:
                continue

            # Check version range
            is_affected = False
            if matching_rule.version:
                try:
                    target_ver = parse_version(matching_rule.version)
                    dep_ver = parse_version(dep_version)
                    # Check if dep_ver <= target_version (affected range)
                    if dep_ver <= target_ver:
                        is_affected = True
                except Exception as e:
                    logger.debug(
                        f"Could not parse version '{dep_version}' for '{dep_name}': {e}"
                    )
                    # If version parsing fails, assume affected (conservative)
                    is_affected = True
            else:
                # No version specified, all versions affected
                is_affected = True

            if is_affected:
                p_data = scan_map.get(dep["scan_id"])
                if p_data:
                    project_id = str(p_data["_id"])
                    if project_id not in affected_projects_map:
                        affected_projects_map[project_id] = Project(**p_data)

                    if project_id not in project_findings:
                        project_findings[project_id] = []

                    finding_str = f"{dep_name} ({dep_version})"
                    if finding_str not in project_findings[project_id]:
                        project_findings[project_id].append(finding_str)

        project_count = len(affected_projects_map)

        # 3. Group by User (Advisory Logic Update)
        # user_id -> { user: User, projects: { project_id: { name: str, findings: [] } } }
        user_notification_map: Dict[str, Dict] = {}

        # We need to resolve users for all affected projects
        all_owner_ids = set()
        for p in affected_projects_map.values():
            all_owner_ids.add(p.owner_id)

        owner_users = await user_repo.find_many(
            {"_id": {"$in": list(all_owner_ids)}, "is_active": True}, limit=10000
        )
        users_dict = {str(u.id): u for u in owner_users}

        for pid, project in affected_projects_map.items():
            if project.owner_id in users_dict:
                uid = project.owner_id
                if uid not in user_notification_map:
                    user_notification_map[uid] = {
                        "user": users_dict[uid],
                        "projects": [],
                    }

                user_notification_map[uid]["projects"].append(
                    {
                        "id": pid,
                        "name": project.name,
                        "findings": project_findings.get(pid, []),
                    }
                )

        unique_user_count = len(user_notification_map)

        # 4. Notify per User (Batching)
        if not payload.dry_run:
            for uid, data in user_notification_map.items():
                user = data["user"]
                projects_data = data["projects"]

                # Construct a consolidated message
                projects_html_parts = []
                projects_text_parts = []

                for p in projects_data:
                    # Escape HTML to prevent XSS
                    safe_name = html.escape(p["name"])
                    safe_findings = html.escape(", ".join(p["findings"]))
                    if dashboard_url:
                        p_link = f"{dashboard_url}/projects/{p['id']}"
                        projects_html_parts.append(
                            f"<li><strong><a href='{p_link}'>{safe_name}</a></strong>: {safe_findings}</li>"
                        )
                    else:
                        projects_html_parts.append(
                            f"<li><strong>{safe_name}</strong>: {safe_findings}</li>"
                        )
                    projects_text_parts.append(
                        f"- {p['name']}: {', '.join(p['findings'])}"
                    )

                # Build Context Message
                findings_list_html = "<ul>" + "".join(projects_html_parts) + "</ul>"
                findings_text_block = "\n".join(projects_text_parts)

                context_message = (
                    f"{payload.message}\n\n"
                    f"--- Affected Projects ---\n"
                    f"{findings_text_block}\n"
                )

                # Use Announcement Template but injected with Project List
                # Generic HTML wrapper used because custom construction is safer for multi-project listings.

                btn_style = (
                    "background-color: #dc3545; color: white; padding: 10px 20px; "
                    "text-decoration: none; border-radius: 4px;"
                )
                div_style = (
                    "background-color: #fff3cd; border: 1px solid #ffeeba; "
                    "padding: 15px; margin-bottom: 20px; border-radius: 4px;"
                )

                dashboard_button = (
                    f'<p style="margin-top: 20px;">'
                    f'<a href="{dashboard_url}" style="{btn_style}">View Dashboard</a>'
                    f"</p>"
                    if dashboard_url
                    else ""
                )

                final_html = f"""
                <div style="font-family: Arial, sans-serif; color: #333;">
                    <h2>Security Advisory</h2>
                    <div style="{div_style}">
                        {message_html_content}
                    </div>
                    <h3>Your Affected Projects ({len(projects_data)})</h3>
                    <p>The following projects you own are using the affected package versions:</p>
                    {findings_list_html}
                    {dashboard_button}
                </div>
                """

                # Queue notification for background delivery
                background_tasks.add_task(
                    notification_service.notify_users,
                    [user],
                    "vulnerability_found",
                    f"ACTION REQUIRED: {payload.subject}",
                    context_message,
                    db=db,
                    forced_channels=forced_channels,
                    html_message=final_html,
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
            packages=(
                [p.model_dump() for p in payload.packages] if payload.packages else None
            ),
            channels=payload.channels,
            teams=payload.target_teams,
        )
        await broadcast_repo.create(history_entry)

    return BroadcastResult(
        recipient_count=unique_user_count,
        project_count=project_count,
        unique_user_count=unique_user_count,
    )
