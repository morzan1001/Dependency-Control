from typing import Any, Dict, List, Set
import logging
import markdown
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from packaging.version import parse as parse_version

from app.api import deps
from app.db.mongodb import get_database
from app.models.project import Project
from app.models.user import User
from app.models.broadcast import Broadcast
from app.schemas.notification import (
    BroadcastRequest,
    BroadcastResult,
    BroadcastHistoryItem,
)
from app.services.notifications.service import notification_service
from app.services.notifications.templates import (
    get_announcement_template,
)

router = APIRouter()
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
    cursor = db.broadcasts.find({}).sort("created_at", -1).limit(50)
    history = await cursor.to_list(None)
    return [
        BroadcastHistoryItem(
            id=str(h["_id"]),
            type=h["type"],
            target_type=h["target_type"],
            subject=h["subject"],
            created_at=(
                h["created_at"].isoformat()
                if isinstance(h["created_at"], datetime)
                else str(h["created_at"])
            ),
            recipient_count=h.get("recipient_count", 0),
            project_count=h.get("project_count", 0),
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
    pipeline: List[Dict[str, Any]] = [
        {"$match": {"name": {"$regex": q, "$options": "i"}}},
        {"$group": {"_id": "$name"}},
        {"$sort": {"_id": 1}},
        {"$limit": 20},
        {"$project": {"_id": 0, "name": "$_id"}},
    ]

    results = await db.dependencies.aggregate(pipeline).to_list(20)
    return [r["name"] for r in results]


@router.post("/broadcast", response_model=BroadcastResult)
async def broadcast_message(
    payload: BroadcastRequest,
    current_user: User = Depends(
        deps.PermissionChecker(["notifications:broadcast", "system:manage"])
    ),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Send a broadcast message to all users, specific teams, or owners of projects affecting a specific dependency.
    """
    users_to_notify: List[User] = []
    project_count = 0
    unique_user_count = 0

    # 0. Check settings for dashboard url
    settings_data = await db.system_settings.find_one({"_id": "current"})
    dashboard_url = settings_data.get("dashboard_url") if settings_data else None
    if not dashboard_url:
        logger.warning(
            "Dashboard URL not configured; notifications will omit dashboard links"
        )

    # Determine forced channels
    forced_channels = payload.channels if payload.channels else None

    # Convert Markdown to HTML for the message body
    message_html_content = markdown.markdown(payload.message)

    if payload.target_type == "global":
        # All active users
        users_cursor = db.users.find({"is_active": True})
        users_list = await users_cursor.to_list(None)
        users_to_notify = [User(**u) for u in users_list]
        unique_user_count = len(users_to_notify)

        if users_to_notify and not payload.dry_run:
            # Generate HTML template
            html_msg = get_announcement_template(
                message=message_html_content,
                link=dashboard_url,
            )

            await notification_service.notify_users(
                users_to_notify,
                "analysis_completed",
                payload.subject,
                payload.message,  # Plaintext version
                db=db,
                forced_channels=forced_channels,
                html_message=html_msg,
            )

    elif payload.target_type == "teams":
        if not payload.target_teams:
            return BroadcastResult(recipient_count=0)

        # Find teams -> members -> users
        teams_cursor = db.teams.find({"_id": {"$in": payload.target_teams}})
        teams = await teams_cursor.to_list(None)
        user_ids: Set[str] = set()

        for t in teams:
            for m in t.get("members", []):
                user_ids.add(m["user_id"])

        if user_ids:
            users_cursor = db.users.find(
                {"_id": {"$in": list(user_ids)}, "is_active": True}
            )
            users_list = await users_cursor.to_list(None)
            users_to_notify = [User(**u) for u in users_list]
            unique_user_count = len(users_to_notify)

            if users_to_notify and not payload.dry_run:
                # Generate HTML
                html_msg = get_announcement_template(
                    message=message_html_content,
                    link=dashboard_url,
                )

                await notification_service.notify_users(
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
        projects_cursor = db.projects.find({"latest_scan_id": {"$exists": True}})
        projects_list = await projects_cursor.to_list(None)

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

        # 2. Iterate over each advisory package rule
        for pkg_rule in payload.packages:
            query = {
                "scan_id": {"$in": list(scan_map.keys())},
                "name": pkg_rule.name,
            }
            if pkg_rule.type:
                query["type"] = pkg_rule.type

            deps_cursor = db.dependencies.find(query)
            dependencies = await deps_cursor.to_list(None)

            target_version = (
                parse_version(pkg_rule.version) if pkg_rule.version else None
            )

            for dep in dependencies:
                is_affected = False
                if target_version:
                    try:
                        dep_ver = parse_version(dep["version"])
                        # Check if dep_ver <= target_version (affected range)
                        if dep_ver <= target_version:
                            is_affected = True
                    except Exception:
                        pass
                else:
                    is_affected = True

                if is_affected:
                    p_data = scan_map.get(dep["scan_id"])
                    if p_data:
                        project_id = str(p_data["_id"])
                        if project_id not in affected_projects_map:
                            affected_projects_map[project_id] = Project(**p_data)

                        if project_id not in project_findings:
                            project_findings[project_id] = []

                        finding_str = f"{dep['name']} ({dep['version']})"
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
            # If teams are supported for ownership, we'd need to fetch teams -> members here too.
            # Assuming simplified 'owner_id' for now as per Project model generally used.

        users_cursor = db.users.find(
            {"_id": {"$in": list(all_owner_ids)}, "is_active": True}
        )
        users_dict = {
            str(u["_id"]): User(**u) for u in await users_cursor.to_list(None)
        }

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
                    findings_str = ", ".join(p["findings"])
                    if dashboard_url:
                        p_link = f"{dashboard_url}/projects/{p['id']}"
                        projects_html_parts.append(
                            f"<li><strong><a href='{p_link}'>{p['name']}</a></strong>: {findings_str}</li>"
                        )
                    else:
                        projects_html_parts.append(
                            f"<li><strong>{p['name']}</strong>: {findings_str}</li>"
                        )
                    projects_text_parts.append(f"- {p['name']}: {findings_str}")

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
                    f"<p style=\"margin-top: 20px;\">"
                    f"<a href=\"{dashboard_url}\" style=\"{btn_style}\">View Dashboard</a>"
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

                # Send Notification
                await notification_service.notify_users(
                    [user],
                    "vulnerability_found",  # Priority Event
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
            packages=[p.dict() for p in payload.packages] if payload.packages else None,
            channels=payload.channels,
            teams=payload.target_teams,
        )
        await db.broadcasts.insert_one(history_entry.dict(by_alias=True))

    return BroadcastResult(
        recipient_count=(
            unique_user_count
            if payload.target_type != "global" and payload.target_type != "teams"
            else len(users_to_notify)
        ),  # Fix count logic for simple types
        project_count=project_count,
        unique_user_count=unique_user_count,
    )
