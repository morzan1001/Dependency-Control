import asyncio
import logging
import os
from typing import Any, Dict, List, Optional

from app.models.project import Project
from app.models.system import SystemSettings
from app.models.user import User
from app.repositories.system_settings import SystemSettingsRepository
from app.services.notifications.email_provider import EmailProvider
from app.services.notifications.mattermost_provider import MattermostProvider
from app.services.notifications.slack_provider import SlackProvider

logger = logging.getLogger(__name__)

_LOGO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "static", "logo.png")


class NotificationService:
    def __init__(self) -> None:
        self.email_provider = EmailProvider()
        self.slack_provider = SlackProvider()
        self.mattermost_provider = MattermostProvider()

    async def _send_based_on_prefs(
        self,
        user: User,
        prefs: Dict[str, List[str]],
        event_type: str,
        subject: str,
        message: str,
        system_settings: Optional[SystemSettings] = None,
        html_message: Optional[str] = None,
        slack_blocks: Optional[List[Dict[str, Any]]] = None,
        mattermost_props: Optional[Dict[str, Any]] = None,
    ) -> None:
        channels = prefs.get(event_type, [])
        tasks = []

        if "email" in channels and user.email:
            tasks.append(
                self.email_provider.send(
                    user.email,
                    subject,
                    message,
                    system_settings=system_settings,
                    html_message=html_message,
                    logo_path=_LOGO_PATH,
                )
            )

        if "slack" in channels and user.slack_username:
            tasks.append(
                self.slack_provider.send(
                    user.slack_username,
                    subject,
                    message,
                    system_settings=system_settings,
                    blocks=slack_blocks,
                )
            )

        if "mattermost" in channels and user.mattermost_username:
            mm_dest = user.mattermost_username
            if not mm_dest.startswith("@"):
                mm_dest = f"@{mm_dest}"
            tasks.append(
                self.mattermost_provider.send(
                    mm_dest,
                    subject,
                    message,
                    system_settings=system_settings,
                    props=mattermost_props,
                )
            )

        if tasks:
            # return_exceptions so one failure doesn't cancel the others.
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Notification task failed: {result}")

    async def notify_users(
        self,
        users: List[User],
        event_type: str,
        subject: str,
        message: str,
        db: Any = None,
        forced_channels: Optional[List[str]] = None,
        html_message: Optional[str] = None,
        slack_blocks: Optional[List[Dict[str, Any]]] = None,
        mattermost_props: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Send a notification to multiple users."""
        system_settings = None
        if db is not None:
            repo = SystemSettingsRepository(db)
            system_settings = await repo.get()

        tasks = []
        for user in users:
            prefs = {event_type: forced_channels} if forced_channels else (user.notification_preferences or {})

            tasks.append(
                self._send_based_on_prefs(
                    user,
                    prefs,
                    event_type,
                    subject,
                    message,
                    system_settings,
                    html_message=html_message,
                    slack_blocks=slack_blocks,
                    mattermost_props=mattermost_props,
                )
            )

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Notification task failed: {result}")

    async def notify_users_with_permission(
        self,
        db: Any,
        *,
        permission: str | List[str],
        event_type: str,
        subject: str,
        message: str,
        forced_channels: Optional[List[str]] = None,
        html_message: Optional[str] = None,
        slack_blocks: Optional[List[Dict[str, Any]]] = None,
        mattermost_props: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Notify all active users whose permissions include any of the given permission(s)."""
        perms = [permission] if isinstance(permission, str) else list(permission)
        if not perms:
            return

        cursor = db.users.find({"permissions": {"$in": perms}, "is_active": True})
        # Bounded fetch: safe ceiling on the admin-scale result set.
        user_docs = await cursor.to_list(length=1000)
        if not user_docs:
            return

        users = [User(**u) for u in user_docs]
        await self.notify_users(
            users,
            event_type=event_type,
            subject=subject,
            message=message,
            db=db,
            forced_channels=forced_channels,
            html_message=html_message,
            slack_blocks=slack_blocks,
            mattermost_props=mattermost_props,
        )

    async def notify_project_members(
        self,
        project: Project,
        event_type: str,
        subject: str,
        message: str,
        db: Any,
        forced_channels: Optional[List[str]] = None,
        html_message: Optional[str] = None,
        slack_blocks: Optional[List[Dict[str, Any]]] = None,
        mattermost_props: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Send notifications to project members."""
        repo = SystemSettingsRepository(db)
        system_settings = await repo.get()

        # user_id -> project-specific prefs (or None if no override)
        targets: Dict[str, Optional[Dict[str, List[str]]]] = {}

        if project.members:
            for member in project.members:
                m_prefs = member.notification_preferences if member.notification_preferences else None

                if member.user_id in targets and targets[member.user_id] is not None:
                    continue

                targets[member.user_id] = m_prefs

        if project.team_id:
            team_data = await db.teams.find_one({"_id": project.team_id})
            if team_data:
                for tm in team_data.get("members", []):
                    uid = tm["user_id"]
                    if uid not in targets:
                        # implicit team members have no project-specific override
                        targets[uid] = None

        user_ids = list(targets.keys())
        if not user_ids:
            return

        users_cursor = db.users.find({"_id": {"$in": user_ids}})
        users_list = await users_cursor.to_list(length=len(user_ids))
        users_map = {str(u["_id"]): User(**u) for u in users_list}

        enforced_prefs = None
        if project.enforce_notification_settings and project.members:
            admin_member = next((m for m in project.members if m.role == "admin" and m.notification_preferences), None)
            if admin_member:
                enforced_prefs = admin_member.notification_preferences

        tasks = []
        for user_id, specific_prefs in targets.items():
            user = users_map.get(user_id)
            if not user:
                continue

            effective_prefs: Dict[str, List[str]] = {}
            if forced_channels:
                effective_prefs = {event_type: forced_channels}
            else:
                effective_prefs = user.notification_preferences or {}

                if enforced_prefs:
                    effective_prefs = enforced_prefs
                elif specific_prefs:
                    effective_prefs = specific_prefs

            if not effective_prefs:
                continue

            tasks.append(
                self._send_based_on_prefs(
                    user,
                    effective_prefs,
                    event_type,
                    subject,
                    message,
                    system_settings,
                    html_message=html_message,
                    slack_blocks=slack_blocks,
                    mattermost_props=mattermost_props,
                )
            )

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Notification task failed: {result}")


notification_service = NotificationService()


async def safe_notify_project_event(
    db: Any,
    project_id: Optional[str],
    event_type: str,
    subject: str,
    message: str,
    *,
    html_message: Optional[str] = None,
    context: str = "notify",
) -> None:
    """Look up the project and dispatch the event to its members; errors are logged, never raised."""
    if not project_id:
        return
    try:
        from app.repositories.projects import ProjectRepository  # late import: circular

        project = await ProjectRepository(db).get_by_id(project_id)
        if project is None:
            return
        await notification_service.notify_project_members(
            project=project,
            event_type=event_type,
            subject=subject,
            message=message,
            db=db,
            html_message=html_message,
        )
    except Exception:
        logger.exception("%s: notification dispatch for %s failed (non-blocking)", context, event_type)
