import asyncio
import logging
from typing import Dict, List, Optional

from app.models.project import Project
from app.models.system import SystemSettings
from app.models.user import User
from app.services.notifications.email_provider import EmailProvider
from app.services.notifications.mattermost_provider import MattermostProvider
from app.services.notifications.slack_provider import SlackProvider

logger = logging.getLogger(__name__)


class NotificationService:
    def __init__(self):
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
    ):
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
                )
            )

        if "slack" in channels and user.slack_username:
            tasks.append(
                self.slack_provider.send(
                    user.slack_username,
                    subject,
                    message,
                    system_settings=system_settings,
                )
            )

        if "mattermost" in channels and user.mattermost_username:
            tasks.append(
                self.mattermost_provider.send(
                    user.mattermost_username,
                    subject,
                    message,
                    system_settings=system_settings,
                )
            )

        if tasks:
            await asyncio.gather(*tasks)

    async def notify_user(
        self, user: User, event_type: str, subject: str, message: str, db=None
    ):
        """
        Send a notification to a user based on their global preferences.
        """
        if not user.notification_preferences:
            return

        system_settings = None
        if db:
            settings_data = await db.system_settings.find_one({"_id": "current"})
            if settings_data:
                system_settings = SystemSettings(**settings_data)

        await self._send_based_on_prefs(
            user,
            user.notification_preferences,
            event_type,
            subject,
            message,
            system_settings,
        )

    async def notify_users(
        self,
        users: List[User],
        event_type: str,
        subject: str,
        message: str,
        db=None,
        forced_channels: Optional[List[str]] = None,
        html_message: Optional[str] = None,
    ):
        """
        Send a notification to multiple users.
        """
        system_settings = None
        if db:
            settings_data = await db.system_settings.find_one({"_id": "current"})
            if settings_data:
                system_settings = SystemSettings(**settings_data)

        tasks = []
        for user in users:
            # If forced_channels is set use it, otherwise use user prefs for event
            prefs = (
                {event_type: forced_channels}
                if forced_channels
                else (user.notification_preferences or {})
            )

            tasks.append(
                self._send_based_on_prefs(
                    user,
                    prefs,
                    event_type,
                    subject,
                    message,
                    system_settings,
                    html_message=html_message,
                )
            )

        if tasks:
            await asyncio.gather(*tasks)

    async def notify_project_members(
        self,
        project: Project,
        event_type: str,
        subject: str,
        message: str,
        db,
        forced_channels: Optional[List[str]] = None,
        html_message: Optional[str] = None,
    ):
        """
        Send notifications to project members.
        """
        # Fetch System Settings
        system_settings = None
        settings_data = await db.system_settings.find_one({"_id": "current"})
        if settings_data:
            system_settings = SystemSettings(**settings_data)

        # 1. Identify all target users and their project-specific overrides
        # Map: user_id -> specific_prefs (or None if no override)
        targets: Dict[str, Optional[Dict[str, List[str]]]] = {}

        # 1a. Owner
        owner_id = project.owner_id
        targets[owner_id] = project.owner_notification_preferences

        # 1b. Project Members
        if project.members:
            for member in project.members:
                # If member has configured preferences (non-empty), use them.
                # Otherwise, treat as None (fallback to Global later)
                # Note: ProjectMember.notification_preferences defaults to {}
                m_prefs = (
                    member.notification_preferences
                    if member.notification_preferences
                    else None
                )

                # If user already in targets (e.g. Owner), prioritize existing value IF it is set
                # But here, Owner prefs is managed in project.owner_notification_preferences.
                # If that was set, targets[owner_id] is set. Member prefs is likely empty for owner.
                if member.user_id in targets and targets[member.user_id] is not None:
                    continue

                targets[member.user_id] = m_prefs

        # 1c. Team Members
        if project.team_id:
            team_data = await db.teams.find_one({"_id": project.team_id})
            if team_data:
                for tm in team_data.get("members", []):
                    uid = tm["user_id"]
                    if uid not in targets:
                        targets[uid] = (
                            None  # No project specific override possible for implicit team members
                        )

        # 2. Bulk Fetch Users
        user_ids = list(targets.keys())
        if not user_ids:
            return

        users_cursor = db.users.find({"_id": {"$in": user_ids}})
        users_list = await users_cursor.to_list(length=len(user_ids))
        users_map = {str(u["_id"]): User(**u) for u in users_list}

        # 3. Determine Enforced Settings
        enforced_prefs = (
            project.owner_notification_preferences
            if project.enforce_notification_settings
            else None
        )

        # 4. Iterate and Send
        tasks = []
        for user_id, specific_prefs in targets.items():
            user = users_map.get(user_id)
            if not user:
                continue

            effective_prefs: Dict[str, List[str]] = {}
            if forced_channels:
                effective_prefs = {event_type: forced_channels}
            else:
                # Determine effective preferences
                effective_prefs = user.notification_preferences or {}

                if enforced_prefs:
                    effective_prefs = enforced_prefs
                elif specific_prefs:
                    effective_prefs = specific_prefs

            # If effective_prefs is None or empty at this point, checking keys will happen in _send_based_on_prefs
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
                )
            )

        if tasks:
            await asyncio.gather(*tasks)


notification_service = NotificationService()
