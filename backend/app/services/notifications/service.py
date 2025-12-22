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
    ):
        channels = prefs.get(event_type, [])

        if "email" in channels and user.email:
            await self.email_provider.send(
                user.email, subject, message, system_settings=system_settings
            )

        if "slack" in channels and user.slack_username:
            await self.slack_provider.send(
                user.slack_username, subject, message, system_settings=system_settings
            )

        if "mattermost" in channels and user.mattermost_username:
            await self.mattermost_provider.send(
                user.mattermost_username,
                subject,
                message,
                system_settings=system_settings,
            )

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
        self, users: List[User], event_type: str, subject: str, message: str, db=None
    ):
        """
        Send a notification to multiple users.
        """
        for user in users:
            await self.notify_user(user, event_type, subject, message, db)

    async def notify_project_members(
        self, project: Project, event_type: str, subject: str, message: str, db
    ):
        """
        Send notifications to project members (and owner) based on their project-specific preferences.
        """
        # Fetch System Settings
        system_settings = None
        settings_data = await db.system_settings.find_one({"_id": "current"})
        if settings_data:
            system_settings = SystemSettings(**settings_data)

        # Determine preferences to use
        enforced_prefs = None
        if project.enforce_notification_settings:
            enforced_prefs = project.owner_notification_preferences

        # 1. Check Owner
        owner_prefs = (
            enforced_prefs if enforced_prefs else project.owner_notification_preferences
        )
        if owner_prefs and event_type in owner_prefs:
            owner_data = await db.users.find_one({"_id": project.owner_id})
            if owner_data:
                owner = User(**owner_data)
                await self._send_based_on_prefs(
                    owner, owner_prefs, event_type, subject, message, system_settings
                )

        # 2. Check Members
        for member in project.members:
            member_prefs = (
                enforced_prefs if enforced_prefs else member.notification_preferences
            )
            if member_prefs and event_type in member_prefs:
                user_data = await db.users.find_one({"_id": member.user_id})
                if user_data:
                    user = User(**user_data)
                    await self._send_based_on_prefs(
                        user,
                        member_prefs,
                        event_type,
                        subject,
                        message,
                        system_settings,
                    )


notification_service = NotificationService()
