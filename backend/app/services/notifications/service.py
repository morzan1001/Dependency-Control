import logging
from typing import List, Dict
from app.models.user import User
from app.models.project import Project
from app.services.notifications.email_provider import EmailProvider
from app.services.notifications.slack_provider import SlackProvider
from app.services.notifications.mattermost_provider import MattermostProvider

logger = logging.getLogger(__name__)

class NotificationService:
    def __init__(self):
        self.email_provider = EmailProvider()
        self.slack_provider = SlackProvider()
        self.mattermost_provider = MattermostProvider()

    async def _send_based_on_prefs(self, user: User, prefs: Dict[str, List[str]], event_type: str, subject: str, message: str):
        channels = prefs.get(event_type, [])
        
        if "email" in channels and user.email:
            await self.email_provider.send(user.email, subject, message)
        
        if "slack" in channels and user.slack_username:
            await self.slack_provider.send(user.slack_username, subject, message)
            
        if "mattermost" in channels and user.mattermost_username:
            await self.mattermost_provider.send(user.mattermost_username, subject, message)

    async def notify_user(self, user: User, event_type: str, subject: str, message: str):
        """
        Send a notification to a user based on their global preferences.
        """
        if not user.notification_preferences:
            return
        
        await self._send_based_on_prefs(user, user.notification_preferences, event_type, subject, message)

    async def notify_users(self, users: List[User], event_type: str, subject: str, message: str):
        """
        Send a notification to multiple users.
        """
        for user in users:
            await self.notify_user(user, event_type, subject, message)

    async def notify_project_members(self, project: Project, event_type: str, subject: str, message: str, db):
        """
        Send notifications to project members (and owner) based on their project-specific preferences.
        """
        # 1. Check Owner
        if project.owner_notification_preferences and event_type in project.owner_notification_preferences:
             owner_data = await db.users.find_one({"_id": project.owner_id})
             if owner_data:
                 owner = User(**owner_data)
                 await self._send_based_on_prefs(owner, project.owner_notification_preferences, event_type, subject, message)

        # 2. Check Members
        for member in project.members:
            if member.notification_preferences and event_type in member.notification_preferences:
                user_data = await db.users.find_one({"_id": member.user_id})
                if user_data:
                    user = User(**user_data)
                    await self._send_based_on_prefs(user, member.notification_preferences, event_type, subject, message)

notification_service = NotificationService()
