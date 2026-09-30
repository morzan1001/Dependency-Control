import asyncio
import logging
from typing import Any

from app.core import abatched
from app.core.constants import (
    NOTIFICATION_CHANNEL_EMAIL,
    NOTIFICATION_CHANNEL_MATTERMOST,
    NOTIFICATION_CHANNEL_SLACK,
    NotificationEvent,
)
from app.models.project import Project
from app.models.user import User
from app.repositories.projects import ProjectRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.repositories.teams import TeamRepository
from app.repositories.users import UserRepository
from app.services.notifications.email_provider import EmailProvider
from app.services.notifications.mattermost_provider import MattermostProvider
from app.services.notifications.slack_provider import SlackProvider

logger = logging.getLogger(__name__)

# Bounds how many recipients are held in memory at once, never how many are reached.
_FAN_OUT_BATCH_SIZE = 500

_PROJECT_RECIPIENT_FIELDS = dict.fromkeys(
    (
        "name",
        "members",
        "team_ids",
        "enforce_notification_settings",
        "enforced_notification_preferences",
        "notification_overrides",
    ),
    1,
)


class NotificationService:
    def __init__(self) -> None:
        self.email_provider = EmailProvider()
        self.slack_provider = SlackProvider()
        self.mattermost_provider = MattermostProvider()

    async def _deliver(
        self,
        db: Any,
        recipients: list[tuple[User, list[str]]],
        subject: str,
        message: str,
        *,
        html_message: str | None = None,
        slack_blocks: list[dict[str, Any]] | None = None,
        mattermost_props: dict[str, Any] | None = None,
    ) -> None:
        """Send each recipient the message on their channels; one failed send never cancels the others."""
        if not any(channels for _, channels in recipients):
            return
        system_settings = await SystemSettingsRepository(db).get()
        sends = []
        for user, channels in recipients:
            if NOTIFICATION_CHANNEL_EMAIL in channels and user.email:
                sends.append(
                    self.email_provider.send(
                        user.email, subject, message, system_settings=system_settings, html_message=html_message
                    )
                )
            if NOTIFICATION_CHANNEL_SLACK in channels and user.slack_username:
                # A member ID, for which chat.postMessage finds no channel once it carries a leading '@'.
                sends.append(
                    self.slack_provider.send(
                        user.slack_username.lstrip("@"),
                        subject,
                        message,
                        system_settings=system_settings,
                        blocks=slack_blocks,
                    )
                )
            if NOTIFICATION_CHANNEL_MATTERMOST in channels and user.mattermost_username:
                # A username, which the provider resolves to the direct-message channel only with a leading '@'.
                sends.append(
                    self.mattermost_provider.send(
                        "@" + user.mattermost_username.lstrip("@"),
                        subject,
                        message,
                        system_settings=system_settings,
                        props=mattermost_props,
                    )
                )
        for result in await asyncio.gather(*sends, return_exceptions=True):
            if isinstance(result, Exception):
                logger.error("Notification send failed: %s", result)

    async def notify_users(
        self,
        users: list[User],
        event_type: NotificationEvent,
        subject: str,
        message: str,
        *,
        db: Any,
        forced_channels: list[str] | None = None,
        html_message: str | None = None,
        slack_blocks: list[dict[str, Any]] | None = None,
        mattermost_props: dict[str, Any] | None = None,
    ) -> None:
        """Send each user the event on the forced channels, else on their own preferences."""
        await self._deliver(
            db,
            [(user, forced_channels or (user.notification_preferences or {}).get(event_type, [])) for user in users],
            subject,
            message,
            html_message=html_message,
            slack_blocks=slack_blocks,
            mattermost_props=mattermost_props,
        )

    async def notify_users_with_permission(
        self,
        db: Any,
        *,
        permission: list[str],
        event_type: NotificationEvent,
        subject: str,
        message: str,
    ) -> None:
        """Notify all active users whose permissions include any of the given ones."""
        query = {"permissions": {"$in": permission}, "is_active": True}
        await self._notify_matching(db, query, event_type=event_type, subject=subject, message=message)

    async def _notify_matching(
        self,
        db: Any,
        query: dict[str, Any],
        *,
        event_type: NotificationEvent,
        subject: str,
        message: str,
        forced_channels: list[str] | None = None,
        html_message: str | None = None,
        slack_blocks: list[dict[str, Any]] | None = None,
        mattermost_props: dict[str, Any] | None = None,
    ) -> None:
        """Notify every user the query matches, one batch in memory at a time."""
        async for batch in abatched(UserRepository(db).iterate(query), _FAN_OUT_BATCH_SIZE):
            await self.notify_users(
                batch,
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
        event_type: NotificationEvent,
        subject: str,
        message: str,
        db: Any,
        html_message: str | None = None,
        slack_blocks: list[dict[str, Any]] | None = None,
        mattermost_props: dict[str, Any] | None = None,
    ) -> None:
        """Notify the active direct and owning-team members; enforced, then project, then account preferences."""
        enforced = (project.enforced_notification_preferences or {}) if project.enforce_notification_settings else None
        if enforced is not None and not enforced.get(event_type):
            return

        project_prefs = {m.user_id: m.notification_preferences for m in project.members}
        for team_members in (await TeamRepository(db).members_by_team(project.team_ids)).values():
            for member in team_members:
                project_prefs.setdefault(member["user_id"], project.notification_overrides.get(member["user_id"]))

        recipients = []
        for doc in await UserRepository(db).find_by_ids(list(project_prefs)):
            user = User(**doc)
            if user.is_active:
                prefs = enforced or project_prefs[user.id] or user.notification_preferences or {}
                recipients.append((user, prefs.get(event_type, [])))
        await self._deliver(
            db,
            recipients,
            subject,
            message,
            html_message=html_message,
            slack_blocks=slack_blocks,
            mattermost_props=mattermost_props,
        )


notification_service = NotificationService()


async def safe_notify_project_event(
    db: Any,
    project_id: str | None,
    event_type: NotificationEvent,
    subject: str,
    message: str,
    *,
    html_message: str | None = None,
    context: str = "notify",
) -> None:
    """Look up the project and dispatch the event to its members; errors are logged, never raised."""
    if not project_id:
        return
    try:
        doc = await ProjectRepository(db).find_one_raw({"_id": project_id}, _PROJECT_RECIPIENT_FIELDS)
        if doc is None:
            return
        await notification_service.notify_project_members(
            Project(**doc), event_type, subject, message, db, html_message=html_message
        )
    except Exception:
        logger.exception("%s: notification dispatch for %s failed (non-blocking)", context, event_type)
