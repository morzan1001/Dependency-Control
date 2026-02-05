import asyncio
import logging
from typing import Optional

import httpx

from app.core.config import settings
from app.core.http_utils import InstrumentedAsyncClient
from app.models.system import SystemSettings
from app.services.notifications.base import NotificationProvider

logger = logging.getLogger(__name__)

# Import metrics for notification tracking
try:
    from app.core.metrics import notifications_failed_total, notifications_sent_total
except ImportError:
    notifications_sent_total = None
    notifications_failed_total = None


class MattermostProvider(NotificationProvider):
    def __init__(self):
        self._bot_user_id: Optional[str] = None
        # Lock to prevent concurrent bot ID fetches within the same pod
        self._bot_id_lock = asyncio.Lock()

    async def _get_bot_user_id(
        self, client: httpx.AsyncClient, base_url: str, headers: dict
    ) -> Optional[str]:
        if self._bot_user_id:
            return self._bot_user_id

        # Use lock to prevent concurrent fetches
        async with self._bot_id_lock:
            # Double-check after acquiring lock
            if self._bot_user_id:
                return self._bot_user_id

            try:
                response = await client.get(
                    f"{base_url}/api/v4/users/me", headers=headers
                )
                if response.status_code == 200:
                    self._bot_user_id = response.json()["id"]
                    return self._bot_user_id
                else:
                    logger.error(f"Failed to get Mattermost bot ID: {response.text}")
                    return None
            except Exception as e:
                logger.error(f"Error getting Mattermost bot ID: {e}")
                return None

    async def _get_user_id_by_username(
        self, client: httpx.AsyncClient, username: str, base_url: str, headers: dict
    ) -> Optional[str]:
        # Remove @ if present
        username = username.lstrip("@")
        try:
            response = await client.get(
                f"{base_url}/api/v4/users/username/{username}", headers=headers
            )
            if response.status_code == 200:
                return response.json()["id"]
            else:
                logger.warning(
                    f"Mattermost user '{username}' not found: {response.text}"
                )
                return None
        except Exception as e:
            logger.error(f"Error getting Mattermost user ID for {username}: {e}")
            return None

    async def _create_dm_channel(
        self, client: httpx.AsyncClient, user_id: str, base_url: str, headers: dict
    ) -> Optional[str]:
        bot_id = await self._get_bot_user_id(client, base_url, headers)
        if not bot_id:
            return None

        try:
            payload = [bot_id, user_id]
            response = await client.post(
                f"{base_url}/api/v4/channels/direct", headers=headers, json=payload
            )
            if response.status_code in [200, 201]:
                return response.json()["id"]
            else:
                logger.error(f"Failed to create Mattermost DM channel: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error creating Mattermost DM channel: {e}")
            return None

    async def _get_channel_id_by_name(
        self, client: httpx.AsyncClient, channel_name: str, base_url: str, headers: dict
    ) -> Optional[str]:
        # Remove # if present
        channel_name = channel_name.lstrip("#")

        # First, get teams the bot is in
        try:
            response = await client.get(
                f"{base_url}/api/v4/users/me/teams", headers=headers
            )
            if response.status_code != 200:
                logger.warning(f"Failed to get Mattermost teams: {response.text}")
                return None

            teams = response.json()
            for team in teams:
                team_id = team["id"]
                # Try to find channel in this team
                chan_response = await client.get(
                    f"{base_url}/api/v4/teams/{team_id}/channels/name/{channel_name}",
                    headers=headers,
                )
                if chan_response.status_code == 200:
                    return chan_response.json()["id"]

            logger.warning(
                f"Mattermost channel '{channel_name}' not found in any team."
            )
            return None

        except Exception as e:
            logger.error(f"Error resolving Mattermost channel {channel_name}: {e}")
            return None

    async def send(
        self,
        destination: str,
        subject: str,
        message: str,
        system_settings: Optional[SystemSettings] = None,
    ) -> bool:
        # Determine configuration
        mattermost_url = system_settings.mattermost_url if system_settings else None
        mattermost_token = (
            system_settings.mattermost_bot_token if system_settings else None
        )

        if not mattermost_token or not mattermost_url:
            logger.warning("Mattermost not configured. Skipping notification.")
            return False

        base_url = mattermost_url.rstrip("/")
        headers = {
            "Authorization": f"Bearer {mattermost_token}",
            "Content-Type": "application/json",
        }

        try:
            async with InstrumentedAsyncClient(
                "Mattermost API", timeout=settings.NOTIFICATION_HTTP_TIMEOUT_SECONDS
            ) as client:
                channel_id = destination

                # If destination looks like a username, try to resolve it to a DM channel
                if destination.startswith("@"):
                    user_id = await self._get_user_id_by_username(
                        client, destination, base_url, headers
                    )
                    if not user_id:
                        logger.error(
                            f"Cannot send Mattermost DM: User {destination} not found"
                        )
                        if notifications_failed_total:
                            notifications_failed_total.labels(type="mattermost").inc()
                        return False

                    dm_channel_id = await self._create_dm_channel(
                        client, user_id, base_url, headers
                    )
                    if not dm_channel_id:
                        logger.error(
                            f"Cannot send Mattermost DM: Failed to create channel for {destination}"
                        )
                        if notifications_failed_total:
                            notifications_failed_total.labels(type="mattermost").inc()
                        return False

                    channel_id = dm_channel_id
                # If it looks like a channel name (starts with # or no special chars and not a UUID)
                elif destination.startswith("#"):
                    # Channel name with # prefix - must be resolved
                    resolved_id = await self._get_channel_id_by_name(
                        client, destination, base_url, headers
                    )
                    if not resolved_id:
                        logger.error(
                            f"Cannot send Mattermost message: Channel {destination} not found"
                        )
                        if notifications_failed_total:
                            notifications_failed_total.labels(type="mattermost").inc()
                        return False
                    channel_id = resolved_id
                elif destination.count("-") != 4:
                    # Not a UUID (UUIDs have exactly 4 dashes) - try to resolve as channel name
                    resolved_id = await self._get_channel_id_by_name(
                        client, destination, base_url, headers
                    )
                    if resolved_id:
                        channel_id = resolved_id

                payload = {
                    "channel_id": channel_id,
                    "message": f"#### {subject}\n{message}",
                }

                response = await client.post(
                    f"{base_url}/api/v4/posts", headers=headers, json=payload
                )

                if response.status_code == 201:
                    logger.info(f"Mattermost message sent to {destination}")
                    if notifications_sent_total:
                        notifications_sent_total.labels(type="mattermost").inc()
                    return True
                else:
                    logger.error(
                        f"Failed to send Mattermost notification: {response.text}"
                    )
                    if notifications_failed_total:
                        notifications_failed_total.labels(type="mattermost").inc()
                    return False

        except Exception as e:
            logger.error(f"Error sending Mattermost notification: {e}")
            if notifications_failed_total:
                notifications_failed_total.labels(type="mattermost").inc()
            return False
