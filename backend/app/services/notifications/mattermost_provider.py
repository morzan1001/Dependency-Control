import logging
from typing import Any

from app.core.config import settings
from app.core.http_utils import InstrumentedAsyncClient
from app.core.metrics import notifications_failed_total, notifications_sent_total
from app.models.system import SystemSettings
from app.services.notifications.base import NotificationProvider

logger = logging.getLogger(__name__)


class MattermostProvider(NotificationProvider):
    async def _get_user_id(
        self, client: InstrumentedAsyncClient, user_path: str, base_url: str, headers: dict
    ) -> str | None:
        try:
            response = await client.get(f"{base_url}/api/v4/users/{user_path}", headers=headers)
            if response.status_code == 200:
                user_id: str | None = response.json()["id"]
                return user_id
            logger.warning(f"Mattermost user lookup '{user_path}' failed: {response.text}")
            return None
        except Exception as e:
            logger.exception("Error looking up Mattermost user %s: %s", user_path, e)
            return None

    async def _create_dm_channel(
        self, client: InstrumentedAsyncClient, user_id: str, base_url: str, headers: dict
    ) -> str | None:
        bot_id = await self._get_user_id(client, "me", base_url, headers)
        if not bot_id:
            return None

        try:
            payload = [bot_id, user_id]
            response = await client.post(f"{base_url}/api/v4/channels/direct", headers=headers, json=payload)
            if response.status_code in [200, 201]:
                dm_channel_id: str | None = response.json()["id"]
                return dm_channel_id
            logger.error(f"Failed to create Mattermost DM channel: {response.text}")
            return None
        except Exception as e:
            logger.exception("Error creating Mattermost DM channel: %s", e)
            return None

    async def send(
        self,
        destination: str,
        subject: str,
        message: str,
        system_settings: SystemSettings | None = None,
        **kwargs: Any,
    ) -> bool:
        mattermost_url = system_settings.mattermost_url if system_settings else None
        mattermost_token = system_settings.mattermost_bot_token if system_settings else None

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
                user_id = await self._get_user_id(client, f"username/{destination}", base_url, headers)
                if not user_id:
                    logger.error(f"Cannot send Mattermost DM: User {destination} not found")
                    notifications_failed_total.labels(type="mattermost").inc()
                    return False

                channel_id = await self._create_dm_channel(client, user_id, base_url, headers)
                if not channel_id:
                    logger.error(f"Cannot send Mattermost DM: Failed to create channel for {destination}")
                    notifications_failed_total.labels(type="mattermost").inc()
                    return False

                from app.services.notifications.mattermost_formatter import build_generic_props

                props = kwargs.get("props")
                if not props:
                    props = build_generic_props(subject, message)

                payload = {
                    "channel_id": channel_id,
                    "message": "",
                    "props": props,
                }

                response = await client.post(f"{base_url}/api/v4/posts", headers=headers, json=payload)

                if response.status_code == 201:
                    logger.info(f"Mattermost message sent to {destination}")
                    notifications_sent_total.labels(type="mattermost").inc()
                    return True
                logger.error(f"Failed to send Mattermost notification: {response.text}")
                notifications_failed_total.labels(type="mattermost").inc()
                return False

        except Exception as e:
            logger.exception("Error sending Mattermost notification: %s", e)
            notifications_failed_total.labels(type="mattermost").inc()
            return False
