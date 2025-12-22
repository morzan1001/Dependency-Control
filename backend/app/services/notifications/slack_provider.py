import logging
import time
from typing import Optional

import httpx

from app.db.mongodb import get_database
from app.models.system import SystemSettings
from app.services.notifications.base import NotificationProvider

logger = logging.getLogger(__name__)


class SlackProvider(NotificationProvider):
    async def _refresh_token(self, system_settings: SystemSettings) -> Optional[str]:
        """
        Refreshes the Slack access token using the refresh token.
        Updates the database with the new token and expiration.
        """
        if (
            not system_settings.slack_client_id
            or not system_settings.slack_client_secret
            or not system_settings.slack_refresh_token
        ):
            logger.error(
                "Cannot refresh Slack token: Missing client_id, client_secret, or refresh_token."
            )
            return None

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://slack.com/api/oauth.v2.access",
                    data={
                        "client_id": system_settings.slack_client_id,
                        "client_secret": system_settings.slack_client_secret,
                        "grant_type": "refresh_token",
                        "refresh_token": system_settings.slack_refresh_token,
                    },
                )

                if response.status_code != 200:
                    logger.error(
                        f"Failed to refresh Slack token. Status: {response.status_code}, Body: {response.text}"
                    )
                    return None

                result = response.json()
                if not result.get("ok"):
                    logger.error(
                        f"Slack API Error during refresh: {result.get('error')}"
                    )
                    return None

                new_access_token = result.get("access_token")
                new_refresh_token = result.get("refresh_token")
                expires_in = result.get("expires_in")

                # Update database
                db = await get_database()

                update_data = {
                    "slack_bot_token": new_access_token,
                }
                if new_refresh_token:
                    update_data["slack_refresh_token"] = new_refresh_token
                if expires_in:
                    update_data["slack_token_expires_at"] = time.time() + expires_in

                await db.system_settings.update_one(
                    {"_id": "current"}, {"$set": update_data}
                )

                logger.info("Successfully refreshed Slack token")
                return new_access_token

        except Exception as e:
            logger.error(f"Error refreshing Slack token: {e}")
            return None

    async def send(
        self,
        destination: str,
        subject: str,
        message: str,
        system_settings: Optional[SystemSettings] = None,
    ) -> bool:
        if not system_settings:
            return False

        slack_token = system_settings.slack_bot_token

        # Check for expiration and refresh if needed
        # Buffer of 5 minutes
        if (
            system_settings.slack_token_expires_at
            and system_settings.slack_token_expires_at < (time.time() + 300)
        ):
            logger.info("Slack token expired or expiring soon. Refreshing...")
            new_token = await self._refresh_token(system_settings)
            if new_token:
                slack_token = new_token
            else:
                logger.warning(
                    "Failed to refresh Slack token, attempting to use existing token."
                )

        if not slack_token:
            logger.warning(
                "SLACK_BOT_TOKEN not configured. Skipping Slack notification."
            )
            return False

        # Slack API 'chat.postMessage' accepts channel IDs, names, or user IDs.

        url = "https://slack.com/api/chat.postMessage"
        headers = {
            "Authorization": f"Bearer {slack_token}",
            "Content-Type": "application/json",
        }

        # Format the message nicely
        payload = {"channel": destination, "text": f"*{subject}*\n{message}"}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(url, headers=headers, json=payload)
                if response.status_code == 200 and response.json().get("ok"):
                    logger.info(f"Slack message sent to {destination}")
                    return True
                else:
                    logger.error(f"Failed to send Slack message: {response.text}")
                    return False
        except Exception as e:
            logger.error(f"Error sending Slack message: {e}")
            return False
