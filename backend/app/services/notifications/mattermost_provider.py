import httpx
import logging
from typing import Optional
from app.core.config import settings
from app.services.notifications.base import NotificationProvider

logger = logging.getLogger(__name__)

class MattermostProvider(NotificationProvider):
    def __init__(self):
        self.bot_user_id: Optional[str] = None
        self.base_url = settings.MATTERMOST_URL.rstrip("/") if settings.MATTERMOST_URL else ""
        self.headers = {
            "Authorization": f"Bearer {settings.MATTERMOST_BOT_TOKEN}",
            "Content-Type": "application/json"
        }

    async def _get_bot_user_id(self, client: httpx.AsyncClient) -> Optional[str]:
        if self.bot_user_id:
            return self.bot_user_id
        
        try:
            response = await client.get(f"{self.base_url}/api/v4/users/me", headers=self.headers)
            if response.status_code == 200:
                self.bot_user_id = response.json()["id"]
                return self.bot_user_id
            else:
                logger.error(f"Failed to get Mattermost bot ID: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error getting Mattermost bot ID: {e}")
            return None

    async def _get_user_id_by_username(self, client: httpx.AsyncClient, username: str) -> Optional[str]:
        # Remove @ if present
        username = username.lstrip("@")
        try:
            response = await client.get(f"{self.base_url}/api/v4/users/username/{username}", headers=self.headers)
            if response.status_code == 200:
                return response.json()["id"]
            else:
                logger.warning(f"Mattermost user '{username}' not found: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error getting Mattermost user ID for {username}: {e}")
            return None

    async def _create_dm_channel(self, client: httpx.AsyncClient, user_id: str) -> Optional[str]:
        bot_id = await self._get_bot_user_id(client)
        if not bot_id:
            return None
            
        try:
            payload = [bot_id, user_id]
            response = await client.post(f"{self.base_url}/api/v4/channels/direct", headers=self.headers, json=payload)
            if response.status_code in [200, 201]:
                return response.json()["id"]
            else:
                logger.error(f"Failed to create Mattermost DM channel: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error creating Mattermost DM channel: {e}")
            return None

    async def send(self, destination: str, subject: str, message: str) -> bool:
        if not settings.MATTERMOST_BOT_TOKEN or not settings.MATTERMOST_URL:
            logger.warning("Mattermost not configured. Skipping notification.")
            return False

        async with httpx.AsyncClient() as client:
            # 1. Resolve User ID
            user_id = await self._get_user_id_by_username(client, destination)
            if not user_id:
                return False
            
            # 2. Get/Create DM Channel
            channel_id = await self._create_dm_channel(client, user_id)
            if not channel_id:
                return False
            
            # 3. Post Message
            url = f"{self.base_url}/api/v4/posts"
            payload = {
                "channel_id": channel_id,
                "message": f"**{subject}**\n{message}"
            }

            try:
                response = await client.post(url, headers=self.headers, json=payload)
                if response.status_code == 201:
                    logger.info(f"Mattermost message sent to {destination}")
                    return True
                else:
                    logger.error(f"Failed to send Mattermost message: {response.text}")
                    return False
            except Exception as e:
                logger.error(f"Error sending Mattermost message: {e}")
                return False
