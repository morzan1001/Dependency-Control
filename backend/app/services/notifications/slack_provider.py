import httpx
import logging
from app.core.config import settings
from app.services.notifications.base import NotificationProvider

logger = logging.getLogger(__name__)

class SlackProvider(NotificationProvider):
    async def send(self, destination: str, subject: str, message: str) -> bool:
        if not settings.SLACK_BOT_TOKEN:
            logger.warning("SLACK_BOT_TOKEN not configured. Skipping Slack notification.")
            return False

        # If destination is a username (starts with @) or channel (#), we might need to resolve it 
        # or just pass it to channel. Slack API 'chat.postMessage' accepts channel IDs, names, or user IDs.
        # Ideally, we should store the Slack User ID (U123456) instead of username, 
        # but for simplicity we'll try to use what is provided.
        
        url = "https://slack.com/api/chat.postMessage"
        headers = {
            "Authorization": f"Bearer {settings.SLACK_BOT_TOKEN}",
            "Content-Type": "application/json"
        }
        
        # Format the message nicely
        payload = {
            "channel": destination,
            "text": f"*{subject}*\n{message}"
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(url, headers=headers, json=payload)
                data = response.json()
                
                if data.get("ok"):
                    logger.info(f"Slack message sent to {destination}")
                    return True
                else:
                    logger.error(f"Failed to send Slack message: {data.get('error')}")
                    return False
        except Exception as e:
            logger.error(f"Error sending Slack message: {e}")
            return False
