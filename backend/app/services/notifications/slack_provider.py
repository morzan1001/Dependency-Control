import httpx
import logging
from typing import Optional
from app.services.notifications.base import NotificationProvider
from app.models.system import SystemSettings

logger = logging.getLogger(__name__)

class SlackProvider(NotificationProvider):
    async def send(self, destination: str, subject: str, message: str, system_settings: Optional[SystemSettings] = None) -> bool:
        slack_token = system_settings.slack_bot_token if system_settings else None

        if not slack_token:
            logger.warning("SLACK_BOT_TOKEN not configured. Skipping Slack notification.")
            return False

        # Slack API 'chat.postMessage' accepts channel IDs, names, or user IDs.
        
        url = "https://slack.com/api/chat.postMessage"
        headers = {
            "Authorization": f"Bearer {slack_token}",
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
                if response.status_code == 200 and response.json().get("ok"):
                    logger.info(f"Slack message sent to {destination}")
                    return True
                else:
                    logger.error(f"Failed to send Slack message: {response.text}")
                    return False
        except Exception as e:
            logger.error(f"Error sending Slack message: {e}")
            return False
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
