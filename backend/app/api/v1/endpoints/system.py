from fastapi import APIRouter
from typing import List, Dict
from app.core.config import settings

router = APIRouter()

@router.get("/notifications/channels", response_model=List[str], summary="Get available notification channels")
async def get_notification_channels():
    """
    Returns a list of available notification channels based on the server configuration.
    """
    channels = []
    
    # Check Email
    if settings.SMTP_HOST and settings.SMTP_USER:
        channels.append("email")
        
    # Check Slack
    if settings.SLACK_BOT_TOKEN:
        channels.append("slack")
        
    # Check Mattermost
    if settings.MATTERMOST_BOT_TOKEN and settings.MATTERMOST_URL:
        channels.append("mattermost")
        
    return channels
