import time
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.db.mongodb import get_database
from app.models.system import SystemSettings

router = APIRouter()


@router.get("/slack/callback")
async def slack_callback(
    code: str,
    state: Optional[str] = None,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Callback endpoint for Slack OAuth.
    Exchanges the code for an access token and refresh token.
    """
    # Fetch current system settings to get client_id and client_secret
    data = await db.system_settings.find_one({"_id": "current"})
    if not data:
        raise HTTPException(status_code=404, detail="System settings not found")

    system_settings = SystemSettings(**data)

    if not system_settings.slack_client_id or not system_settings.slack_client_secret:
        raise HTTPException(
            status_code=400,
            detail="Slack Client ID and Client Secret must be configured in System Settings",
        )

    # Exchange code for token
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://slack.com/api/oauth.v2.access",
            data={
                "client_id": system_settings.slack_client_id,
                "client_secret": system_settings.slack_client_secret,
                "code": code,
                "grant_type": "authorization_code",
                # "redirect_uri": ... # Optional if configured in Slack App, but good practice to match
            },
        )

        if response.status_code != 200:
            raise HTTPException(
                status_code=400, detail="Failed to exchange code with Slack"
            )

        result = response.json()

        if not result.get("ok"):
            raise HTTPException(
                status_code=400, detail=f"Slack API Error: {result.get('error')}"
            )

        # Extract tokens
        access_token = result.get("access_token")
        refresh_token = result.get("refresh_token")
        expires_in = result.get("expires_in")  # Seconds

        update_data = {
            "slack_bot_token": access_token,
        }

        if refresh_token:
            update_data["slack_refresh_token"] = refresh_token

        if expires_in:
            update_data["slack_token_expires_at"] = time.time() + expires_in

        # Update database
        await db.system_settings.update_one({"_id": "current"}, {"$set": update_data})

        # Redirect to frontend settings page
        redirect_url = f"{settings.FRONTEND_BASE_URL}/settings?slack_connected=true"
        return RedirectResponse(url=redirect_url)
