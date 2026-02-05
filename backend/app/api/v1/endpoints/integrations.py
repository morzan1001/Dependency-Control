from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.v1.helpers.integrations import (
    SlackOAuthError,
    exchange_slack_code_for_token,
    extract_slack_tokens,
)
from app.core.config import settings
from app.db.mongodb import get_database
from app.repositories.system_settings import SystemSettingsRepository

router = APIRouter(
    # Use field names (e.g., 'id') instead of aliases (e.g., '_id') in JSON responses.
    response_model_by_alias=False,
)


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
    repo = SystemSettingsRepository(db)
    system_settings = await repo.get()

    if not system_settings.slack_client_id or not system_settings.slack_client_secret:
        raise HTTPException(
            status_code=400,
            detail="Slack Client ID and Client Secret must be configured in System Settings",
        )

    try:
        oauth_response = await exchange_slack_code_for_token(
            code=code,
            client_id=system_settings.slack_client_id,
            client_secret=system_settings.slack_client_secret,
        )
    except SlackOAuthError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Slack OAuth failed: {e.message}",
        )

    update_data = extract_slack_tokens(oauth_response)
    await repo.update(update_data)

    redirect_url = f"{settings.FRONTEND_BASE_URL}/settings?slack_connected=true"
    return RedirectResponse(url=redirect_url)
