from typing import Optional

from fastapi import HTTPException

from app.api.deps import DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_400
from fastapi.responses import RedirectResponse

from app.api.v1.helpers.integrations import (
    SlackOAuthError,
    exchange_slack_code_for_token,
    extract_slack_tokens,
)
from app.core.config import settings
from app.repositories.system_settings import SystemSettingsRepository

router = CustomAPIRouter()


@router.get("/slack/callback", responses={**RESP_400})
async def slack_callback(
    code: str,
    db: DatabaseDep,
    state: Optional[str] = None,
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
