from urllib.parse import urlencode

from fastapi import HTTPException
from fastapi.responses import RedirectResponse
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import DatabaseDep, SystemManagerDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_400, RESP_AUTH_400
from app.core.config import settings
from app.core.security import create_slack_oauth_state, verify_slack_oauth_state
from app.repositories.system_settings import SystemSettingsRepository
from app.services.notifications.slack_provider import SlackOAuthError, request_slack_tokens

router = CustomAPIRouter()

_SLACK_AUTHORIZE_URL = "https://slack.com/oauth/v2/authorize"
_SLACK_REDIRECT_URI = f"{settings.FRONTEND_BASE_URL}{settings.API_V1_STR}/integrations/slack/callback"


async def _slack_app(db: AsyncIOMotorDatabase) -> tuple[str, str, str]:
    """The Slack app's client id, client secret and bot scopes; 400 while id or secret is missing."""
    system_settings = await SystemSettingsRepository(db).get()
    if not system_settings.slack_client_id or not system_settings.slack_client_secret:
        raise HTTPException(
            status_code=400,
            detail="Slack Client ID and Client Secret must be configured in System Settings",
        )
    return system_settings.slack_client_id, system_settings.slack_client_secret, system_settings.slack_oauth_scopes


@router.get("/slack/authorize", responses=RESP_AUTH_400)
async def slack_authorize(current_user: SystemManagerDep, db: DatabaseDep) -> dict[str, str]:
    """The Slack install URL, whose signed state is what lets the callback store the token."""
    client_id, _, scopes = await _slack_app(db)
    query = urlencode(
        {
            "client_id": client_id,
            "scope": scopes or "chat:write",
            "redirect_uri": _SLACK_REDIRECT_URI,
            "state": create_slack_oauth_state(str(current_user.id)),
        }
    )
    return {"url": f"{_SLACK_AUTHORIZE_URL}?{query}"}


@router.get("/slack/callback", responses=RESP_400)
async def slack_callback(code: str, db: DatabaseDep, state: str | None = None) -> RedirectResponse:
    """Slack OAuth callback: exchange the code for access and refresh tokens."""
    if not state or verify_slack_oauth_state(state) is None:
        raise HTTPException(status_code=400, detail="Start the Slack install from the system settings page")
    client_id, client_secret, _ = await _slack_app(db)

    try:
        tokens = await request_slack_tokens(
            client_id,
            client_secret,
            grant_type="authorization_code",
            code=code,
            redirect_uri=_SLACK_REDIRECT_URI,
        )
    except SlackOAuthError as e:
        raise HTTPException(status_code=400, detail=f"Slack OAuth failed: {e}") from e

    await SystemSettingsRepository(db).update(tokens)
    return RedirectResponse(url=f"{settings.FRONTEND_BASE_URL}/settings?slack_connected=true")
