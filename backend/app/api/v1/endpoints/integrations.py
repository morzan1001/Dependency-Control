import logging
from urllib.parse import urlencode

from fastapi import HTTPException
from fastapi.responses import RedirectResponse
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import DatabaseDep, SystemManagerDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_AUTH_400
from app.core.config import settings
from app.core.security import create_slack_oauth_state, verify_slack_oauth_state
from app.repositories.system_settings import SystemSettingsRepository
from app.services.notifications.slack_provider import SlackOAuthError, request_slack_tokens

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

_SLACK_AUTHORIZE_URL = "https://slack.com/oauth/v2/authorize"
_SLACK_REDIRECT_URI = f"{settings.FRONTEND_BASE_URL}{settings.API_V1_STR}/integrations/slack/callback"


async def _slack_app(db: AsyncIOMotorDatabase) -> tuple[str, str, str] | None:
    system_settings = await SystemSettingsRepository(db).get()
    if not system_settings.slack_client_id or not system_settings.slack_client_secret:
        return None
    return system_settings.slack_client_id, system_settings.slack_client_secret, system_settings.slack_oauth_scopes


def _settings_page(outcome: str) -> RedirectResponse:
    return RedirectResponse(url=f"{settings.FRONTEND_BASE_URL}/settings?{outcome}")


@router.get("/slack/authorize", responses=RESP_AUTH_400)
async def slack_authorize(current_user: SystemManagerDep, db: DatabaseDep) -> dict[str, str]:
    """The Slack install URL, whose signed state is what lets the callback store the token."""
    slack_app = await _slack_app(db)
    if slack_app is None:
        raise HTTPException(
            status_code=400,
            detail="Slack Client ID and Client Secret must be configured in System Settings",
        )
    client_id, _, scopes = slack_app
    query = urlencode(
        {
            "client_id": client_id,
            "scope": scopes or "chat:write",
            "redirect_uri": _SLACK_REDIRECT_URI,
            "state": create_slack_oauth_state(str(current_user.id)),
        }
    )
    return {"url": f"{_SLACK_AUTHORIZE_URL}?{query}"}


@router.get("/slack/callback")
async def slack_callback(
    db: DatabaseDep, code: str | None = None, state: str | None = None, error: str | None = None
) -> RedirectResponse:
    """Slack OAuth callback: exchange the code for access and refresh tokens, then report on the settings page."""
    if error or not code:
        return _settings_page("slack_error=cancelled")
    if not state or verify_slack_oauth_state(state) is None:
        return _settings_page("slack_error=invalid_state")
    slack_app = await _slack_app(db)
    if slack_app is None:
        return _settings_page("slack_error=not_configured")
    client_id, client_secret, _ = slack_app

    try:
        tokens = await request_slack_tokens(
            client_id,
            client_secret,
            grant_type="authorization_code",
            code=code,
            redirect_uri=_SLACK_REDIRECT_URI,
        )
    except SlackOAuthError as e:
        logger.warning("Slack refused the install's code exchange: %s", e)
        return _settings_page("slack_error=exchange_failed")

    await SystemSettingsRepository(db).update(tokens)
    return _settings_page("slack_connected=true")
