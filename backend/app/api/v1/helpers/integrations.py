"""
Integration Helper Functions

Helper functions for external service integrations (Slack, etc.).
"""

import logging
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)

# Slack API endpoints
SLACK_OAUTH_URL = "https://slack.com/api/oauth.v2.access"


class SlackOAuthError(Exception):
    """Exception raised when Slack OAuth fails."""

    def __init__(self, message: str, error_code: str | None = None):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)


async def exchange_slack_code_for_token(
    code: str,
    client_id: str,
    client_secret: str,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    """
    Exchange a Slack OAuth code for access and refresh tokens.

    Args:
        code: The OAuth authorization code from Slack callback
        client_id: Slack application client ID
        client_secret: Slack application client secret
        timeout: Request timeout in seconds

    Returns:
        Dict containing token data:
        {
            "access_token": str,
            "refresh_token": str | None,
            "expires_in": int | None,
            "team": {...},
            ...
        }

    Raises:
        SlackOAuthError: If the token exchange fails
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                SLACK_OAUTH_URL,
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                },
            )

            if response.status_code != 200:
                logger.error(f"Slack OAuth HTTP error: status={response.status_code}")
                raise SlackOAuthError(
                    f"HTTP error from Slack: {response.status_code}",
                    error_code="http_error",
                )

            result = response.json()

            if not result.get("ok"):
                error = result.get("error", "unknown_error")
                logger.error(f"Slack OAuth API error: {error}")
                raise SlackOAuthError(
                    f"Slack API error: {error}",
                    error_code=error,
                )

            return result

    except httpx.TimeoutException as e:
        logger.error(f"Slack OAuth timeout: {e}")
        raise SlackOAuthError(
            "Request to Slack timed out",
            error_code="timeout",
        ) from e

    except httpx.ConnectError as e:
        logger.error(f"Slack OAuth connection error: {e}")
        raise SlackOAuthError(
            "Could not connect to Slack",
            error_code="connection_error",
        ) from e

    except httpx.RequestError as e:
        logger.error(f"Slack OAuth request error: {e}")
        raise SlackOAuthError(
            f"Request error: {str(e)}",
            error_code="request_error",
        ) from e


def extract_slack_tokens(oauth_response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract token data from Slack OAuth response.

    Args:
        oauth_response: The full OAuth response from Slack

    Returns:
        Dict with extracted token data ready for database update:
        {
            "slack_bot_token": str,
            "slack_refresh_token": str | None,
            "slack_token_expires_at": float | None,
        }
    """
    import time

    update_data: Dict[str, Any] = {
        "slack_bot_token": oauth_response.get("access_token"),
    }

    refresh_token = oauth_response.get("refresh_token")
    if refresh_token:
        update_data["slack_refresh_token"] = refresh_token

    expires_in = oauth_response.get("expires_in")
    if expires_in:
        update_data["slack_token_expires_at"] = time.time() + expires_in

    return update_data
