import asyncio
import logging
import time
from typing import Any

import httpx

from app.core.config import settings
from app.core.constants import SLACK_TOKEN_EXPIRY_BUFFER_SECONDS
from app.core.http_utils import InstrumentedAsyncClient
from app.core.metrics import notifications_failed_total, notifications_sent_total
from app.db.mongodb import get_database
from app.models.system import SystemSettings
from app.repositories.distributed_locks import DistributedLocksRepository, new_lock_holder
from app.repositories.system_settings import SystemSettingsRepository
from app.services.notifications.slack_formatter import _escape_mrkdwn, build_generic_blocks

logger = logging.getLogger(__name__)

SLACK_OAUTH_URL = "https://slack.com/api/oauth.v2.access"
_REFRESH_LOCK = "slack_token_refresh"


class SlackOAuthError(Exception):
    """Slack refused or did not answer a token request; the message is the reason."""


async def request_slack_tokens(client_id: str, client_secret: str, **grant: str) -> dict[str, Any]:
    """The system-settings fields of a token that oauth.v2.access grants for ``grant``."""
    try:
        async with InstrumentedAsyncClient("Slack OAuth", timeout=settings.NOTIFICATION_HTTP_TIMEOUT_SECONDS) as client:
            response = await client.post(
                SLACK_OAUTH_URL, data={"client_id": client_id, "client_secret": client_secret, **grant}
            )
    except httpx.RequestError as e:
        raise SlackOAuthError(f"Request to Slack failed ({type(e).__name__})") from e
    if response.status_code != 200:
        raise SlackOAuthError(f"HTTP error from Slack: {response.status_code}")
    result = response.json()
    if not result.get("ok"):
        raise SlackOAuthError(f"Slack API error: {result.get('error', 'unknown_error')}")

    expires_in = result.get("expires_in")
    return {
        "slack_bot_token": result.get("access_token"),
        "slack_refresh_token": result.get("refresh_token"),
        "slack_token_expires_at": time.time() + expires_in if expires_in else None,
    }


def _expiring(system_settings: SystemSettings) -> bool:
    expires_at = system_settings.slack_token_expires_at
    return bool(expires_at and expires_at < time.time() + SLACK_TOKEN_EXPIRY_BUFFER_SECONDS)


class SlackProvider:
    def __init__(self) -> None:
        # Serialises this pod's refreshes; the distributed lock serialises the pods'.
        self._refresh_lock = asyncio.Lock()

    async def _refresh_token(self, system_settings: SystemSettings) -> str | None:
        """Refresh the Slack access token and persist the new token and expiry."""
        if (
            not system_settings.slack_client_id
            or not system_settings.slack_client_secret
            or not system_settings.slack_refresh_token
        ):
            logger.error("Cannot refresh Slack token: Missing client_id, client_secret, or refresh_token.")
            return None

        try:
            tokens = await request_slack_tokens(
                system_settings.slack_client_id,
                system_settings.slack_client_secret,
                grant_type="refresh_token",
                refresh_token=system_settings.slack_refresh_token,
            )
        except SlackOAuthError as e:
            logger.error("Slack token refresh failed: %s", e)
            return None

        await SystemSettingsRepository(await get_database()).update(tokens)
        logger.info("Successfully refreshed Slack token")
        access_token: str | None = tokens["slack_bot_token"]
        return access_token

    async def _current_token(self, system_settings: SystemSettings) -> str | None:
        """The bot token, refreshed first while it expires within the buffer; the stored one if that fails."""
        if not _expiring(system_settings):
            return system_settings.slack_bot_token
        db = await get_database()
        settings_repo = SystemSettingsRepository(db)
        async with self._refresh_lock:
            locks = DistributedLocksRepository(db)
            holder = new_lock_holder()
            if await locks.acquire_lock(_REFRESH_LOCK, holder, ttl_seconds=30):
                try:
                    # Read under the lock: another pod may have just rotated the refresh token.
                    fresh = await settings_repo.get()
                    if not _expiring(fresh):
                        return fresh.slack_bot_token
                    return await self._refresh_token(fresh) or fresh.slack_bot_token
                finally:
                    await locks.release_lock(_REFRESH_LOCK, holder)
        logger.info("Another pod is refreshing the Slack token, waiting...")
        # Outside the pod lock, so sends queued behind it do not each wait in turn.
        await asyncio.sleep(2)
        return (await settings_repo.get()).slack_bot_token

    async def send(
        self,
        destination: str,
        subject: str,
        message: str,
        *,
        system_settings: SystemSettings,
        blocks: list[dict[str, Any]] | None = None,
    ) -> bool:
        slack_token = await self._current_token(system_settings)
        if not slack_token:
            logger.warning("SLACK_BOT_TOKEN not configured. Skipping Slack notification.")
            return False

        url = "https://slack.com/api/chat.postMessage"
        headers = {
            "Authorization": f"Bearer {slack_token}",
            "Content-Type": "application/json",
        }

        # text is the fallback for notifications and accessibility
        payload: dict[str, Any] = {
            "channel": destination,
            "text": f"*{_escape_mrkdwn(subject)}*\n{_escape_mrkdwn(message)}",
            "blocks": blocks or build_generic_blocks(subject, message),
        }

        try:
            async with InstrumentedAsyncClient(
                "Slack API", timeout=settings.NOTIFICATION_HTTP_TIMEOUT_SECONDS
            ) as client:
                response = await client.post(url, headers=headers, json=payload)
                if response.status_code == 200 and response.json().get("ok"):
                    logger.info(f"Slack message sent to {destination}")
                    notifications_sent_total.labels(type="slack").inc()
                    return True
                logger.error(f"Failed to send Slack message: {response.text}")
                notifications_failed_total.labels(type="slack").inc()
                return False
        except Exception as e:
            logger.exception("Error sending Slack message: %s", e)
            notifications_failed_total.labels(type="slack").inc()
            return False
