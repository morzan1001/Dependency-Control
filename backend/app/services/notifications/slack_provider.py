import asyncio
import logging
import time
from typing import Any

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.constants import SLACK_TOKEN_EXPIRY_BUFFER_SECONDS
from app.core.http_utils import InstrumentedAsyncClient
from app.core.metrics import record_notification
from app.models.system import SystemSettings
from app.repositories.distributed_locks import DistributedLocksRepository, new_lock_holder
from app.repositories.system_settings import SystemSettingsRepository
from app.services.notifications.slack_formatter import _escape_mrkdwn, build_generic_blocks

logger = logging.getLogger(__name__)

SLACK_OAUTH_URL = "https://slack.com/api/oauth.v2.access"
_REFRESH_LOCK = "slack_token_refresh"
# Without it every send of a fan-out retries a refused refresh in turn, under the lock the delivery workers wait on.
_REFRESH_RETRY_SECONDS = 60


class SlackOAuthError(Exception):
    """Slack refused or did not answer a token request; the message is the reason."""


async def request_slack_tokens(client_id: str, client_secret: str, **grant: str) -> dict[str, Any]:
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
        self._refresh_failed_at = float("-inf")

    async def _refresh_token(self, db: AsyncIOMotorDatabase, system_settings: SystemSettings) -> str | None:
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

        await SystemSettingsRepository(db).update(tokens)
        logger.info("Successfully refreshed Slack token")
        access_token: str | None = tokens["slack_bot_token"]
        return access_token

    async def _current_token(self, db: AsyncIOMotorDatabase, system_settings: SystemSettings) -> str | None:
        if not _expiring(system_settings):
            return system_settings.slack_bot_token
        settings_repo = SystemSettingsRepository(db)
        async with self._refresh_lock:
            if time.monotonic() - self._refresh_failed_at < _REFRESH_RETRY_SECONDS:
                return system_settings.slack_bot_token
            locks = DistributedLocksRepository(db)
            holder = new_lock_holder()
            if await locks.acquire_lock(_REFRESH_LOCK, holder, ttl_seconds=30):
                try:
                    # Read under the lock: another pod may have just rotated the refresh token.
                    fresh = await settings_repo.get()
                    if not _expiring(fresh):
                        return fresh.slack_bot_token
                    refreshed = await self._refresh_token(db, fresh)
                    if refreshed is None:
                        self._refresh_failed_at = time.monotonic()
                    return refreshed or fresh.slack_bot_token
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
        db: AsyncIOMotorDatabase,
        system_settings: SystemSettings,
        blocks: list[dict[str, Any]] | None = None,
    ) -> bool:
        slack_token = await self._current_token(db, system_settings)
        if not slack_token:
            logger.warning("SLACK_BOT_TOKEN not configured. Skipping Slack notification.")
            return False

        # text is the fallback for notifications and accessibility
        payload: dict[str, Any] = {
            "channel": destination,
            "text": f"*{_escape_mrkdwn(subject)}*\n{_escape_mrkdwn(message)}",
            "blocks": blocks or build_generic_blocks(subject, message),
        }
        try:
            delivered = await self._deliver(slack_token, payload)
        except Exception as e:
            logger.exception("Error sending Slack message: %s", e)
            delivered = False
        record_notification("slack", delivered)
        return delivered

    async def _deliver(self, slack_token: str, payload: dict[str, Any]) -> bool:
        headers = {"Authorization": f"Bearer {slack_token}", "Content-Type": "application/json"}
        async with InstrumentedAsyncClient("Slack API", timeout=settings.NOTIFICATION_HTTP_TIMEOUT_SECONDS) as client:
            response = await client.post("https://slack.com/api/chat.postMessage", headers=headers, json=payload)
        if response.status_code == 200 and response.json().get("ok"):
            logger.info(f"Slack message sent to {payload['channel']}")
            return True
        logger.error(f"Failed to send Slack message: {response.text}")
        return False
