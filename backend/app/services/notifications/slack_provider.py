import asyncio
import logging
import time
from typing import Optional

from app.core.config import settings
from app.core.http_utils import InstrumentedAsyncClient
from app.core.constants import SLACK_TOKEN_EXPIRY_BUFFER_SECONDS
from app.db.mongodb import get_database
from app.models.system import SystemSettings
from app.repositories.system_settings import SystemSettingsRepository
from app.services.notifications.base import NotificationProvider

logger = logging.getLogger(__name__)

# Import metrics for notification tracking
try:
    from app.core.metrics import notifications_failed_total, notifications_sent_total
except ImportError:
    notifications_sent_total = None
    notifications_failed_total = None


class SlackProvider(NotificationProvider):
    def __init__(self):
        # Local lock to prevent concurrent refresh within same pod
        self._refresh_lock = asyncio.Lock()
        # Cache the refreshed token to avoid redundant refreshes
        self._cached_token: Optional[str] = None
        self._cached_token_expires_at: float = 0

    async def _acquire_distributed_lock(self, db, lock_name: str, ttl_seconds: int = 30) -> bool:
        """
        Acquire a distributed lock using DistributedLocksRepository.

        Args:
            db: Database connection
            lock_name: Name of the lock
            ttl_seconds: Lock TTL in seconds (auto-expires if holder crashes)

        Returns:
            True if lock acquired, False otherwise
        """
        from app.repositories.distributed_locks import DistributedLocksRepository

        locks_repo = DistributedLocksRepository(db)
        holder_id = f"slack-provider-{id(self)}"

        return await locks_repo.acquire_lock(lock_name, holder_id, ttl_seconds)

    async def _release_distributed_lock(self, db, lock_name: str) -> None:
        """Release a distributed lock using DistributedLocksRepository."""
        from app.repositories.distributed_locks import DistributedLocksRepository

        locks_repo = DistributedLocksRepository(db)
        await locks_repo.release_lock(lock_name)

    async def _refresh_token(self, system_settings: SystemSettings) -> Optional[str]:
        """
        Refreshes the Slack access token using the refresh token.
        Updates the database with the new token and expiration.
        """
        if (
            not system_settings.slack_client_id
            or not system_settings.slack_client_secret
            or not system_settings.slack_refresh_token
        ):
            logger.error("Cannot refresh Slack token: Missing client_id, client_secret, or refresh_token.")
            return None

        try:
            async with InstrumentedAsyncClient(
                "Slack API", timeout=settings.NOTIFICATION_HTTP_TIMEOUT_SECONDS
            ) as client:
                response = await client.post(
                    "https://slack.com/api/oauth.v2.access",
                    data={
                        "client_id": system_settings.slack_client_id,
                        "client_secret": system_settings.slack_client_secret,
                        "grant_type": "refresh_token",
                        "refresh_token": system_settings.slack_refresh_token,
                    },
                )

                if response.status_code != 200:
                    logger.error(
                        f"Failed to refresh Slack token. Status: {response.status_code}, Body: {response.text}"
                    )
                    return None

                result = response.json()
                if not result.get("ok"):
                    logger.error(f"Slack API Error during refresh: {result.get('error')}")
                    return None

                new_access_token = result.get("access_token")
                new_refresh_token = result.get("refresh_token")
                expires_in = result.get("expires_in")

                # Update database
                db = await get_database()
                repo = SystemSettingsRepository(db)

                update_data = {
                    "slack_bot_token": new_access_token,
                }
                if new_refresh_token:
                    update_data["slack_refresh_token"] = new_refresh_token
                if expires_in:
                    update_data["slack_token_expires_at"] = time.time() + expires_in

                await repo.update(update_data)

                logger.info("Successfully refreshed Slack token")
                return new_access_token

        except Exception as e:
            logger.error(f"Error refreshing Slack token: {e}")
            return None

    async def send(
        self,
        destination: str,
        subject: str,
        message: str,
        system_settings: Optional[SystemSettings] = None,
    ) -> bool:
        if not system_settings:
            return False

        slack_token = system_settings.slack_bot_token
        current_time = time.time()

        # Check for expiration and refresh if needed
        if system_settings.slack_token_expires_at and system_settings.slack_token_expires_at < (
            current_time + SLACK_TOKEN_EXPIRY_BUFFER_SECONDS
        ):
            # Check if we have a valid cached token first (local cache)
            if self._cached_token and self._cached_token_expires_at > current_time:
                slack_token = self._cached_token
            else:
                # Use LOCAL lock for intra-pod coordination
                async with self._refresh_lock:
                    # Double-check after acquiring local lock
                    if self._cached_token and self._cached_token_expires_at > current_time:
                        slack_token = self._cached_token
                    else:
                        # Try to acquire DISTRIBUTED lock for inter-pod coordination
                        db = await get_database()
                        lock_acquired = await self._acquire_distributed_lock(db, "slack_token_refresh", ttl_seconds=30)

                        if lock_acquired:
                            try:
                                logger.info("Acquired distributed lock for Slack token refresh")
                                # Re-check settings (another pod may have refreshed)
                                from app.repositories.system_settings import (
                                    SystemSettingsRepository,
                                )

                                repo = SystemSettingsRepository(db)
                                fresh_settings = await repo.get()
                                if (
                                    fresh_settings
                                    and fresh_settings.slack_token_expires_at
                                    and fresh_settings.slack_token_expires_at
                                    > (current_time + SLACK_TOKEN_EXPIRY_BUFFER_SECONDS)
                                ):
                                    # Another pod already refreshed, use new token
                                    slack_token = fresh_settings.slack_bot_token
                                    self._cached_token = slack_token
                                    self._cached_token_expires_at = fresh_settings.slack_token_expires_at
                                    logger.info("Using token refreshed by another pod")
                                else:
                                    # We need to refresh
                                    logger.info("Slack token expired or expiring soon. Refreshing...")
                                    new_token = await self._refresh_token(system_settings)
                                    if new_token:
                                        slack_token = new_token
                                        # Cache locally
                                        self._cached_token = new_token
                                        self._cached_token_expires_at = (
                                            current_time + 3600 - SLACK_TOKEN_EXPIRY_BUFFER_SECONDS
                                        )
                                    else:
                                        logger.warning(
                                            "Failed to refresh Slack token, attempting to use existing token."
                                        )
                            finally:
                                # Always release distributed lock
                                await self._release_distributed_lock(db, "slack_token_refresh")
                        else:
                            # Another pod is refreshing, wait and retry
                            logger.info("Another pod is refreshing Slack token, waiting...")
                            await asyncio.sleep(2)
                            # Re-fetch settings after wait
                            from app.repositories.system_settings import (
                                SystemSettingsRepository,
                            )

                            repo = SystemSettingsRepository(db)
                            fresh_settings = await repo.get()
                            if fresh_settings and fresh_settings.slack_bot_token:
                                slack_token = fresh_settings.slack_bot_token
                                self._cached_token = slack_token
                                if fresh_settings.slack_token_expires_at:
                                    self._cached_token_expires_at = fresh_settings.slack_token_expires_at
                            else:
                                logger.warning("Could not acquire lock and no refreshed token found")

        if not slack_token:
            logger.warning("SLACK_BOT_TOKEN not configured. Skipping Slack notification.")
            return False

        url = "https://slack.com/api/chat.postMessage"
        headers = {
            "Authorization": f"Bearer {slack_token}",
            "Content-Type": "application/json",
        }

        # Format the message nicely
        payload = {"channel": destination, "text": f"*{subject}*\n{message}"}

        try:
            async with InstrumentedAsyncClient(
                "Slack API", timeout=settings.NOTIFICATION_HTTP_TIMEOUT_SECONDS
            ) as client:
                response = await client.post(url, headers=headers, json=payload)
                if response.status_code == 200 and response.json().get("ok"):
                    logger.info(f"Slack message sent to {destination}")
                    if notifications_sent_total:
                        notifications_sent_total.labels(type="slack").inc()
                    return True
                else:
                    logger.error(f"Failed to send Slack message: {response.text}")
                    if notifications_failed_total:
                        notifications_failed_total.labels(type="slack").inc()
                    return False
        except Exception as e:
            logger.error(f"Error sending Slack message: {e}")
            if notifications_failed_total:
                notifications_failed_total.labels(type="slack").inc()
            return False
