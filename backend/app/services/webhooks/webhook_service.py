"""
Webhook Service for triggering webhooks on various events.

Supports multiple event types:
- scan_completed: Triggered when a scan finishes
- vulnerability_found: Triggered when critical vulnerabilities are detected
- analysis_failed: Triggered when analysis fails
"""

import asyncio
import hashlib
import hmac
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.webhook import Webhook

logger = logging.getLogger(__name__)

# Import metrics for webhook tracking
try:
    from app.core.metrics import webhooks_failed_total, webhooks_triggered_total
except ImportError:
    webhooks_triggered_total = None
    webhooks_failed_total = None


class WebhookService:
    """
    Service for triggering webhooks on various events.
    """

    def __init__(self):
        self.timeout = 30.0  # Timeout for webhook requests
        self.max_retries = 3

    def _generate_signature(self, secret: str, payload: str) -> str:
        """
        Generate HMAC signature for webhook payload.

        Args:
            secret: Webhook secret for signing
            payload: JSON payload as string

        Returns:
            HMAC-SHA256 signature as hex string
        """
        return hmac.new(
            secret.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    async def _send_webhook(
        self,
        webhook: Webhook,
        payload: Dict[str, Any],
        event_type: str,
    ) -> bool:
        """
        Send a single webhook with retries.

        Args:
            webhook: Webhook configuration
            payload: Payload to send
            event_type: Type of event being triggered

        Returns:
            True if successful, False otherwise
        """
        import json

        json_payload = json.dumps(payload)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "DependencyControl-Webhook/1.0",
            "X-Webhook-Event": event_type,
            "X-Webhook-Timestamp": str(int(time.time())),
        }

        # Add signature if secret is configured
        if webhook.secret:
            signature = self._generate_signature(webhook.secret, json_payload)
            headers["X-Webhook-Signature"] = f"sha256={signature}"

        # Add custom headers if configured
        if webhook.headers:
            headers.update(webhook.headers)

        retry_count = 0
        last_error = None

        while retry_count < self.max_retries:
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        webhook.url,
                        content=json_payload,
                        headers=headers,
                    )

                    if 200 <= response.status_code < 300:
                        logger.info(
                            f"Webhook {webhook.id} triggered successfully for {event_type} "
                            f"(status: {response.status_code})"
                        )
                        return True
                    else:
                        logger.warning(
                            f"Webhook {webhook.id} returned non-success status {response.status_code} "
                            f"for {event_type}: {response.text[:200]}"
                        )
                        last_error = f"HTTP {response.status_code}"

            except httpx.TimeoutException as e:
                logger.warning(
                    f"Webhook {webhook.id} timed out for {event_type} (attempt {retry_count + 1})"
                )
                last_error = "Timeout"
            except httpx.RequestError as e:
                logger.warning(
                    f"Webhook {webhook.id} request failed for {event_type}: {e} "
                    f"(attempt {retry_count + 1})"
                )
                last_error = str(e)
            except Exception as e:
                logger.error(
                    f"Unexpected error sending webhook {webhook.id} for {event_type}: {e}"
                )
                last_error = str(e)

            retry_count += 1
            if retry_count < self.max_retries:
                # Exponential backoff: 1s, 2s, 4s
                await asyncio.sleep(2 ** (retry_count - 1))

        # All retries failed
        logger.error(
            f"Webhook {webhook.id} failed after {self.max_retries} attempts for {event_type}. "
            f"Last error: {last_error}"
        )
        return False

    async def _get_webhooks_for_event(
        self, db: AsyncIOMotorDatabase, project_id: Optional[str], event_type: str
    ) -> List[Webhook]:
        """
        Fetch all active webhooks for a given event type and project.

        Args:
            db: Database connection
            project_id: Project ID (None for global webhooks)
            event_type: Type of event

        Returns:
            List of matching webhooks
        """
        # Fetch project-specific webhooks
        query = {
            "enabled": True,
            "events": event_type,
        }

        webhooks = []

        # Project-specific webhooks
        if project_id:
            project_query = {**query, "project_id": project_id}
            cursor = db.webhooks.find(project_query)
            async for webhook_data in cursor:
                webhooks.append(Webhook(**webhook_data))

        # Global webhooks
        global_query = {**query, "project_id": None}
        cursor = db.webhooks.find(global_query)
        async for webhook_data in cursor:
            webhooks.append(Webhook(**webhook_data))

        return webhooks

    async def trigger_webhooks(
        self,
        db: AsyncIOMotorDatabase,
        event_type: str,
        payload: Dict[str, Any],
        project_id: Optional[str] = None,
    ) -> None:
        """
        Trigger all webhooks for a given event.

        Args:
            db: Database connection
            event_type: Type of event (scan_completed, vulnerability_found, etc.)
            payload: Payload to send to webhooks
            project_id: Optional project ID for project-specific webhooks
        """
        try:
            webhooks = await self._get_webhooks_for_event(db, project_id, event_type)

            if not webhooks:
                logger.debug(f"No webhooks configured for event {event_type}")
                return

            logger.info(
                f"Triggering {len(webhooks)} webhook(s) for event {event_type} "
                f"(project: {project_id or 'global'})"
            )

            # Track metric
            if webhooks_triggered_total:
                webhooks_triggered_total.labels(event_type=event_type).inc(
                    len(webhooks)
                )

            # Trigger webhooks concurrently
            tasks = []
            for webhook in webhooks:
                task = self._send_webhook(webhook, payload, event_type)
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Count failures for metrics
            failed_count = 0
            for idx, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(
                        f"Webhook {webhooks[idx].id} raised exception: {result}"
                    )
                    failed_count += 1
                elif result is False:
                    failed_count += 1

            # Track failure metrics
            if failed_count > 0 and webhooks_failed_total:
                webhooks_failed_total.labels(event_type=event_type).inc(failed_count)

            logger.info(
                f"Webhooks for {event_type} completed: "
                f"{len(webhooks) - failed_count} succeeded, {failed_count} failed"
            )

        except Exception as e:
            logger.error(f"Error triggering webhooks for {event_type}: {e}")

    async def trigger_scan_completed(
        self,
        db: AsyncIOMotorDatabase,
        scan_id: str,
        project_id: str,
        project_name: str,
        findings_count: int,
        stats: Dict[str, Any],
        scan_url: Optional[str] = None,
    ) -> None:
        """
        Trigger webhooks when a scan completes.

        Args:
            db: Database connection
            scan_id: Scan ID
            project_id: Project ID
            project_name: Project name
            findings_count: Total number of findings
            stats: Statistics about findings
            scan_url: Optional URL to view scan results
        """
        payload = {
            "event": "scan_completed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan": {
                "id": scan_id,
                "url": scan_url,
            },
            "project": {
                "id": project_id,
                "name": project_name,
            },
            "findings": {
                "total": findings_count,
                "stats": stats,
            },
        }

        await self.trigger_webhooks(db, "scan_completed", payload, project_id)

    async def trigger_vulnerability_found(
        self,
        db: AsyncIOMotorDatabase,
        scan_id: str,
        project_id: str,
        project_name: str,
        critical_count: int,
        high_count: int,
        kev_count: int,
        high_epss_count: int,
        top_vulnerabilities: List[Dict[str, Any]],
        scan_url: Optional[str] = None,
    ) -> None:
        """
        Trigger webhooks when critical vulnerabilities are found.

        Args:
            db: Database connection
            scan_id: Scan ID
            project_id: Project ID
            project_name: Project name
            critical_count: Number of critical vulnerabilities
            high_count: Number of high vulnerabilities
            kev_count: Number of KEV vulnerabilities
            high_epss_count: Number of high EPSS vulnerabilities
            top_vulnerabilities: List of top vulnerabilities
            scan_url: Optional URL to view scan results
        """
        payload = {
            "event": "vulnerability_found",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan": {
                "id": scan_id,
                "url": scan_url,
            },
            "project": {
                "id": project_id,
                "name": project_name,
            },
            "vulnerabilities": {
                "critical": critical_count,
                "high": high_count,
                "kev": kev_count,
                "high_epss": high_epss_count,
                "top": top_vulnerabilities,
            },
        }

        await self.trigger_webhooks(db, "vulnerability_found", payload, project_id)

    async def trigger_analysis_failed(
        self,
        db: AsyncIOMotorDatabase,
        scan_id: str,
        project_id: str,
        project_name: str,
        error_message: str,
        scan_url: Optional[str] = None,
    ) -> None:
        """
        Trigger webhooks when analysis fails.

        Args:
            db: Database connection
            scan_id: Scan ID
            project_id: Project ID
            project_name: Project name
            error_message: Error message
            scan_url: Optional URL to view scan results
        """
        payload = {
            "event": "analysis_failed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan": {
                "id": scan_id,
                "url": scan_url,
            },
            "project": {
                "id": project_id,
                "name": project_name,
            },
            "error": error_message,
        }

        await self.trigger_webhooks(db, "analysis_failed", payload, project_id)


# Global singleton instance
webhook_service = WebhookService()
