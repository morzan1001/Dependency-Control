"""Webhook delivery service. Canonical event names are dot-notation
(e.g. ``scan.completed``); snake_case aliases are still accepted via
WEBHOOK_EVENT_ALIASES in core.constants.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional

if TYPE_CHECKING:
    from app.models.webhook import Webhook

import httpx
from prometheus_client import Counter

from app.core.http_utils import InstrumentedAsyncClient
from app.services.webhooks.validation import assert_safe_webhook_target
from app.services.webhooks.types import (
    AnalysisFailedPayload,
    BaseWebhookPayload,
    ProjectPayload,
    ScanCompletedPayload,
    ScanPayload,
    TestWebhookPayload,
    VulnerabilityFoundPayload,
)
from app.services.webhooks.teams_formatter import TeamsFormatter
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.constants import (
    WEBHOOK_BACKOFF_BASE,
    WEBHOOK_EVENT_ALIASES,
    WEBHOOK_EVENT_ANALYSIS_FAILED,
    WEBHOOK_EVENT_SCAN_COMPLETED,
    WEBHOOK_EVENT_VULNERABILITY_FOUND,
    WEBHOOK_HEADER_CONTENT_TYPE,
    WEBHOOK_HEADER_EVENT,
    WEBHOOK_HEADER_ID,
    WEBHOOK_HEADER_SIGNATURE,
    WEBHOOK_HEADER_TEST,
    WEBHOOK_HEADER_TIMESTAMP,
    WEBHOOK_HEADER_USER_AGENT,
    WEBHOOK_USER_AGENT_VALUE,
)


def _normalize_event_name(event_type: str) -> str:
    """Canonicalize a webhook event name to its dot-notation form."""
    return WEBHOOK_EVENT_ALIASES.get(event_type, event_type)


def _event_match_set(event_type: str) -> List[str]:
    """Subscriptions may store the canonical dot-notation name or the snake_case
    alias — return both forms so either subscription type matches."""
    canonical = _normalize_event_name(event_type)
    names = [canonical]
    for alias, target in WEBHOOK_EVENT_ALIASES.items():
        if target == canonical and alias not in names:
            names.append(alias)
    if event_type not in names:
        names.append(event_type)
    return names


logger = logging.getLogger(__name__)

webhooks_triggered_total: Optional[Counter] = None
webhooks_failed_total: Optional[Counter] = None

try:
    from app.core.metrics import webhooks_failed_total, webhooks_triggered_total
except ImportError:
    pass


class WebhookService:
    """Webhook delivery with retries, HMAC signing, and per-delivery audit logging."""

    def __init__(
        self,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
    ):
        """
        Initialize the webhook service.

        Args:
            timeout: Timeout for webhook HTTP requests in seconds (default from settings)
            max_retries: Maximum number of retry attempts for failed deliveries (default from settings)
        """
        self.timeout = timeout if timeout is not None else settings.WEBHOOK_TIMEOUT_SECONDS
        self.max_retries = max_retries if max_retries is not None else settings.WEBHOOK_MAX_RETRIES

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

    def _build_headers(
        self,
        webhook: "Webhook",
        event_type: str,
        json_payload: str,
        is_test: bool = False,
    ) -> Dict[str, str]:
        """
        Build HTTP headers for webhook request.

        Args:
            webhook: Webhook configuration
            event_type: Type of event being triggered
            json_payload: JSON-encoded payload for signature generation
            is_test: Whether this is a test request

        Returns:
            Dictionary of HTTP headers
        """
        timestamp = str(int(time.time()))

        headers = {
            WEBHOOK_HEADER_CONTENT_TYPE: "application/json",
            WEBHOOK_HEADER_USER_AGENT: WEBHOOK_USER_AGENT_VALUE,
            WEBHOOK_HEADER_EVENT: event_type,
            WEBHOOK_HEADER_TIMESTAMP: timestamp,
            WEBHOOK_HEADER_ID: webhook.id,
        }

        # Add test header if this is a test request
        if is_test:
            headers[WEBHOOK_HEADER_TEST] = "true"

        # Add signature if secret is configured
        if webhook.secret:
            signature = self._generate_signature(webhook.secret, json_payload)
            headers[WEBHOOK_HEADER_SIGNATURE] = f"sha256={signature}"

        # Add custom headers if configured
        if webhook.headers:
            headers.update(webhook.headers)

        return headers

    def _build_base_payload(
        self,
        event_type: str,
        scan_id: str,
        project_id: str,
        project_name: str,
        scan_url: Optional[str] = None,
    ) -> BaseWebhookPayload:
        scan: ScanPayload = {
            "id": scan_id,
            "url": scan_url,
        }
        project: ProjectPayload = {
            "id": project_id,
            "name": project_name,
        }
        return {
            "event": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan": scan,
            "project": project,
        }

    async def _update_webhook_status(
        self,
        db: AsyncIOMotorDatabase,
        webhook_id: str,
        success: bool,
    ) -> None:
        """Track delivery state in DB with circuit-breaker — required for multi-pod
        deployments where any pod may fire a webhook."""
        from datetime import timedelta

        try:
            now = datetime.now(timezone.utc)

            if success:
                await db.webhooks.update_one(
                    {"_id": webhook_id},
                    {
                        "$set": {
                            "last_triggered_at": now,
                            "consecutive_failures": 0,
                            "circuit_breaker_until": None,
                        },
                        "$inc": {"total_deliveries": 1},
                    },
                )
            else:
                # Circuit breaker: 5 consecutive failures disable webhook for 1h.
                CIRCUIT_BREAKER_THRESHOLD = 5
                CIRCUIT_BREAKER_DURATION_HOURS = 1

                await db.webhooks.update_one(
                    {"_id": webhook_id},
                    {
                        "$set": {"last_failure_at": now},
                        "$inc": {"consecutive_failures": 1, "total_failures": 1},
                    },
                )

                # Conditional update is race-safe: only flips when threshold is
                # reached and breaker isn't already active (prevents duplicate logs).
                circuit_until = now + timedelta(hours=CIRCUIT_BREAKER_DURATION_HOURS)
                result = await db.webhooks.find_one_and_update(
                    {
                        "_id": webhook_id,
                        "consecutive_failures": {"$gte": CIRCUIT_BREAKER_THRESHOLD},
                        "$or": [
                            {"circuit_breaker_until": {"$exists": False}},
                            {"circuit_breaker_until": None},
                            {"circuit_breaker_until": {"$lte": now}},
                        ],
                    },
                    {"$set": {"circuit_breaker_until": circuit_until}},
                    return_document=True,
                )

                if result:
                    consecutive = result.get("consecutive_failures", 0)
                    logger.warning(
                        f"Circuit breaker activated for webhook {webhook_id} "
                        f"after {consecutive} consecutive failures. "
                        f"Will retry after {circuit_until.isoformat()}"
                    )

        except Exception as e:
            logger.error(f"Failed to update webhook status for {webhook_id}: {e}")

    async def _log_webhook_delivery(
        self,
        db: AsyncIOMotorDatabase,
        webhook_id: str,
        event_type: str,
        payload: "Mapping[str, Any]",
        success: bool,
        status_code: Optional[int] = None,
        error: Optional[str] = None,
        retry_count: int = 0,
    ) -> None:
        """
        Log webhook delivery for audit trail using WebhookDeliveriesRepository.

        Args:
            db: Database connection
            webhook_id: Webhook ID
            event_type: Event type
            payload: Payload sent
            success: Whether delivery was successful
            status_code: HTTP status code received
            error: Error message if failed
            retry_count: Number of retries attempted
        """
        from app.repositories.webhook_deliveries import WebhookDeliveriesRepository

        try:
            deliveries_repo = WebhookDeliveriesRepository(db)

            payload_summary = {
                "scan_id": payload.get("scan", {}).get("id"),
                "project_id": payload.get("project", {}).get("id"),
            }

            await deliveries_repo.log_delivery(
                webhook_id=webhook_id,
                event_type=event_type,
                payload_summary=payload_summary,
                success=success,
                status_code=status_code,
                error=error,
                retry_count=retry_count,
            )

        except Exception as e:
            logger.error(f"Failed to log webhook delivery: {e}")

    def _format_payload(
        self,
        webhook: "Webhook",
        event_type: str,
        raw_payload: "Mapping[str, Any]",
    ) -> "Mapping[str, Any]":
        if webhook.webhook_type != "teams":
            return raw_payload

        normalized = _normalize_event_name(event_type)
        project_name = raw_payload.get("project", {}).get("name", "Unknown Project")
        scan_url = raw_payload.get("scan", {}).get("url")

        if normalized == WEBHOOK_EVENT_SCAN_COMPLETED:
            return TeamsFormatter.build_scan_completed_card(
                project_name=project_name,
                _scan_id=raw_payload.get("scan", {}).get("id", ""),
                findings=raw_payload.get("findings", {"total": 0, "stats": {}}),
                scan_url=scan_url,
            )
        if normalized == WEBHOOK_EVENT_VULNERABILITY_FOUND:
            return TeamsFormatter.build_vulnerability_found_card(
                project_name=project_name,
                _scan_id=raw_payload.get("scan", {}).get("id", ""),
                vulns=raw_payload.get("vulnerabilities", {"critical": 0, "high": 0, "kev": 0, "high_epss": 0, "top": []}),
                scan_url=scan_url,
            )
        if normalized == WEBHOOK_EVENT_ANALYSIS_FAILED:
            return TeamsFormatter.build_analysis_failed_card(
                project_name=project_name,
                error=str(raw_payload.get("error", "Unknown error")),
                scan_url=scan_url,
            )
        if event_type == "test":
            return TeamsFormatter.build_test_card()
        return TeamsFormatter.build_generic_card(
            subject=normalized.replace(".", " ").title(),
            message=f"Event for project **{project_name}**",
            url=scan_url,
        )

    async def _send_webhook(
        self,
        db: AsyncIOMotorDatabase,
        webhook: "Webhook",
        payload: "Mapping[str, Any]",
        event_type: str,
    ) -> bool:
        """
        Send a single webhook with retries and audit logging.

        Args:
            db: Database connection for status updates
            webhook: Webhook configuration
            payload: Payload to send
            event_type: Type of event being triggered

        Returns:
            True if successful, False otherwise

        NOTE: Retry Persistence
        -----------------------
        Current implementation uses in-memory retry (asyncio.sleep).
        If pod crashes during retry, the delivery is lost.

        For production-grade reliability, consider implementing:
        - Persistent retry queue (Redis/RabbitMQ)
        - Background worker for retry processing
        - Dead letter queue for exhausted retries

        See module docstring for detailed architecture recommendations.
        """
        formatted_payload = self._format_payload(webhook, event_type, payload)
        json_payload = json.dumps(formatted_payload)
        headers = self._build_headers(webhook, event_type, json_payload)

        retry_count = 0
        last_error: Optional[str] = None
        last_status_code: Optional[int] = None

        while retry_count < self.max_retries:
            try:
                await assert_safe_webhook_target(webhook.url)

                async with InstrumentedAsyncClient("Webhook Delivery", timeout=self.timeout) as client:
                    response = await client.post(
                        webhook.url,
                        content=json_payload,
                        headers=headers,
                    )

                    last_status_code = response.status_code

                    if 200 <= response.status_code < 300:
                        logger.info(
                            f"Webhook {webhook.id} triggered successfully for {event_type} "
                            f"(status: {response.status_code})"
                        )
                        await self._update_webhook_status(db, webhook.id, success=True)
                        # Log successful delivery
                        await self._log_webhook_delivery(
                            db,
                            webhook.id,
                            event_type,
                            payload,
                            success=True,
                            status_code=response.status_code,
                            retry_count=retry_count,
                        )
                        return True
                    else:
                        logger.warning(
                            f"Webhook {webhook.id} returned non-success status {response.status_code} "
                            f"for {event_type}: {response.text[:200]}"
                        )
                        last_error = f"HTTP {response.status_code}: {response.text[:200]}"

            except ValueError as e:
                # Blocked by SSRF policy — don't retry.
                logger.warning(
                    f"Webhook {webhook.id} blocked for {event_type}: {e}"
                )
                last_error = f"Blocked target: {e}"
                break
            except httpx.TimeoutException:
                logger.warning(f"Webhook {webhook.id} timed out for {event_type} (attempt {retry_count + 1})")
                last_error = "Timeout"
            except httpx.RequestError as e:
                logger.warning(f"Webhook {webhook.id} request failed for {event_type}: {e} (attempt {retry_count + 1})")
                last_error = str(e)
            except Exception as e:
                logger.error(f"Unexpected error sending webhook {webhook.id} for {event_type}: {e}")
                last_error = str(e)

            retry_count += 1
            if retry_count < self.max_retries:
                # Exponential backoff: 1s, 2s, 4s (with base=2)
                await asyncio.sleep(WEBHOOK_BACKOFF_BASE ** (retry_count - 1))

        # All retries failed
        logger.error(
            f"Webhook {webhook.id} failed after {self.max_retries} attempts for {event_type}. Last error: {last_error}"
        )
        await self._update_webhook_status(db, webhook.id, success=False)
        # Log failed delivery
        await self._log_webhook_delivery(
            db,
            webhook.id,
            event_type,
            payload,
            success=False,
            status_code=last_status_code,
            error=last_error,
            retry_count=retry_count,
        )
        return False

    async def _fetch_webhooks_by_query(
        self, db: AsyncIOMotorDatabase, query: Dict[str, Any], label: str
    ) -> List["Webhook"]:
        """
        Fetch and parse webhooks matching a MongoDB query.

        Args:
            db: Database connection
            query: MongoDB query dict
            label: Label for error logging (e.g. "project", "team", "global")

        Returns:
            List of parsed Webhook objects
        """
        from app.models.webhook import Webhook

        results: List[Webhook] = []
        cursor = db.webhooks.find(query)
        async for webhook_data in cursor:
            try:
                results.append(Webhook(**webhook_data))
            except Exception as e:
                logger.error(f"Failed to parse {label} webhook data: {e}")
        return results

    async def _get_webhooks_for_event(
        self, db: AsyncIOMotorDatabase, project_id: Optional[str], event_type: str
    ) -> List["Webhook"]:
        """
        Fetch all active webhooks for a given event type and project.
        Includes project-specific, team-level, and global webhooks.
        Filters out webhooks in circuit breaker state.

        Args:
            db: Database connection
            project_id: Project ID (None for global webhooks only)
            event_type: Type of event

        Returns:
            List of matching webhooks (excluding those in circuit breaker state)
        """
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)

        # Base query with circuit breaker filter. Subscriptions may store the
        # event under either its canonical dot-notation name or the legacy
        # snake_case alias; match either form. MongoDB's array-membership
        # behaviour means `events: {"$in": [...]}` matches docs whose
        # `events` array contains any of the listed values.
        event_names = _event_match_set(event_type)
        base_conditions: Dict[str, Any] = {
            "is_active": True,
            "events": {"$in": event_names},
            "$or": [
                {"circuit_breaker_until": {"$exists": False}},
                {"circuit_breaker_until": None},
                {"circuit_breaker_until": {"$lt": now}},
            ],
        }

        webhooks: List["Webhook"] = []

        if project_id:
            # Project-specific webhooks
            webhooks.extend(
                await self._fetch_webhooks_by_query(db, {**base_conditions, "project_id": project_id}, "project")
            )

            # Team webhooks: look up the project's team_id
            try:
                project_doc = await db.projects.find_one({"_id": project_id}, {"team_id": 1})
                team_id = project_doc.get("team_id") if project_doc else None
                if team_id:
                    webhooks.extend(
                        await self._fetch_webhooks_by_query(db, {**base_conditions, "team_id": team_id}, "team")
                    )
            except Exception as e:
                logger.error(f"Failed to look up team webhooks for project {project_id}: {e}")

        # Global webhooks (both project_id and team_id are None)
        webhooks.extend(
            await self._fetch_webhooks_by_query(db, {**base_conditions, "project_id": None, "team_id": None}, "global")
        )

        return webhooks

    async def safe_trigger_webhooks(
        self,
        db: AsyncIOMotorDatabase,
        event_type: str,
        payload: "Mapping[str, Any]",
        project_id: Optional[str] = None,
        *,
        context: str = "webhook",
    ) -> None:
        """Fire-and-forget wrapper for ``trigger_webhooks``.

        Webhook delivery is **never** load-bearing for the surrounding
        operation: a failed dispatch must not roll back the ingest, audit
        write, report generation, etc. that triggered it. Every caller
        used to wrap ``trigger_webhooks`` in the same try/except + logger
        boilerplate; this helper centralises that pattern.

        ``context`` is included in the log message so log readers know
        which subsystem failed to dispatch.
        """
        try:
            await self.trigger_webhooks(
                db,
                event_type=event_type,
                payload=payload,
                project_id=project_id,
            )
        except Exception:
            logger.exception(
                "%s: webhook dispatch for %s failed (non-blocking)",
                context,
                event_type,
            )

    async def trigger_webhooks(
        self,
        db: AsyncIOMotorDatabase,
        event_type: str,
        payload: "Mapping[str, Any]",
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
                f"Triggering {len(webhooks)} webhook(s) for event {event_type} (project: {project_id or 'global'})"
            )

            # Track metric
            if webhooks_triggered_total:
                webhooks_triggered_total.labels(event_type=event_type).inc(len(webhooks))

            # Trigger webhooks concurrently
            tasks = [self._send_webhook(db, webhook, payload, event_type) for webhook in webhooks]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Count failures for metrics
            failed_count = 0
            for idx, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Webhook {webhooks[idx].id} raised exception: {result}")
                    failed_count += 1
                elif result is False:
                    failed_count += 1

            # Track failure metrics
            if failed_count > 0 and webhooks_failed_total:
                webhooks_failed_total.labels(event_type=event_type).inc(failed_count)

            logger.info(
                f"Webhooks for {event_type} completed: {len(webhooks) - failed_count} succeeded, {failed_count} failed"
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
            stats: Statistics about findings (severity breakdown, etc.)
            scan_url: Optional URL to view scan results
        """
        base_payload = self._build_base_payload(
            event_type=WEBHOOK_EVENT_SCAN_COMPLETED,
            scan_id=scan_id,
            project_id=project_id,
            project_name=project_name,
            scan_url=scan_url,
        )
        payload: ScanCompletedPayload = {
            **base_payload,
            "findings": {
                "total": findings_count,
                "stats": stats,
            },
        }

        await self.trigger_webhooks(db, WEBHOOK_EVENT_SCAN_COMPLETED, payload, project_id)

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
            kev_count: Number of KEV (Known Exploited Vulnerabilities)
            high_epss_count: Number of high EPSS score vulnerabilities
            top_vulnerabilities: List of top vulnerabilities with details
            scan_url: Optional URL to view scan results
        """
        base_payload = self._build_base_payload(
            event_type=WEBHOOK_EVENT_VULNERABILITY_FOUND,
            scan_id=scan_id,
            project_id=project_id,
            project_name=project_name,
            scan_url=scan_url,
        )
        payload: VulnerabilityFoundPayload = {
            **base_payload,
            "vulnerabilities": {
                "critical": critical_count,
                "high": high_count,
                "kev": kev_count,
                "high_epss": high_epss_count,
                "top": top_vulnerabilities,
            },
        }

        await self.trigger_webhooks(db, WEBHOOK_EVENT_VULNERABILITY_FOUND, payload, project_id)

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
            error_message: Error message describing the failure
            scan_url: Optional URL to view scan results
        """
        base_payload = self._build_base_payload(
            event_type=WEBHOOK_EVENT_ANALYSIS_FAILED,
            scan_id=scan_id,
            project_id=project_id,
            project_name=project_name,
            scan_url=scan_url,
        )
        payload: AnalysisFailedPayload = {
            **base_payload,
            "error": error_message,
        }

        await self.trigger_webhooks(db, WEBHOOK_EVENT_ANALYSIS_FAILED, payload, project_id)

    async def test_webhook(
        self,
        webhook: "Webhook",
        event_type: str = WEBHOOK_EVENT_SCAN_COMPLETED,
    ) -> Dict[str, Any]:
        """
        Send a test webhook to verify configuration.

        Args:
            webhook: Webhook configuration to test
            event_type: Event type for the test payload

        Returns:
            Dict with success status, status_code, error, and response_time_ms
        """
        test_payload: TestWebhookPayload = {
            "event": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test": True,
            "message": "This is a test webhook from DependencyControl",
            "scan": {
                "id": "test-scan-id",
                "url": None,
            },
            "project": {
                "id": "test-project-id",
                "name": "Test Project",
            },
        }

        formatted_test_payload = self._format_payload(webhook, event_type, test_payload)
        json_payload = json.dumps(formatted_test_payload)
        headers = self._build_headers(webhook, event_type, json_payload, is_test=True)

        start_time = time.monotonic()

        try:
            await assert_safe_webhook_target(webhook.url)

            async with InstrumentedAsyncClient("Webhook Test", timeout=self.timeout) as client:
                response = await client.post(
                    webhook.url,
                    content=json_payload,
                    headers=headers,
                )

                response_time_ms = (time.monotonic() - start_time) * 1000

                if 200 <= response.status_code < 300:
                    return {
                        "success": True,
                        "status_code": response.status_code,
                        "error": None,
                        "response_time_ms": round(response_time_ms, 2),
                    }
                else:
                    return {
                        "success": False,
                        "status_code": response.status_code,
                        "error": f"HTTP {response.status_code}: {response.text[:200]}",
                        "response_time_ms": round(response_time_ms, 2),
                    }

        except ValueError as e:
            return {
                "success": False,
                "status_code": None,
                "error": f"Blocked target: {e}",
                "response_time_ms": None,
            }
        except httpx.TimeoutException:
            return {
                "success": False,
                "status_code": None,
                "error": f"Request timed out after {self.timeout}s",
                "response_time_ms": None,
            }
        except httpx.RequestError as e:
            return {
                "success": False,
                "status_code": None,
                "error": str(e),
                "response_time_ms": None,
            }
        except Exception as e:
            return {
                "success": False,
                "status_code": None,
                "error": f"Unexpected error: {e}",
                "response_time_ms": None,
            }


# Global singleton instance
webhook_service = WebhookService()
