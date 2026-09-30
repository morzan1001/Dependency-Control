"""Webhook delivery to the subscribers of dot-notation events."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import scan_link, settings
from app.core.constants import (
    WEBHOOK_BACKOFF_BASE,
    WEBHOOK_EVENT_ANALYSIS_FAILED,
    WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED,
    WEBHOOK_EVENT_LICENSE_POLICY_CHANGED,
    WEBHOOK_EVENT_SCAN_COMPLETED,
    WEBHOOK_EVENT_VULNERABILITY_FOUND,
    WEBHOOK_HEADER_CONTENT_TYPE,
    WEBHOOK_HEADER_DELIVERY,
    WEBHOOK_HEADER_EVENT,
    WEBHOOK_HEADER_ID,
    WEBHOOK_HEADER_SIGNATURE,
    WEBHOOK_HEADER_SIGNATURE_V2,
    WEBHOOK_HEADER_TEST,
    WEBHOOK_HEADER_TIMESTAMP,
    WEBHOOK_HEADER_USER_AGENT,
    WEBHOOK_RESPONSE_BODY_LIMIT_BYTES,
    WEBHOOK_USER_AGENT_VALUE,
    WebhookType,
)
from app.core.http_utils import InstrumentedAsyncClient, _retry_after_seconds
from app.core.metrics import webhooks_failed_total, webhooks_triggered_total
from app.models.webhook import Webhook
from app.repositories.projects import ProjectRepository
from app.repositories.webhook_deliveries import WebhookDeliveriesRepository
from app.repositories.webhooks import WebhookRepository
from app.services.webhooks.teams_formatter import TeamsFormatter
from app.services.webhooks.types import (
    AnalysisFailedPayload,
    BaseWebhookPayload,
    ProjectPayload,
    ScanCompletedPayload,
    ScanPayload,
    TestWebhookPayload,
    VulnerabilityFoundPayload,
)
from app.services.webhooks.validation import WebhookTargetBlocked, build_pinned_transport

_CIRCUIT_BREAKER_THRESHOLD = 5
_CIRCUIT_BREAKER_DURATION = timedelta(hours=1)
# Longer waits are not worth it: delivery is awaited inside the ingest request or worker slot.
_RETRY_AFTER_CAP_SECONDS = 10.0

logger = logging.getLogger(__name__)


class WebhookService:
    """Webhook delivery with retries, HMAC signing, and per-delivery audit logging."""

    def __init__(
        self,
        timeout: float | None = None,
        max_attempts: int | None = None,
    ):
        self.timeout = timeout if timeout is not None else settings.WEBHOOK_TIMEOUT_SECONDS
        # WEBHOOK_MAX_RETRIES counts attempts; even 0 still delivers once.
        self.max_attempts = max(1, max_attempts if max_attempts is not None else settings.WEBHOOK_MAX_RETRIES)

    def _generate_signature(self, secret: str, payload: str) -> str:
        return hmac.new(
            secret.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _build_headers(
        self,
        webhook: Webhook,
        event_type: str,
        json_payload: str,
        is_test: bool = False,
    ) -> dict[str, str]:
        timestamp = str(int(time.time()))

        headers = {
            **(webhook.headers or {}),
            WEBHOOK_HEADER_CONTENT_TYPE: "application/json",
            WEBHOOK_HEADER_USER_AGENT: WEBHOOK_USER_AGENT_VALUE,
            WEBHOOK_HEADER_EVENT: event_type,
            WEBHOOK_HEADER_TIMESTAMP: timestamp,
            WEBHOOK_HEADER_ID: webhook.id,
            WEBHOOK_HEADER_DELIVERY: uuid.uuid4().hex,
        }

        if is_test:
            headers[WEBHOOK_HEADER_TEST] = "true"

        if webhook.secret:
            headers[WEBHOOK_HEADER_SIGNATURE] = f"sha256={self._generate_signature(webhook.secret, json_payload)}"
            timed_signature = self._generate_signature(webhook.secret, f"{timestamp}.{json_payload}")
            headers[WEBHOOK_HEADER_SIGNATURE_V2] = f"t={timestamp},v1={timed_signature}"

        return headers

    def _build_base_payload(
        self,
        event_type: str,
        scan_id: str,
        project_id: str,
        project_name: str,
    ) -> BaseWebhookPayload:
        scan: ScanPayload = {
            "id": scan_id,
            "url": scan_link(project_id, scan_id),
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
        try:
            repo = WebhookRepository(db)
            now = datetime.now(timezone.utc)
            if success:
                await repo.record_success(webhook_id, now)
                return
            circuit_until = now + _CIRCUIT_BREAKER_DURATION
            opened = await repo.record_failure(webhook_id, now, _CIRCUIT_BREAKER_THRESHOLD, circuit_until)
            if opened:
                logger.warning(
                    "Circuit breaker activated for webhook %s after %s consecutive failures. Will retry after %s",
                    webhook_id,
                    opened.get("consecutive_failures", 0),
                    circuit_until.isoformat(),
                )
        except Exception as e:
            logger.exception("Failed to update webhook status for %s: %s", webhook_id, e)

    async def _log_webhook_delivery(
        self,
        db: AsyncIOMotorDatabase,
        webhook_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        success: bool,
        status_code: int | None = None,
        error: str | None = None,
        retry_count: int = 0,
    ) -> None:
        try:
            deliveries_repo = WebhookDeliveriesRepository(db)

            # Policy-changed events carry project_id flat, not nested under "project".
            payload_summary = {
                "scan_id": payload.get("scan", {}).get("id"),
                "project_id": payload.get("project", {}).get("id") or payload.get("project_id"),
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
            logger.exception("Failed to log webhook delivery: %s", e)

    def _format_payload(
        self,
        webhook_type: WebhookType,
        event_type: str,
        raw_payload: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if webhook_type != "teams":
            return raw_payload
        if event_type == WEBHOOK_EVENT_SCAN_COMPLETED:
            return TeamsFormatter.build_scan_completed_card(raw_payload)
        if event_type == WEBHOOK_EVENT_VULNERABILITY_FOUND:
            return TeamsFormatter.build_vulnerability_found_card(raw_payload)
        if event_type == WEBHOOK_EVENT_ANALYSIS_FAILED:
            return TeamsFormatter.build_analysis_failed_card(raw_payload)
        if event_type in (WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED, WEBHOOK_EVENT_LICENSE_POLICY_CHANGED):
            return TeamsFormatter.build_policy_changed_card(event_type, raw_payload)
        project_name = raw_payload.get("project", {}).get("name", "Unknown Project")
        return TeamsFormatter.build_generic_card(event_type, f"Event for project **{project_name}**")

    async def _post_bounded(
        self, client_name: str, webhook: Webhook, content: str, headers: Mapping[str, str]
    ) -> tuple[int | None, str | None, float | None]:
        """One POST under one deadline: the status, the error text and the retry delay (None: do not retry)."""
        try:
            async with asyncio.timeout(self.timeout):
                transport = await build_pinned_transport(webhook.url)
                request_headers = httpx.Headers(encoding="latin-1")
                # Item assignment is case-insensitive, so a stored case-variant cannot duplicate a protocol header.
                for name, value in {**headers, "Accept-Encoding": "identity"}.items():
                    request_headers[name] = value
                async with (
                    InstrumentedAsyncClient(
                        client_name, timeout=httpx.Timeout(self.timeout, connect=5.0), transport=transport
                    ) as client,
                    # identity keeps the raw prefix readable; decoding compressed chunks has no output limit.
                    client.stream("POST", webhook.url, content=content, headers=request_headers) as response,
                ):
                    status = response.status_code
                    if 200 <= status < 300:
                        return status, None, None
                    body = bytearray()
                    async for chunk in response.aiter_raw():
                        body += chunk
                        if len(body) >= WEBHOOK_RESPONSE_BODY_LIMIT_BYTES:
                            break
                    text = body[:WEBHOOK_RESPONSE_BODY_LIMIT_BYTES].decode("utf-8", "replace")
                    error = f"HTTP {status}: {text[:200]}"
                    if status < 500 and status not in (408, 429):
                        return status, error, None
                    delay = _retry_after_seconds(response) or 0.0
                    return status, error, delay if delay <= _RETRY_AFTER_CAP_SECONDS else None
        except WebhookTargetBlocked as exc:
            logger.warning("Webhook %s refused: %s", webhook.id, exc.detail)
            return None, str(exc), None
        except UnicodeEncodeError:
            return None, "Invalid header value", None
        except (httpx.TimeoutException, TimeoutError):
            return None, f"Request timed out after {self.timeout}s", 0.0
        except httpx.RequestError as exc:
            return None, str(exc), 0.0
        except Exception as exc:
            logger.exception("Unexpected error delivering webhook %s", webhook.id)
            return None, f"Unexpected error: {exc}", 0.0

    async def _send_webhook(
        self,
        db: AsyncIOMotorDatabase,
        webhook: Webhook,
        payload: Mapping[str, Any],
        event_type: str,
    ) -> bool:
        """Send a single webhook with retries. Retries are in-memory — delivery is lost if the pod crashes mid-retry."""
        json_payload = json.dumps(self._format_payload(webhook.webhook_type, event_type, payload))
        headers = self._build_headers(webhook, event_type, json_payload)

        for attempt in range(1, self.max_attempts + 1):
            status_code, error, retry_delay = await self._post_bounded(
                "Webhook Delivery", webhook, json_payload, headers
            )
            if error is None:
                logger.info(f"Webhook {webhook.id} triggered successfully for {event_type} (status: {status_code})")
                break
            if retry_delay is None or attempt == self.max_attempts:
                logger.error(
                    f"Webhook {webhook.id} failed after {attempt} attempts for {event_type}. Last error: {error}"
                )
                break
            logger.warning(f"Webhook {webhook.id} attempt {attempt} for {event_type} failed, retrying: {error}")
            await asyncio.sleep(max(retry_delay, WEBHOOK_BACKOFF_BASE ** (attempt - 1)))

        success = error is None
        await self._update_webhook_status(db, webhook.id, success=success)
        await self._log_webhook_delivery(
            db,
            webhook.id,
            event_type,
            payload,
            success=success,
            status_code=status_code,
            error=error,
            retry_count=attempt - 1,
        )
        return success

    async def _get_webhooks_for_event(
        self,
        db: AsyncIOMotorDatabase,
        project_id: str | None,
        event_type: str,
        *,
        team_ids: Sequence[str] | None = None,
    ) -> list[Webhook]:
        """Deliverable webhooks of the project, its owning teams (read from it unless given) and global scope."""
        if team_ids is None:
            team_ids = []
            if project_id:
                try:
                    project = await ProjectRepository(db).find_one_raw({"_id": project_id}, {"team_ids": 1})
                    team_ids = (project or {}).get("team_ids") or []
                except Exception:
                    webhooks_failed_total.labels(event_type=event_type).inc()
                    logger.exception("Team webhooks for project %s skipped: team lookup failed", project_id)
        return await WebhookRepository(db).find_deliverable(
            event_type, datetime.now(timezone.utc), project_id, team_ids
        )

    async def safe_trigger_webhooks(
        self,
        db: AsyncIOMotorDatabase,
        event_type: str,
        payload: Mapping[str, Any],
        project_id: str | None = None,
        *,
        team_ids: Sequence[str] | None = None,
        context: str = "webhook",
    ) -> None:
        """Non-blocking trigger_webhooks — a failed dispatch never rolls back the caller."""
        try:
            await self.trigger_webhooks(
                db, event_type=event_type, payload=payload, project_id=project_id, team_ids=team_ids
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
        payload: Mapping[str, Any],
        project_id: str | None = None,
        *,
        team_ids: Sequence[str] | None = None,
    ) -> None:
        """Dispatch an event to all matching webhooks; a failure while resolving webhooks may propagate, so use safe_trigger_webhooks when the caller must not be affected."""
        webhooks = await self._get_webhooks_for_event(db, project_id, event_type, team_ids=team_ids)

        if not webhooks:
            logger.debug(f"No webhooks configured for event {event_type}")
            return

        logger.info(f"Triggering {len(webhooks)} webhook(s) for event {event_type} (project: {project_id or 'global'})")

        webhooks_triggered_total.labels(event_type=event_type).inc(len(webhooks))

        tasks = [self._send_webhook(db, webhook, payload, event_type) for webhook in webhooks]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        failed_count = 0
        for idx, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Webhook {webhooks[idx].id} raised exception: {result}")
                failed_count += 1
            elif result is False:
                failed_count += 1

        if failed_count > 0:
            webhooks_failed_total.labels(event_type=event_type).inc(failed_count)

        logger.info(
            f"Webhooks for {event_type} completed: {len(webhooks) - failed_count} succeeded, {failed_count} failed"
        )

    async def trigger_scan_completed(
        self,
        db: AsyncIOMotorDatabase,
        scan_id: str,
        project_id: str,
        project_name: str,
        findings_count: int,
        stats: dict[str, Any],
        scan_status: str,
        failed_analyzers: list[str],
        *,
        team_ids: Sequence[str] | None = None,
    ) -> None:
        base_payload = self._build_base_payload(
            event_type=WEBHOOK_EVENT_SCAN_COMPLETED,
            scan_id=scan_id,
            project_id=project_id,
            project_name=project_name,
        )
        payload: ScanCompletedPayload = {
            **base_payload,
            "findings": {
                "total": findings_count,
                "stats": stats,
            },
            "scan_status": scan_status,
            "failed_analyzers": failed_analyzers,
        }

        await self.safe_trigger_webhooks(
            db, WEBHOOK_EVENT_SCAN_COMPLETED, payload, project_id, team_ids=team_ids, context="scan.completed"
        )

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
        priority_count: int,
        top_vulnerabilities: list[dict[str, Any]],
        *,
        team_ids: Sequence[str] | None = None,
    ) -> None:
        base_payload = self._build_base_payload(
            event_type=WEBHOOK_EVENT_VULNERABILITY_FOUND,
            scan_id=scan_id,
            project_id=project_id,
            project_name=project_name,
        )
        payload: VulnerabilityFoundPayload = {
            **base_payload,
            "vulnerabilities": {
                "critical": critical_count,
                "high": high_count,
                "kev": kev_count,
                "high_epss": high_epss_count,
                "priority": priority_count,
                "top": top_vulnerabilities,
            },
        }

        await self.safe_trigger_webhooks(
            db, WEBHOOK_EVENT_VULNERABILITY_FOUND, payload, project_id, team_ids=team_ids, context="vulnerability.found"
        )

    async def trigger_analysis_failed(
        self,
        db: AsyncIOMotorDatabase,
        scan_id: str,
        project_id: str,
        project_name: str,
        error_message: str,
    ) -> None:
        base_payload = self._build_base_payload(
            event_type=WEBHOOK_EVENT_ANALYSIS_FAILED,
            scan_id=scan_id,
            project_id=project_id,
            project_name=project_name,
        )
        payload: AnalysisFailedPayload = {
            **base_payload,
            "error": error_message,
        }

        await self.safe_trigger_webhooks(
            db, WEBHOOK_EVENT_ANALYSIS_FAILED, payload, project_id, context="analysis.failed"
        )

    async def test_webhook(
        self,
        webhook: Webhook,
        event_type: str = WEBHOOK_EVENT_SCAN_COMPLETED,
    ) -> dict[str, Any]:
        test_payload: TestWebhookPayload = {
            **self._build_base_payload(event_type, "test-scan-id", "test-project-id", "Test Project"),
            "test": True,
            "message": "This is a test webhook from DependencyControl",
        }

        # Teams gets the test card: formatting test_payload's event would produce a scan card.
        teams = webhook.webhook_type == "teams"
        json_payload = json.dumps(TeamsFormatter.build_test_card() if teams else test_payload)
        headers = self._build_headers(webhook, event_type, json_payload, is_test=True)

        start_time = time.monotonic()
        status_code, error, _ = await self._post_bounded("Webhook Test", webhook, json_payload, headers)
        return {
            "success": error is None,
            "status_code": status_code,
            "error": error,
            "response_time_ms": None if status_code is None else round((time.monotonic() - start_time) * 1000, 2),
        }


webhook_service = WebhookService()
