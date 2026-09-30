"""Webhook delivery; canonical event names are dot-notation, snake_case aliases accepted via WEBHOOK_EVENT_ALIASES."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.constants import (
    WEBHOOK_BACKOFF_BASE,
    WEBHOOK_EVENT_ALIASES,
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
from app.repositories.webhook_deliveries import WebhookDeliveriesRepository
from app.repositories.webhooks import GLOBAL_WEBHOOK_SCOPE
from app.schemas.webhook import effective_webhook_type
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


def _circuit_closed(now: datetime) -> dict[str, Any]:
    return {"$or": [{"circuit_breaker_until": None}, {"circuit_breaker_until": {"$lte": now}}]}


def _event_match_set(event_type: str) -> list[str]:
    """The canonical event plus its snake_case aliases, which subscriptions written before
    validation canonicalised event names may still store."""
    return [event_type, *(alias for alias, target in WEBHOOK_EVENT_ALIASES.items() if target == event_type)]


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
        scan_url: str | None = None,
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
                await db.webhooks.update_one(
                    {"_id": webhook_id},
                    {
                        "$set": {"last_failure_at": now},
                        "$inc": {"consecutive_failures": 1, "total_failures": 1},
                    },
                )

                # Conditional update is race-safe: flips only once per threshold breach, avoiding duplicate logs.
                circuit_until = now + _CIRCUIT_BREAKER_DURATION
                result = await db.webhooks.find_one_and_update(
                    {
                        "_id": webhook_id,
                        "consecutive_failures": {"$gte": _CIRCUIT_BREAKER_THRESHOLD},
                        **_circuit_closed(now),
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

        project_name = raw_payload.get("project", {}).get("name", "Unknown Project")
        scan_url = raw_payload.get("scan", {}).get("url")

        if event_type == WEBHOOK_EVENT_SCAN_COMPLETED:
            return TeamsFormatter.build_scan_completed_card(
                project_name=project_name,
                _scan_id=raw_payload.get("scan", {}).get("id", ""),
                findings=raw_payload.get("findings", {"total": 0, "stats": {}}),
                scan_url=scan_url,
            )
        if event_type == WEBHOOK_EVENT_VULNERABILITY_FOUND:
            return TeamsFormatter.build_vulnerability_found_card(
                project_name=project_name,
                _scan_id=raw_payload.get("scan", {}).get("id", ""),
                vulns=raw_payload.get(
                    "vulnerabilities", {"critical": 0, "high": 0, "kev": 0, "high_epss": 0, "top": []}
                ),
                scan_url=scan_url,
            )
        if event_type == WEBHOOK_EVENT_ANALYSIS_FAILED:
            return TeamsFormatter.build_analysis_failed_card(
                project_name=project_name,
                error=str(raw_payload.get("error", "Unknown error")),
                scan_url=scan_url,
            )
        if event_type in (WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED, WEBHOOK_EVENT_LICENSE_POLICY_CHANGED):
            return self._build_policy_changed_card(event_type, raw_payload)
        return TeamsFormatter.build_generic_card(
            subject=event_type.replace(".", " ").title(),
            message=f"Event for project **{project_name}**",
            url=scan_url,
        )

    @staticmethod
    def _build_policy_changed_card(
        normalized_event: str,
        raw_payload: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Teams card for policy-changed events, whose payloads are flat (no nested project/scan)."""
        project_id = raw_payload.get("project_id")
        policy_scope = raw_payload.get("policy_scope")
        version = raw_payload.get("version")
        change_summary = raw_payload.get("change_summary") or "Policy updated"
        actor = raw_payload.get("actor") or {}
        actor_name = actor.get("display_name") or "A user"

        subject = normalized_event.replace(".", " ").replace("_", " ").title()
        scope_text = f"project {project_id}" if project_id else (policy_scope or "system")
        message = f"{actor_name} updated the {scope_text} policy: {change_summary}"
        if version is not None:
            message = f"{message} (version {version})"

        return TeamsFormatter.build_generic_card(subject=subject, message=message, url=None)

    async def _post_bounded(
        self, client_name: str, webhook: Webhook, content: str, headers: Mapping[str, str]
    ) -> tuple[int | None, str | None, float | None]:
        """One POST under one overall deadline: the status, the error text, and the delay before a retry (None: do not retry)."""
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
        webhook_type = effective_webhook_type(webhook.webhook_type, webhook.url)
        json_payload = json.dumps(self._format_payload(webhook_type, event_type, payload))
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

    async def _fetch_webhooks_by_query(
        self, db: AsyncIOMotorDatabase, query: dict[str, Any], label: str
    ) -> list[Webhook]:
        results: list[Webhook] = []
        cursor = db.webhooks.find(query)
        async for webhook_data in cursor:
            try:
                results.append(Webhook(**webhook_data))
            except Exception as e:
                logger.exception("Failed to parse %s webhook data: %s", label, e)
        return results

    async def _get_webhooks_for_event(
        self, db: AsyncIOMotorDatabase, project_id: str | None, event_type: str
    ) -> list[Webhook]:
        """Active webhooks for the event across project, team, and global scope, excluding circuit-broken ones."""
        # Match both dot-notation and snake_case alias forms stored in subscriptions.
        base_conditions: dict[str, Any] = {
            "is_active": True,
            "events": {"$in": _event_match_set(event_type)},
            **_circuit_closed(datetime.now(timezone.utc)),
        }

        webhooks: list[Webhook] = []

        if project_id:
            webhooks.extend(
                await self._fetch_webhooks_by_query(db, {**base_conditions, "project_id": project_id}, "project")
            )

            try:
                project_doc = await db.projects.find_one({"_id": project_id}, {"team_ids": 1})
                owners = (project_doc or {}).get("team_ids") or []
                if owners:
                    webhooks.extend(
                        await self._fetch_webhooks_by_query(db, {**base_conditions, "team_id": {"$in": owners}}, "team")
                    )
            except Exception as e:
                logger.exception("Failed to look up team webhooks for project %s: %s", project_id, e)

        webhooks.extend(await self._fetch_webhooks_by_query(db, {**base_conditions, **GLOBAL_WEBHOOK_SCOPE}, "global"))

        return webhooks

    async def safe_trigger_webhooks(
        self,
        db: AsyncIOMotorDatabase,
        event_type: str,
        payload: Mapping[str, Any],
        project_id: str | None = None,
        *,
        context: str = "webhook",
    ) -> None:
        """Non-blocking trigger_webhooks — a failed dispatch never rolls back the caller."""
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
        payload: Mapping[str, Any],
        project_id: str | None = None,
    ) -> None:
        """Dispatch an event to all matching webhooks; a failure while resolving webhooks may propagate, so use safe_trigger_webhooks when the caller must not be affected."""
        webhooks = await self._get_webhooks_for_event(db, project_id, event_type)

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
        scan_url: str | None = None,
        scan_status: str = "completed",
        failed_analyzers: list[str] | None = None,
    ) -> None:
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
            "scan_status": scan_status,
            "failed_analyzers": failed_analyzers or [],
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
        top_vulnerabilities: list[dict[str, Any]],
        scan_url: str | None = None,
    ) -> None:
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
        scan_url: str | None = None,
    ) -> None:
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
        webhook: Webhook,
        event_type: str = WEBHOOK_EVENT_SCAN_COMPLETED,
    ) -> dict[str, Any]:
        test_payload: TestWebhookPayload = {
            **self._build_base_payload(event_type, "test-scan-id", "test-project-id", "Test Project"),
            "test": True,
            "message": "This is a test webhook from DependencyControl",
        }

        # Teams gets the test card: formatting test_payload's event would produce a scan card.
        teams = effective_webhook_type(webhook.webhook_type, webhook.url) == "teams"
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
