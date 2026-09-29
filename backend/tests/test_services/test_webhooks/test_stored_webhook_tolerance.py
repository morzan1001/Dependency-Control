"""A stored webhook whose URL today's rules reject stays readable and deletable; delivery still refuses it."""

import pytest

from app.models.webhook import Webhook
from app.services.webhooks.webhook_service import webhook_service

_LEGACY_URL = "http://metadata.google.internal/computeMetadata/v1/"


def _legacy_webhook() -> Webhook:
    return Webhook(project_id="p1", url=_LEGACY_URL, events=["scan_completed", "retired.event"])


def test_a_document_stored_under_older_rules_still_loads():
    webhook = _legacy_webhook()

    assert (webhook.url, webhook.events) == (_LEGACY_URL, ["scan_completed", "retired.event"])


@pytest.mark.asyncio
async def test_delivery_refuses_a_target_the_current_rules_reject():
    result = await webhook_service.test_webhook(_legacy_webhook())

    assert result["success"] is False
    assert result["error"].startswith("Blocked target:")
    assert "not an allowed target" in result["error"]
