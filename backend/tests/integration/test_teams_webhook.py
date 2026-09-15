"""Integration tests for Teams webhook type auto-detection."""

import pytest

from app.models.webhook import Webhook
from app.schemas.webhook import WebhookCreate, WebhookUpdate
from app.services.webhooks.validation import detect_webhook_type


class TestDetectWebhookTypeIntegration:
    def _resolve_type(self, webhook_in: WebhookCreate) -> str:
        """Simulate the endpoint logic: use explicit type or auto-detect."""
        return webhook_in.webhook_type or detect_webhook_type(webhook_in.url)

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            pytest.param(
                "https://contoso.webhook.office.com/webhookb2/abc/IncomingWebhook/xyz",
                "teams",
                id="teams-incoming-webhook",
            ),
            pytest.param(
                "https://prod-12.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke",
                "teams",
                id="power-automate",
            ),
            pytest.param(
                "https://default047b2e1fa2714bc197a4703bf7adf1.35.environment.api.powerplatform.com"
                "/powerautomate/automations/direct/workflows/67fa2e06/triggers/manual/paths/invoke",
                "teams",
                id="power-platform",
            ),
            pytest.param("https://my-server.example.com/webhook", "generic", id="unknown-host"),
        ],
    )
    def test_url_auto_detected(self, url, expected):
        webhook_in = WebhookCreate(url=url, events=["scan.completed"])
        assert self._resolve_type(webhook_in) == expected

    @pytest.mark.parametrize(
        ("url", "webhook_type"),
        [
            pytest.param("https://contoso.webhook.office.com/webhookb2/abc", "generic", id="generic-over-teams-url"),
            pytest.param("https://my-server.example.com/webhook", "teams", id="teams-over-generic-url"),
        ],
    )
    def test_explicit_type_overrides_url(self, url, webhook_type):
        webhook_in = WebhookCreate(url=url, events=["scan.completed"], webhook_type=webhook_type)
        assert self._resolve_type(webhook_in) == webhook_type


class TestWebhookModelCreationWithType:
    def test_webhook_created_with_resolved_teams_type(self):
        webhook_in = WebhookCreate(
            url="https://contoso.webhook.office.com/webhookb2/abc",
            events=["scan.completed"],
        )
        resolved_type = webhook_in.webhook_type or detect_webhook_type(webhook_in.url)
        webhook_data = webhook_in.model_dump(exclude={"webhook_type"})
        webhook = Webhook(project_id="proj-1", webhook_type=resolved_type, **webhook_data)
        assert webhook.webhook_type == "teams"


class TestDetectWebhookTypeOnUpdate:
    """Simulate the update-endpoint logic: re-detect when URL changes, respect explicit override."""

    def _apply_update(self, existing_type: str, update: WebhookUpdate) -> str:
        """Simulate what update_webhook does with the update_data dict."""
        update_data = update.model_dump(exclude_unset=True)
        if "url" in update_data and "webhook_type" not in update_data:
            update_data["webhook_type"] = detect_webhook_type(update_data["url"])
        return update_data.get("webhook_type", existing_type)

    @pytest.mark.parametrize(
        ("existing_type", "url", "expected"),
        [
            pytest.param(
                "generic",
                "https://contoso.webhook.office.com/webhookb2/abc",
                "teams",
                id="to-teams",
            ),
            pytest.param(
                "generic",
                "https://default123.environment.api.powerplatform.com"
                "/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke",
                "teams",
                id="to-power-platform",
            ),
            pytest.param(
                "teams",
                "https://my-server.example.com/webhook",
                "generic",
                id="to-generic",
            ),
        ],
    )
    def test_url_change_auto_detects(self, existing_type, url, expected):
        update = WebhookUpdate(url=url)
        assert self._apply_update(existing_type, update) == expected

    def test_explicit_override_respected_even_when_url_present(self):
        update = WebhookUpdate(
            url="https://contoso.webhook.office.com/webhookb2/abc",
            webhook_type="generic",
        )
        assert self._apply_update("generic", update) == "generic"

    def test_no_url_in_update_leaves_type_unchanged(self):
        update = WebhookUpdate(events=["vulnerability.found"])
        assert self._apply_update("teams", update) == "teams"
