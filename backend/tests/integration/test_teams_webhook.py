"""Integration tests for Teams webhook type auto-detection."""


from app.models.webhook import Webhook
from app.schemas.webhook import WebhookCreate, WebhookUpdate
from app.services.webhooks.validation import detect_webhook_type


class TestDetectWebhookTypeIntegration:
    """Test the auto-detection logic that runs inside create endpoints."""

    def _resolve_type(self, webhook_in: WebhookCreate) -> str:
        """Simulate the endpoint logic: use explicit type or auto-detect."""
        return webhook_in.webhook_type or detect_webhook_type(webhook_in.url)

    def test_teams_url_auto_detected(self):
        webhook_in = WebhookCreate(
            url="https://contoso.webhook.office.com/webhookb2/abc/IncomingWebhook/xyz",
            events=["scan.completed"],
        )
        assert self._resolve_type(webhook_in) == "teams"

    def test_power_automate_url_auto_detected(self):
        webhook_in = WebhookCreate(
            url="https://prod-12.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke",
            events=["scan.completed"],
        )
        assert self._resolve_type(webhook_in) == "teams"

    def test_power_platform_url_auto_detected(self):
        webhook_in = WebhookCreate(
            url=(
                "https://default047b2e1fa2714bc197a4703bf7adf1.35.environment.api.powerplatform.com"
                "/powerautomate/automations/direct/workflows/67fa2e06/triggers/manual/paths/invoke"
            ),
            events=["scan.completed"],
        )
        assert self._resolve_type(webhook_in) == "teams"

    def test_generic_url_defaults_to_generic(self):
        webhook_in = WebhookCreate(
            url="https://my-server.example.com/webhook",
            events=["scan.completed"],
        )
        assert self._resolve_type(webhook_in) == "generic"

    def test_explicit_generic_overrides_teams_url(self):
        webhook_in = WebhookCreate(
            url="https://contoso.webhook.office.com/webhookb2/abc",
            events=["scan.completed"],
            webhook_type="generic",
        )
        assert self._resolve_type(webhook_in) == "generic"

    def test_explicit_teams_overrides_generic_url(self):
        webhook_in = WebhookCreate(
            url="https://my-server.example.com/webhook",
            events=["scan.completed"],
            webhook_type="teams",
        )
        assert self._resolve_type(webhook_in) == "teams"


class TestWebhookModelCreationWithType:
    """Test that Webhook objects are built with the correct type."""

    def test_webhook_created_with_resolved_teams_type(self):
        webhook_in = WebhookCreate(
            url="https://contoso.webhook.office.com/webhookb2/abc",
            events=["scan.completed"],
        )
        resolved_type = webhook_in.webhook_type or detect_webhook_type(webhook_in.url)
        webhook_data = webhook_in.model_dump(exclude={"webhook_type"})
        webhook = Webhook(project_id="proj-1", webhook_type=resolved_type, **webhook_data)
        assert webhook.webhook_type == "teams"

    def test_webhook_response_exposes_type(self):
        from app.schemas.webhook import WebhookResponse
        from datetime import datetime, timezone

        webhook = Webhook(
            url="https://contoso.webhook.office.com/webhookb2/abc",
            events=["scan.completed"],
            webhook_type="teams",
        )
        resp = WebhookResponse(
            id=webhook.id,
            url=webhook.url,
            events=webhook.events,
            is_active=webhook.is_active,
            created_at=webhook.created_at,
            webhook_type=webhook.webhook_type,
        )
        assert resp.webhook_type == "teams"


class TestDetectWebhookTypeOnUpdate:
    """Simulate the update-endpoint logic: re-detect when URL changes, respect explicit override."""

    def _apply_update(self, existing_type: str, update: WebhookUpdate) -> str:
        """Simulate what update_webhook does with the update_data dict."""
        update_data = update.model_dump(exclude_unset=True)
        if "url" in update_data and "webhook_type" not in update_data:
            update_data["webhook_type"] = detect_webhook_type(update_data["url"])
        return update_data.get("webhook_type", existing_type)

    def test_url_change_to_teams_auto_detects(self):
        update = WebhookUpdate(url="https://contoso.webhook.office.com/webhookb2/abc")
        assert self._apply_update("generic", update) == "teams"

    def test_url_change_to_power_platform_auto_detects(self):
        update = WebhookUpdate(
            url=(
                "https://default123.environment.api.powerplatform.com"
                "/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke"
            )
        )
        assert self._apply_update("generic", update) == "teams"

    def test_url_change_to_generic_auto_detects(self):
        update = WebhookUpdate(url="https://my-server.example.com/webhook")
        assert self._apply_update("teams", update) == "generic"

    def test_explicit_override_respected_even_when_url_present(self):
        update = WebhookUpdate(
            url="https://contoso.webhook.office.com/webhookb2/abc",
            webhook_type="generic",
        )
        assert self._apply_update("generic", update) == "generic"

    def test_no_url_in_update_leaves_type_unchanged(self):
        update = WebhookUpdate(events=["vulnerability.found"])
        assert self._apply_update("teams", update) == "teams"
