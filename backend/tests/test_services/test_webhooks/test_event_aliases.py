"""Tests for webhook event-name backward-compat aliases.

When event names were migrated from snake_case (``scan_completed``) to
dot-notation (``scan.completed``) we kept an alias map so that:

1. Existing MongoDB webhook subscriptions storing the old names continue to
   match events fired under the new name (and vice versa).
2. Validation accepts either form when a caller submits a POST /webhooks.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

from app.core.constants import WEBHOOK_EVENT_ALIASES, WEBHOOK_EVENT_SCAN_COMPLETED
from app.models.webhook import Webhook
from app.services.webhooks.validation import (
    validate_webhook_event_type,
    validate_webhook_events,
)
from app.services.webhooks.webhook_service import (
    WebhookService,
    _event_match_set,
    _normalize_event_name,
)


class TestEventNameNormalization:
    def test_normalize_legacy_name_returns_dot_notation(self):
        assert _normalize_event_name("scan_completed") == "scan.completed"
        assert _normalize_event_name("vulnerability_found") == "vulnerability.found"
        assert _normalize_event_name("analysis_failed") == "analysis.failed"

    def test_normalize_dot_notation_is_unchanged(self):
        assert _normalize_event_name("scan.completed") == "scan.completed"

    def test_normalize_unknown_event_is_unchanged(self):
        assert _normalize_event_name("something.else") == "something.else"

    def test_match_set_includes_legacy_alias(self):
        names = _event_match_set("scan.completed")
        assert "scan.completed" in names
        assert "scan_completed" in names

    def test_match_set_from_legacy_name_includes_canonical(self):
        names = _event_match_set("scan_completed")
        assert "scan.completed" in names
        assert "scan_completed" in names


class TestValidationAcceptsBothForms:
    def test_subscribe_accepts_dot_notation(self):
        """POST /webhooks with events=['scan.completed'] is valid."""
        result = validate_webhook_events(["scan.completed"])
        assert result == ["scan.completed"]

    def test_subscribe_accepts_legacy_alias(self):
        """Backward-compat: legacy snake_case names still validate."""
        result = validate_webhook_events(["scan_completed"])
        assert result == ["scan_completed"]

    def test_single_event_accepts_dot_notation(self):
        assert validate_webhook_event_type("vulnerability.found") == "vulnerability.found"


class TestWebhookModelAcceptsBothForms:
    def test_webhook_model_accepts_dot_notation(self):
        w = Webhook(url="https://example.com/hook", events=["scan.completed"])
        assert "scan.completed" in w.events

    def test_webhook_model_accepts_legacy_alias(self):
        w = Webhook(url="https://example.com/hook", events=["scan_completed"])
        assert "scan_completed" in w.events


class TestWebhookTriggerHandlesOldName:
    """
    A subscription with ``events=["scan_completed"]`` (legacy name stored in
    MongoDB) must still fire when the dispatcher emits ``"scan.completed"``.
    """

    def test_legacy_subscription_matches_canonical_event(self):
        # Build a subscription doc that looks like what's in MongoDB today:
        # events stored under the old snake_case name.
        subscription_doc = {
            "_id": "wh-1",
            "project_id": None,
            "team_id": None,
            "url": "https://example.com/hook",
            "events": ["scan_completed"],
            "is_active": True,
        }

        # Mock the async cursor returned by db.webhooks.find(...)
        class _AsyncCursor:
            def __init__(self, docs: List[Dict[str, Any]]):
                self._docs = docs

            def __aiter__(self):
                self._iter = iter(self._docs)
                return self

            async def __anext__(self):
                try:
                    return next(self._iter)
                except StopIteration as exc:
                    raise StopAsyncIteration from exc

        captured_queries: List[Dict[str, Any]] = []

        def _find(query: Dict[str, Any]) -> "_AsyncCursor":
            captured_queries.append(query)
            # Only return the subscription for the global (project_id is None)
            # query branch; return empty for project/team branches.
            if query.get("project_id") is None and query.get("team_id") is None:
                return _AsyncCursor([subscription_doc])
            return _AsyncCursor([])

        db = MagicMock()
        db.webhooks = MagicMock()
        db.webhooks.find = MagicMock(side_effect=_find)
        db.projects = MagicMock()
        db.projects.find_one = AsyncMock(return_value=None)

        service = WebhookService()
        webhooks = asyncio.run(
            service._get_webhooks_for_event(db, project_id=None, event_type=WEBHOOK_EVENT_SCAN_COMPLETED)
        )

        # The subscription with legacy events=["scan_completed"] must be picked
        # up when the dispatcher fires "scan.completed".
        assert len(webhooks) == 1
        assert webhooks[0].id == "wh-1"

        # And the query used `$in` with both the canonical and alias names,
        # so MongoDB's array-membership predicate will match the legacy doc.
        assert captured_queries, "expected at least one mongo query to be issued"
        match_criteria = captured_queries[-1]["events"]
        assert "$in" in match_criteria
        event_names = match_criteria["$in"]
        assert "scan.completed" in event_names
        assert "scan_completed" in event_names


class TestAliasMapCompleteness:
    """Sanity-check: every alias resolves to a canonical name we actually emit."""

    def test_all_aliases_resolve_to_dot_notation(self):
        for alias, canonical in WEBHOOK_EVENT_ALIASES.items():
            assert "." in canonical, f"alias {alias} -> {canonical} is not dot-notation"
