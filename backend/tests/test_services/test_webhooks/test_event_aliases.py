"""Legacy snake_case webhook event names are canonicalised on input."""

from __future__ import annotations

from app.core.constants import WEBHOOK_EVENT_ALIASES
from app.schemas.webhook import (
    validate_webhook_event_type,
    validate_webhook_events,
)


class TestValidationAcceptsBothForms:
    def test_subscribe_accepts_dot_notation(self):
        result = validate_webhook_events(["scan.completed"])
        assert result == ["scan.completed"]

    def test_subscribe_stores_a_legacy_name_in_its_canonical_form(self):
        assert validate_webhook_events(["scan_completed"]) == ["scan.completed"]

    def test_single_event_accepts_dot_notation(self):
        assert validate_webhook_event_type("vulnerability.found") == "vulnerability.found"


class TestAliasMapCompleteness:
    def test_all_aliases_resolve_to_dot_notation(self):
        for alias, canonical in WEBHOOK_EVENT_ALIASES.items():
            assert "." in canonical, f"alias {alias} -> {canonical} is not dot-notation"
