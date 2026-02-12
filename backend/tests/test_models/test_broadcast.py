"""Tests for Broadcast model."""

import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from app.models.broadcast import Broadcast


class TestBroadcastModel:
    """Broadcast model creation, defaults, and required fields."""

    def _make_broadcast(self, **overrides):
        """Factory for a valid Broadcast with minimal required fields."""
        defaults = {
            "type": "general",
            "target_type": "global",
            "subject": "Maintenance window",
            "message": "System will be down for maintenance.",
            "created_by": "admin-1",
        }
        defaults.update(overrides)
        return Broadcast(**defaults)

    def test_minimal_valid(self):
        """Broadcast can be created with only required fields."""
        b = self._make_broadcast()
        assert b.type == "general"
        assert b.target_type == "global"
        assert b.subject == "Maintenance window"
        assert b.message == "System will be down for maintenance."
        assert b.created_by == "admin-1"

    def test_id_auto_generated(self):
        """Each Broadcast gets a unique auto-generated id."""
        a = self._make_broadcast()
        b = self._make_broadcast()
        assert a.id is not None
        assert len(a.id) > 0
        assert a.id != b.id

    def test_default_stats_zero(self):
        """Stat counters default to zero."""
        b = self._make_broadcast()
        assert b.recipient_count == 0
        assert b.project_count == 0

    def test_default_optional_fields_none(self):
        """Optional list fields default to None."""
        b = self._make_broadcast()
        assert b.packages is None
        assert b.channels is None
        assert b.teams is None

    def test_created_at_auto_set(self):
        """created_at is set to a UTC datetime by default."""
        before = datetime.now(timezone.utc)
        b = self._make_broadcast()
        after = datetime.now(timezone.utc)
        assert before <= b.created_at <= after

    def test_missing_required_field_rejected(self):
        """Omitting a required field raises ValidationError."""
        with pytest.raises(ValidationError):
            Broadcast(
                type="general",
                target_type="global",
                subject="s",
                # message is missing
                created_by="u1",
            )

    def test_custom_stats(self):
        """Stats can be set to custom values."""
        b = self._make_broadcast(recipient_count=42, project_count=5)
        assert b.recipient_count == 42
        assert b.project_count == 5

    def test_optional_lists_populated(self):
        """Optional list fields accept values when provided."""
        b = self._make_broadcast(
            packages=[{"name": "requests", "version": "2.31.0"}],
            channels=["email", "slack"],
            teams=["team-a", "team-b"],
        )
        assert len(b.packages) == 1
        assert b.packages[0]["name"] == "requests"
        assert b.channels == ["email", "slack"]
        assert b.teams == ["team-a", "team-b"]


class TestBroadcastIdAlias:
    """Broadcast _id alias round-trip for MongoDB compatibility."""

    def _make_broadcast(self, **overrides):
        """Factory for a valid Broadcast with minimal required fields."""
        defaults = {
            "type": "general",
            "target_type": "global",
            "subject": "s",
            "message": "m",
            "created_by": "u1",
        }
        defaults.update(overrides)
        return Broadcast(**defaults)

    def test_model_dump_by_alias_contains_id(self):
        """model_dump(by_alias=True) produces '_id' key."""
        b = self._make_broadcast()
        dumped = b.model_dump(by_alias=True)
        assert "_id" in dumped
        assert dumped["_id"] == b.id

    def test_accepts_id_from_mongo(self):
        """Broadcast accepts _id via validation_alias."""
        b = Broadcast(
            _id="custom-broadcast-id",
            type="advisory",
            target_type="teams",
            subject="s",
            message="m",
            created_by="u1",
        )
        assert b.id == "custom-broadcast-id"

    def test_roundtrip_via_model_dump(self):
        """Broadcast survives model_dump -> reconstruct cycle."""
        original = self._make_broadcast()
        dumped = original.model_dump(by_alias=True)
        restored = Broadcast(**dumped)
        assert restored.id == original.id
        assert restored.type == original.type
        assert restored.subject == original.subject
