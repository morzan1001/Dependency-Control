"""Tests for ProjectInvitation and SystemInvitation models."""

import pytest
from datetime import datetime, timezone, timedelta
from pydantic import ValidationError

from app.models.invitation import ProjectInvitation, SystemInvitation


class TestProjectInvitationModel:
    """ProjectInvitation model creation, defaults, and required fields."""

    def _make_project_invitation(self, **overrides):
        """Factory for a valid ProjectInvitation with minimal required fields."""
        defaults = {
            "project_id": "proj-1",
            "email": "dev@example.com",
            "role": "viewer",
            "token": "tok-abc-123",
            "invited_by": "admin-1",
            "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
        }
        defaults.update(overrides)
        return ProjectInvitation(**defaults)

    def test_minimal_valid(self):
        """ProjectInvitation can be created with all required fields."""
        inv = self._make_project_invitation()
        assert inv.project_id == "proj-1"
        assert inv.email == "dev@example.com"
        assert inv.role == "viewer"
        assert inv.token == "tok-abc-123"
        assert inv.invited_by == "admin-1"

    def test_id_auto_generated(self):
        """Each ProjectInvitation gets a unique auto-generated id."""
        a = self._make_project_invitation()
        b = self._make_project_invitation()
        assert a.id is not None
        assert len(a.id) > 0
        assert a.id != b.id

    def test_created_at_auto_set(self):
        """created_at is set to a UTC datetime by default."""
        before = datetime.now(timezone.utc)
        inv = self._make_project_invitation()
        after = datetime.now(timezone.utc)
        assert before <= inv.created_at <= after

    def test_expires_at_is_required(self):
        """Omitting expires_at raises ValidationError."""
        with pytest.raises(ValidationError):
            ProjectInvitation(
                project_id="p1",
                email="a@b.com",
                role="viewer",
                token="t",
                invited_by="u1",
            )

    def test_invalid_email_rejected(self):
        """Invalid email raises ValidationError."""
        with pytest.raises(ValidationError):
            self._make_project_invitation(email="not-an-email")

    def test_model_dump_by_alias_contains_id(self):
        """model_dump(by_alias=True) produces '_id' key."""
        inv = self._make_project_invitation()
        dumped = inv.model_dump(by_alias=True)
        assert "_id" in dumped
        assert dumped["_id"] == inv.id

    def test_accepts_id_from_mongo(self):
        """ProjectInvitation accepts _id via validation_alias."""
        inv = self._make_project_invitation(_id="inv-custom-id")
        assert inv.id == "inv-custom-id"

    def test_roundtrip_via_model_dump(self):
        """ProjectInvitation survives model_dump -> reconstruct cycle."""
        original = self._make_project_invitation()
        dumped = original.model_dump(by_alias=True)
        restored = ProjectInvitation(**dumped)
        assert restored.id == original.id
        assert restored.project_id == "proj-1"
        assert restored.email == "dev@example.com"
        assert restored.role == "viewer"


class TestSystemInvitationModel:
    """SystemInvitation model creation, defaults, and required fields."""

    def _make_system_invitation(self, **overrides):
        """Factory for a valid SystemInvitation with minimal required fields."""
        defaults = {
            "email": "newuser@example.com",
            "token": "sys-tok-456",
            "invited_by": "superadmin",
            "expires_at": datetime.now(timezone.utc) + timedelta(days=3),
        }
        defaults.update(overrides)
        return SystemInvitation(**defaults)

    def test_minimal_valid(self):
        """SystemInvitation can be created with all required fields."""
        inv = self._make_system_invitation()
        assert inv.email == "newuser@example.com"
        assert inv.token == "sys-tok-456"
        assert inv.invited_by == "superadmin"

    def test_id_auto_generated(self):
        """Each SystemInvitation gets a unique auto-generated id."""
        a = self._make_system_invitation()
        b = self._make_system_invitation()
        assert a.id is not None
        assert len(a.id) > 0
        assert a.id != b.id

    def test_is_used_defaults_to_false(self):
        """is_used defaults to False."""
        inv = self._make_system_invitation()
        assert inv.is_used is False

    def test_is_used_can_be_set_true(self):
        """is_used can be explicitly set to True."""
        inv = self._make_system_invitation(is_used=True)
        assert inv.is_used is True

    def test_created_at_auto_set(self):
        """created_at is set to a UTC datetime by default."""
        before = datetime.now(timezone.utc)
        inv = self._make_system_invitation()
        after = datetime.now(timezone.utc)
        assert before <= inv.created_at <= after

    def test_expires_at_is_required(self):
        """Omitting expires_at raises ValidationError."""
        with pytest.raises(ValidationError):
            SystemInvitation(
                email="a@b.com",
                token="t",
                invited_by="u1",
            )

    def test_invalid_email_rejected(self):
        """Invalid email raises ValidationError."""
        with pytest.raises(ValidationError):
            self._make_system_invitation(email="bad-email")

    def test_model_dump_by_alias_contains_id(self):
        """model_dump(by_alias=True) produces '_id' key."""
        inv = self._make_system_invitation()
        dumped = inv.model_dump(by_alias=True)
        assert "_id" in dumped
        assert dumped["_id"] == inv.id

    def test_accepts_id_from_mongo(self):
        """SystemInvitation accepts _id via validation_alias."""
        inv = self._make_system_invitation(_id="sys-inv-custom")
        assert inv.id == "sys-inv-custom"

    def test_roundtrip_via_model_dump(self):
        """SystemInvitation survives model_dump -> reconstruct cycle."""
        original = self._make_system_invitation()
        dumped = original.model_dump(by_alias=True)
        restored = SystemInvitation(**dumped)
        assert restored.id == original.id
        assert restored.email == "newuser@example.com"
        assert restored.is_used is False
