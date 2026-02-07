"""Tests for User model and notification preferences validator."""

import pytest
from pydantic import ValidationError

from app.models.user import User


class TestUserModel:
    def test_minimal_valid_user(self):
        user = User(username="testuser", email="test@example.com")
        assert user.username == "testuser"
        assert user.email == "test@example.com"

    def test_invalid_email_rejected(self):
        with pytest.raises(ValidationError):
            User(username="testuser", email="not-an-email")

    def test_default_auth_provider(self):
        user = User(username="test", email="test@example.com")
        assert user.auth_provider == "local"

    def test_default_permissions_empty(self):
        user = User(username="test", email="test@example.com")
        assert user.permissions == []

    def test_totp_disabled_by_default(self):
        user = User(username="test", email="test@example.com")
        assert user.totp_enabled is False
        assert user.totp_secret is None

    def test_is_active_by_default(self):
        user = User(username="test", email="test@example.com")
        assert user.is_active is True

    def test_not_verified_by_default(self):
        user = User(username="test", email="test@example.com")
        assert user.is_verified is False


class TestNotificationPreferencesValidator:
    def test_valid_preferences_accepted(self):
        user = User(
            username="test",
            email="test@example.com",
            notification_preferences={
                "analysis_completed": ["email", "slack"],
                "vulnerability_found": ["email"],
            },
        )
        assert user.notification_preferences["analysis_completed"] == ["email", "slack"]

    def test_none_replaced_with_defaults(self):
        user = User(
            username="test",
            email="test@example.com",
            notification_preferences=None,
        )
        assert "analysis_completed" in user.notification_preferences
        assert "vulnerability_found" in user.notification_preferences

    def test_invalid_event_stripped(self):
        user = User(
            username="test",
            email="test@example.com",
            notification_preferences={
                "bogus_event": ["email"],
                "analysis_completed": ["email"],
            },
        )
        assert "bogus_event" not in user.notification_preferences
        assert "analysis_completed" in user.notification_preferences

    def test_invalid_channel_stripped(self):
        user = User(
            username="test",
            email="test@example.com",
            notification_preferences={
                "analysis_completed": ["email", "telegram"],
            },
        )
        assert user.notification_preferences["analysis_completed"] == ["email"]

    def test_missing_events_get_defaults(self):
        user = User(
            username="test",
            email="test@example.com",
            notification_preferences={},
        )
        # Both default events should be restored
        assert "analysis_completed" in user.notification_preferences
        assert "vulnerability_found" in user.notification_preferences

    def test_channels_not_list_rejected_by_pydantic(self):
        # Pydantic validates type before field_validator runs,
        # so a string value for list[str] raises ValidationError
        with pytest.raises(ValidationError):
            User(
                username="test",
                email="test@example.com",
                notification_preferences={
                    "analysis_completed": "email",  # string instead of list
                },
            )

    def test_default_preferences_structure(self):
        user = User(username="test", email="test@example.com")
        prefs = user.notification_preferences
        assert prefs is not None
        assert "analysis_completed" in prefs
        assert "vulnerability_found" in prefs
        assert "email" in prefs["analysis_completed"]

    def test_mattermost_channel_valid(self):
        user = User(
            username="test",
            email="test@example.com",
            notification_preferences={
                "analysis_completed": ["mattermost"],
                "vulnerability_found": ["mattermost"],
            },
        )
        assert user.notification_preferences["analysis_completed"] == ["mattermost"]

    def test_all_invalid_channels_restores_defaults(self):
        user = User(
            username="test",
            email="test@example.com",
            notification_preferences={
                "analysis_completed": ["telegram", "discord"],  # all invalid
                "vulnerability_found": ["telegram"],  # all invalid
            },
        )
        # Events with no valid channels are skipped, then defaults are restored
        assert "analysis_completed" in user.notification_preferences
        assert "vulnerability_found" in user.notification_preferences
