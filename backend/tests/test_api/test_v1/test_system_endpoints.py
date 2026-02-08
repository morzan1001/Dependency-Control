"""Tests for system settings API endpoints.

Tests get/update settings, public config, app config, and notification channels.
"""

import asyncio
from unittest.mock import ANY, AsyncMock, MagicMock, patch

from app.models.system import SystemSettings

MODULE = "app.api.v1.endpoints.system"


def _make_settings(**overrides):
    """Create SystemSettings with optional overrides."""
    return SystemSettings(**overrides)


class TestGetSettings:
    def test_returns_settings(self, admin_user):
        from app.api.v1.endpoints.system import get_settings

        settings = _make_settings(instance_name="My Instance")

        with patch(f"{MODULE}.deps.get_system_settings", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = settings
            result = asyncio.run(
                get_settings(
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert result.instance_name == "My Instance"

    def test_passes_auto_init_true(self, admin_user):
        from app.api.v1.endpoints.system import get_settings

        settings = _make_settings()

        with patch(f"{MODULE}.deps.get_system_settings", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = settings
            asyncio.run(get_settings(current_user=admin_user, db=MagicMock()))

        mock_get.assert_called_once_with(ANY, auto_init=True)


class TestUpdateSettings:
    def test_updates_settings(self, admin_user):
        from app.api.v1.endpoints.system import update_settings
        from app.schemas.system import SystemSettingsUpdate

        update_data = SystemSettingsUpdate(instance_name="Updated")
        updated_settings = _make_settings(instance_name="Updated")

        mock_repo = MagicMock()
        mock_repo.update = AsyncMock(return_value=updated_settings)

        with patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo):
            result = asyncio.run(
                update_settings(
                    settings_in=update_data,
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert result.instance_name == "Updated"
        mock_repo.update.assert_called_once()

    def test_new_slack_token_clears_refresh(self, admin_user):
        from app.api.v1.endpoints.system import update_settings
        from app.schemas.system import SystemSettingsUpdate

        update_data = SystemSettingsUpdate(slack_bot_token="xoxb-new-token")
        current_settings = _make_settings(
            slack_bot_token="xoxb-old-token",
            slack_refresh_token="old-refresh",
            slack_token_expires_at=12345.0,
        )
        updated_settings = _make_settings(
            slack_bot_token="xoxb-new-token",
            slack_refresh_token=None,
            slack_token_expires_at=None,
        )

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=current_settings)
        mock_repo.update = AsyncMock(return_value=updated_settings)

        with patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo):
            asyncio.run(
                update_settings(
                    settings_in=update_data,
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        # Verify refresh fields are cleared in the update call
        call_args = mock_repo.update.call_args[0][0]
        assert call_args["slack_refresh_token"] is None
        assert call_args["slack_token_expires_at"] is None

    def test_same_slack_token_keeps_refresh(self, admin_user):
        from app.api.v1.endpoints.system import update_settings
        from app.schemas.system import SystemSettingsUpdate

        update_data = SystemSettingsUpdate(slack_bot_token="xoxb-same-token")
        current_settings = _make_settings(
            slack_bot_token="xoxb-same-token",
            slack_refresh_token="keep-this",
            slack_token_expires_at=99999.0,
        )

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=current_settings)
        mock_repo.update = AsyncMock(return_value=current_settings)

        with patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo):
            asyncio.run(
                update_settings(
                    settings_in=update_data,
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        call_args = mock_repo.update.call_args[0][0]
        assert "slack_refresh_token" not in call_args


class TestGetPublicConfig:
    def test_returns_public_flags(self):
        from app.api.v1.endpoints.system import get_public_config

        settings = _make_settings(
            allow_public_registration=True,
            enforce_2fa=True,
            oidc_enabled=True,
            oidc_provider_name="Keycloak",
        )

        with patch(f"{MODULE}.deps.get_system_settings", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = settings
            result = asyncio.run(get_public_config(db=MagicMock()))

        assert result.allow_public_registration is True
        assert result.enforce_2fa is True
        assert result.oidc_enabled is True
        assert result.oidc_provider_name == "Keycloak"

    def test_defaults_all_false(self):
        from app.api.v1.endpoints.system import get_public_config

        settings = _make_settings()

        with patch(f"{MODULE}.deps.get_system_settings", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = settings
            result = asyncio.run(get_public_config(db=MagicMock()))

        assert result.allow_public_registration is False
        assert result.enforce_2fa is False
        assert result.oidc_enabled is False


class TestGetAppConfig:
    def test_returns_app_config(self, regular_user):
        from app.api.v1.endpoints.system import get_app_config

        settings = _make_settings(
            project_limit_per_user=10,
            gitlab_integration_enabled=True,
            gitlab_access_token="glpat-tok",
            slack_bot_token="xoxb-tok",
            smtp_host="mail.test.com",
            smtp_user="user",
        )

        with patch(f"{MODULE}.deps.get_system_settings", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = settings
            result = asyncio.run(
                get_app_config(
                    current_user=regular_user,
                    db=MagicMock(),
                )
            )

        assert result.project_limit_per_user == 10
        assert result.notifications.slack is True
        assert result.notifications.email is True

    def test_no_smtp_means_no_email_channel(self, regular_user):
        from app.api.v1.endpoints.system import get_app_config

        settings = _make_settings()  # No SMTP configured

        with patch(f"{MODULE}.deps.get_system_settings", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = settings
            result = asyncio.run(
                get_app_config(
                    current_user=regular_user,
                    db=MagicMock(),
                )
            )

        assert result.notifications.email is False
        assert result.notifications.slack is False
        assert result.notifications.mattermost is False
        assert result.gitlab_token_configured is False


class TestGetNotificationChannels:
    def test_returns_channels_based_on_config(self, regular_user):
        from app.api.v1.endpoints.system import get_notification_channels

        settings = _make_settings(
            smtp_host="mail.com",
            smtp_user="u",
            slack_bot_token="xoxb-tok",
            mattermost_bot_token="mm-tok",
            mattermost_url="https://mm.com",
        )

        with patch(f"{MODULE}.deps.get_system_settings", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = settings
            result = asyncio.run(
                get_notification_channels(
                    current_user=regular_user,
                    db=MagicMock(),
                )
            )

        assert "email" in result
        assert "slack" in result
        assert "mattermost" in result

    def test_empty_when_nothing_configured(self, regular_user):
        from app.api.v1.endpoints.system import get_notification_channels

        settings = _make_settings()

        with patch(f"{MODULE}.deps.get_system_settings", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = settings
            result = asyncio.run(
                get_notification_channels(
                    current_user=regular_user,
                    db=MagicMock(),
                )
            )

        assert result == []
