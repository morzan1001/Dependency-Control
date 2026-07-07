"""Tests for auth endpoint security fixes.

Covers:
1. refresh-token must NOT bypass the enforced-2FA setup gate (a local user with
   no 2FA configured, while enforce_2fa is on, must only ever get the restricted
   ["auth:setup_2fa"] scope — never full DB permissions).
2. Email-dependent endpoints must gate on the DB system settings the email
   provider actually reads (system_config.smtp_host), not the env SMTP_HOST.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from jose import jwt

from app.core import security
from app.core.config import settings
from app.models.system import SystemSettings

MODULE = "app.api.v1.endpoints.auth"


def _make_settings(**overrides):
    return SystemSettings(**overrides)


def _decode_permissions(access_token: str) -> list:
    payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    return payload.get("permissions", [])


class TestRefreshToken2FAGate:
    def _run_refresh(self, user: dict, system_config: SystemSettings):
        from app.api.v1.endpoints.auth import refresh_token

        token = security.create_refresh_token(user["username"])

        mock_repo = MagicMock()
        mock_repo.get_raw_by_username = AsyncMock(return_value=user)

        with (
            patch(f"{MODULE}.UserRepository", return_value=mock_repo),
            patch(f"{MODULE}.deps.get_system_settings", new_callable=AsyncMock) as mock_get,
        ):
            mock_get.return_value = system_config
            return asyncio.run(refresh_token(refresh_token=token, db=MagicMock()))

    def test_no_2fa_enforced_local_user_gets_only_setup_scope(self):
        """Regression: full DB permissions must NOT be minted on refresh when a
        local user has no 2FA and enforce_2fa is on."""
        user = {
            "username": "bob",
            "is_active": True,
            "totp_enabled": False,
            "auth_provider": "local",
            "permissions": ["admin:manage", "scan:read"],
        }
        system_config = _make_settings(enforce_2fa=True)

        result = self._run_refresh(user, system_config)

        assert _decode_permissions(result["access_token"]) == ["auth:setup_2fa"]

    def test_2fa_configured_user_keeps_full_permissions(self):
        """A user who already has 2FA configured keeps full permissions on refresh."""
        user = {
            "username": "alice",
            "is_active": True,
            "totp_enabled": True,
            "auth_provider": "local",
            "permissions": ["admin:manage", "scan:read"],
        }
        system_config = _make_settings(enforce_2fa=True)

        result = self._run_refresh(user, system_config)

        assert _decode_permissions(result["access_token"]) == ["admin:manage", "scan:read"]

    def test_enforce_2fa_off_keeps_full_permissions(self):
        """When 2FA is not enforced, a local user without 2FA keeps full permissions."""
        user = {
            "username": "carol",
            "is_active": True,
            "totp_enabled": False,
            "auth_provider": "local",
            "permissions": ["scan:read"],
        }
        system_config = _make_settings(enforce_2fa=False)

        result = self._run_refresh(user, system_config)

        assert _decode_permissions(result["access_token"]) == ["scan:read"]

    def test_oidc_user_exempt_from_2fa_gate(self):
        """OIDC users are exempt from enforced-2FA setup restriction."""
        user = {
            "username": "dave",
            "is_active": True,
            "totp_enabled": False,
            "auth_provider": "oidc",
            "permissions": ["scan:read"],
        }
        system_config = _make_settings(enforce_2fa=True)

        result = self._run_refresh(user, system_config)

        assert _decode_permissions(result["access_token"]) == ["scan:read"]


class TestForgotPasswordSmtpGate:
    def _run_forgot(self, system_config, send_mock, user=None):
        from app.api.v1.endpoints.auth import forgot_password

        request = MagicMock()
        request.client.host = "1.2.3.4"

        mock_repo = MagicMock()
        mock_repo.get_raw_by_email = AsyncMock(return_value=user)

        with (
            patch(f"{MODULE}._check_rate_limit", new_callable=AsyncMock),
            patch(f"{MODULE}.deps.get_system_settings", new_callable=AsyncMock) as mock_get,
            patch(f"{MODULE}.UserRepository", return_value=mock_repo),
            patch(f"{MODULE}.send_password_reset_email", send_mock),
        ):
            mock_get.return_value = system_config
            return asyncio.run(
                forgot_password(
                    request=request,
                    background_tasks=MagicMock(),
                    email="user@test.com",
                    db=MagicMock(),
                )
            )

    def test_db_smtp_unset_returns_501(self):
        """Failure B: env SMTP may be set, but if DB smtp_host is empty the
        provider cannot send -> endpoint must surface 501, not claim success."""
        send_mock = AsyncMock()
        with patch.object(settings, "SMTP_HOST", "smtp.env-set.example.com"):
            with pytest.raises(HTTPException) as exc_info:
                self._run_forgot(_make_settings(smtp_host=None), send_mock)

        assert exc_info.value.status_code == 501
        send_mock.assert_not_called()

    def test_db_smtp_set_sends_email_with_system_settings(self):
        """Endpoint->helper contract only: with DB smtp_host set, the endpoint
        calls send_password_reset_email and forwards the DB system settings.

        NOTE: this mocks the helper, so it deliberately does NOT prove the email
        actually goes out. End-to-end Failure A coverage lives in
        test_db_smtp_set_actually_schedules_email_via_real_helper below.
        """
        send_mock = AsyncMock()
        system_config = _make_settings(smtp_host="smtp.db.example.com")
        user = {"email": "user@test.com", "username": "user", "is_active": True, "auth_provider": "local"}

        with patch.object(settings, "SMTP_HOST", None):
            result = self._run_forgot(system_config, send_mock, user=user)

        assert "password reset email has been sent" in result.message
        send_mock.assert_awaited_once()
        assert send_mock.call_args.kwargs["system_settings"] is system_config

    def test_db_smtp_set_actually_schedules_email_via_real_helper(self):
        """Failure A, end-to-end regression: env SMTP_HOST unset but DB smtp_host
        set MUST actually schedule the password-reset email. Exercises the REAL
        send_password_reset_email helper (not a mock), proving the helper now gates
        on the effective DB smtp_host rather than env settings.SMTP_HOST."""
        from app.api.v1.endpoints.auth import forgot_password

        request = MagicMock()
        request.client.host = "1.2.3.4"
        user = {"email": "user@test.com", "username": "user", "is_active": True, "auth_provider": "local"}
        mock_repo = MagicMock()
        mock_repo.get_raw_by_email = AsyncMock(return_value=user)
        background_tasks = MagicMock()
        system_config = _make_settings(smtp_host="smtp.db.example.com")

        with (
            patch(f"{MODULE}._check_rate_limit", new_callable=AsyncMock),
            patch(f"{MODULE}.deps.get_system_settings", new_callable=AsyncMock) as mock_get,
            patch(f"{MODULE}.UserRepository", return_value=mock_repo),
            patch("app.api.v1.helpers.auth.EmailProvider"),
            patch.object(settings, "SMTP_HOST", None),
        ):
            mock_get.return_value = system_config
            asyncio.run(
                forgot_password(
                    request=request,
                    background_tasks=background_tasks,
                    email="user@test.com",
                    db=MagicMock(),
                )
            )

        # The real helper must schedule the send even with env SMTP_HOST unset.
        background_tasks.add_task.assert_called_once()
        assert background_tasks.add_task.call_args.kwargs["system_settings"] is system_config


class TestResendVerificationSmtpGate:
    def test_db_smtp_unset_returns_501(self):
        from app.api.v1.endpoints.auth import resend_verification_email_public

        with patch.object(settings, "SMTP_HOST", "smtp.env-set.example.com"):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    resend_verification_email_public(
                        background_tasks=MagicMock(),
                        email="user@test.com",
                        db=MagicMock(),
                        system_config=_make_settings(smtp_host=None),
                    )
                )

        assert exc_info.value.status_code == 501


class TestRequestVerificationSmtpGate:
    def test_db_smtp_unset_returns_501(self, regular_user):
        from app.api.v1.endpoints.auth import request_verification_email

        regular_user.is_verified = False
        with patch.object(settings, "SMTP_HOST", "smtp.env-set.example.com"):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    request_verification_email(
                        background_tasks=MagicMock(),
                        current_user=regular_user,
                        system_config=_make_settings(smtp_host=None),
                    )
                )

        assert exc_info.value.status_code == 501

    def test_db_smtp_set_sends_verification(self, regular_user):
        """Endpoint->helper contract only: with DB smtp_host set, the endpoint
        calls send_verification_email and forwards the DB system settings.

        NOTE: this mocks the helper, so it deliberately does NOT prove the email
        actually goes out. End-to-end Failure A coverage lives in
        test_db_smtp_set_actually_schedules_verification_via_real_helper below.
        """
        from app.api.v1.endpoints.auth import request_verification_email

        regular_user.is_verified = False
        system_config = _make_settings(smtp_host="smtp.db.example.com")
        send_mock = AsyncMock()

        with (
            patch.object(settings, "SMTP_HOST", None),
            patch(f"{MODULE}.send_verification_email", send_mock),
        ):
            result = asyncio.run(
                request_verification_email(
                    background_tasks=MagicMock(),
                    current_user=regular_user,
                    system_config=system_config,
                )
            )

        assert result.message == "Verification email sent"
        send_mock.assert_awaited_once()
        assert send_mock.call_args.kwargs["system_settings"] is system_config

    def test_db_smtp_set_actually_schedules_verification_via_real_helper(self, regular_user):
        """Failure A, end-to-end regression: env SMTP_HOST unset but DB smtp_host
        set MUST actually schedule the verification email. Exercises the REAL
        send_verification_email helper (not a mock), proving the helper now gates
        on the effective DB smtp_host rather than env settings.SMTP_HOST."""
        from app.api.v1.endpoints.auth import request_verification_email

        regular_user.is_verified = False
        system_config = _make_settings(smtp_host="smtp.db.example.com")
        background_tasks = MagicMock()

        with (
            patch.object(settings, "SMTP_HOST", None),
            patch("app.api.v1.helpers.auth.EmailProvider"),
        ):
            result = asyncio.run(
                request_verification_email(
                    background_tasks=background_tasks,
                    current_user=regular_user,
                    system_config=system_config,
                )
            )

        assert result.message == "Verification email sent"
        # The real helper must schedule the send even with env SMTP_HOST unset.
        background_tasks.add_task.assert_called_once()
        assert background_tasks.add_task.call_args.kwargs["system_settings"] is system_config
