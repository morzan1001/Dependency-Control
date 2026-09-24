"""Auth endpoint security: refresh-token must not bypass the enforced-2FA setup gate, and email endpoints must gate on the DB system settings (system_config.smtp_host), not env SMTP_HOST."""

import asyncio
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from jose import jwt

from app.core import security
from app.core.config import settings
from app.models.system import SystemSettings
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.api.v1.endpoints.auth"
_USER_LOOKUP = "app.repositories.users.UserRepository.get_raw_by_username"

# The pad targets 200ms; the floor sits below it so scheduler jitter cannot flake the assertion.
_TIMING_PAD_FLOOR_SECONDS = 0.15

_BAD_REQUEST = 400
_FORBIDDEN = 403
_NOT_FOUND = 404
_MSG_CREDENTIALS = "Could not validate credentials"
# Stored datetimes come back naive and .timestamp() reads them in the process timezone, so the
# logout lies far enough ahead to stay ahead of any offset.
_LOGOUT_AFTER_ISSUE = timedelta(days=1)


def _make_settings(**overrides):
    return SystemSettings(**overrides)


def _decode_permissions(access_token: str) -> list:
    payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    return payload.get("permissions", [])


def _refresh(token: str, *users: dict, system_config: SystemSettings | None = None):
    from app.api.v1.endpoints.auth import refresh_token

    async def run():
        db = FakeDatabase()
        for user in users:
            await db.users.insert_one(dict(user))
        with patch(f"{MODULE}.deps.get_system_settings", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = system_config or _make_settings()
            return await refresh_token(refresh_token=token, db=db)

    return asyncio.run(run())


class TestRefreshToken2FAGate:
    def _run_refresh(self, user: dict, system_config: SystemSettings):
        return _refresh(security.create_refresh_token(user["username"]), user, system_config=system_config)

    def test_no_2fa_enforced_local_user_gets_only_setup_scope(self):
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

    def test_a_user_document_without_the_totp_field_counts_as_2fa_unconfigured(self):
        """Documents written before the 2FA columns existed carry no totp_enabled at all."""
        user = {
            "username": "erin",
            "is_active": True,
            "auth_provider": "local",
            "permissions": ["admin:manage", "scan:read"],
        }
        system_config = _make_settings(enforce_2fa=True)

        result = self._run_refresh(user, system_config)

        assert _decode_permissions(result["access_token"]) == ["auth:setup_2fa"]


class TestRefreshTokenType:
    @pytest.mark.parametrize(
        "token",
        [
            pytest.param(security.create_access_token("bob", permissions=["admin:manage"]), id="access"),
            pytest.param(security.create_password_reset_token("bob@test.com"), id="password-reset"),
        ],
    )
    def test_a_token_of_another_type_is_not_accepted_in_place_of_a_refresh_token(self, token):
        with patch(_USER_LOOKUP, new_callable=AsyncMock) as lookup:
            with pytest.raises(HTTPException) as exc_info:
                _refresh(token)

        assert exc_info.value.status_code == _FORBIDDEN
        assert exc_info.value.detail == _MSG_CREDENTIALS
        lookup.assert_not_awaited()


class TestRefreshTokenRejections:
    def test_a_token_that_does_not_decode_is_403(self):
        with pytest.raises(HTTPException) as exc_info:
            _refresh("not-a-jwt")

        assert exc_info.value.status_code == _FORBIDDEN

    def test_an_unknown_user_is_404(self):
        with pytest.raises(HTTPException) as exc_info:
            _refresh(security.create_refresh_token("ghost"))

        assert exc_info.value.status_code == _NOT_FOUND

    def test_an_inactive_user_is_400(self):
        user = {"username": "bob", "is_active": False, "permissions": []}

        with pytest.raises(HTTPException) as exc_info:
            _refresh(security.create_refresh_token("bob"), user)

        assert exc_info.value.status_code == _BAD_REQUEST

    def test_a_token_issued_before_the_last_logout_is_403(self):
        user = {
            "username": "bob",
            "is_active": True,
            "permissions": [],
            "last_logout_at": datetime.now(timezone.utc) + _LOGOUT_AFTER_ISSUE,
        }

        with pytest.raises(HTTPException) as exc_info:
            _refresh(security.create_refresh_token("bob"), user)

        assert exc_info.value.status_code == _FORBIDDEN


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
        """Even with env SMTP set, an empty DB smtp_host must surface 501 rather than claim success."""
        send_mock = AsyncMock()
        with patch.object(settings, "SMTP_HOST", "smtp.env-set.example.com"):
            with pytest.raises(HTTPException) as exc_info:
                self._run_forgot(_make_settings(smtp_host=None), send_mock)

        assert exc_info.value.status_code == 501
        send_mock.assert_not_called()

    def test_db_smtp_set_sends_email_with_system_settings(self):
        """Contract only (helper mocked): with DB smtp_host set, the endpoint forwards DB system settings to send_password_reset_email."""
        send_mock = AsyncMock()
        system_config = _make_settings(smtp_host="smtp.db.example.com")
        user = {"email": "user@test.com", "username": "user", "is_active": True, "auth_provider": "local"}

        with patch.object(settings, "SMTP_HOST", None):
            result = self._run_forgot(system_config, send_mock, user=user)

        assert "password reset email has been sent" in result.message
        send_mock.assert_awaited_once()
        assert send_mock.call_args.kwargs["system_settings"] is system_config

    def test_db_smtp_set_actually_schedules_email_via_real_helper(self):
        """With env SMTP_HOST unset but DB smtp_host set, the real send_password_reset_email helper must still schedule the email (gates on effective DB smtp_host)."""
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

        background_tasks.add_task.assert_called_once()
        assert background_tasks.add_task.call_args.kwargs["system_settings"] is system_config


class _MemoryCache:
    """Stand-in for the Redis-backed cache so the real rate limiter can actually count."""

    def __init__(self):
        self._data: dict = {}

    async def get(self, key):
        return self._data.get(key)

    async def set(self, key, value, ttl_seconds=None):
        self._data[key] = value
        return True


def _run_forgot_password(user=None, cache=None, host="1.2.3.4", send_mock=None):
    from app.api.v1.endpoints.auth import forgot_password

    request = MagicMock()
    request.client.host = host
    mock_repo = MagicMock()
    mock_repo.get_raw_by_email = AsyncMock(return_value=user)

    rate_limit_patch = (
        patch(f"{MODULE}.cache_service", cache)
        if cache
        else patch(f"{MODULE}._check_rate_limit", new_callable=AsyncMock)
    )

    with (
        rate_limit_patch,
        patch(f"{MODULE}.deps.get_system_settings", new_callable=AsyncMock) as mock_get,
        patch(f"{MODULE}.UserRepository", return_value=mock_repo),
        patch(f"{MODULE}.send_password_reset_email", send_mock or AsyncMock()),
    ):
        mock_get.return_value = _make_settings(smtp_host="smtp.db.example.com")
        return asyncio.run(
            forgot_password(
                request=request,
                background_tasks=MagicMock(),
                email="user@test.com",
                db=MagicMock(),
            )
        )


class TestForgotPasswordRateLimit:
    """The budget on this unauthenticated endpoint is the only thing standing between a caller and
    unlimited password-reset mail to an address they do not own."""

    def test_a_client_gets_three_attempts_before_being_rejected(self):
        cache = _MemoryCache()

        for _ in range(3):
            assert _run_forgot_password(cache=cache) is not None

        with pytest.raises(HTTPException) as exc_info:
            _run_forgot_password(cache=cache)

        assert exc_info.value.status_code == 429

    def test_the_budget_is_counted_per_client_address(self):
        cache = _MemoryCache()
        for _ in range(3):
            _run_forgot_password(cache=cache, host="1.2.3.4")

        assert _run_forgot_password(cache=cache, host="5.6.7.8") is not None


class TestForgotPasswordConstantTime:
    def test_an_unknown_address_takes_as_long_to_answer_as_a_registered_one(self):
        known = {"email": "user@test.com", "username": "user", "is_active": True, "auth_provider": "local"}

        start = time.monotonic()
        _run_forgot_password(user=known)
        registered_duration = time.monotonic() - start

        start = time.monotonic()
        _run_forgot_password(user=None)
        unknown_duration = time.monotonic() - start

        assert registered_duration >= _TIMING_PAD_FLOOR_SECONDS
        assert unknown_duration >= _TIMING_PAD_FLOOR_SECONDS


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
        """Contract only (helper mocked): with DB smtp_host set, the endpoint forwards DB system settings to send_verification_email."""
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
        """With env SMTP_HOST unset but DB smtp_host set, the real send_verification_email helper must still schedule the email (gates on effective DB smtp_host)."""
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
        background_tasks.add_task.assert_called_once()
        assert background_tasks.add_task.call_args.kwargs["system_settings"] is system_config
