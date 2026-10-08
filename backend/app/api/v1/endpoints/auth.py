import hmac
import logging
import secrets
from collections.abc import Awaitable
from datetime import datetime, timezone
from typing import Annotated, Any
from urllib.parse import urlencode

import httpx
from fastapi import (
    BackgroundTasks,
    Body,
    Depends,
    Form,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm

from app.api import deps
from app.api.deps import DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.auth import require_email_configured, send_password_reset_email, send_verification_email
from app.api.v1.helpers.responses import (
    RESP_400,
    RESP_400_401_500,
    RESP_400_403,
    RESP_400_403_404,
    RESP_400_404,
    RESP_400_500,
    RESP_501,
    RESP_AUTH,
    RESP_AUTH_400_501,
)
from app.core import security
from app.core.cache import cache_service
from app.core.config import settings
from app.core.constants import (
    AUTH_PROVIDER_LOCAL,
    OIDC_HANDOFF_TTL_SECONDS,
    OIDC_HTTP_TIMEOUT_SECONDS,
    OIDC_STATE_TTL_SECONDS,
)
from app.core.http_utils import InstrumentedAsyncClient
from app.core.metrics import (
    auth_2fa_verifications_total,
    auth_login_attempts_total,
    auth_oidc_logins_total,
    auth_password_resets_total,
    auth_signups_total,
)
from app.core.permissions import Permissions
from app.models.system import SystemSettings
from app.models.user import User, is_local_account
from app.repositories.token_blacklist import TokenBlacklistRepository
from app.repositories.users import UserRepository
from app.schemas.auth import (
    EmailVerifyResponse,
    ForgotPasswordResponse,
    LogoutResponse,
    PasswordResetResponse,
    VerificationEmailResponse,
)
from app.schemas.token import Token
from app.schemas.user import UserResponse
from app.schemas.user import UserPasswordReset, UserSignup

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

_MSG_USER_INACTIVE = "User account is inactive"
_MSG_CREDENTIALS = "Could not validate credentials"
_MSG_INVALID_RESET_TOKEN = "Invalid or expired reset token"


async def _within_rate_limit(key: str, max_attempts: int, window_seconds: int) -> bool:
    """Count this attempt; True while the budget holds or Redis is unreachable."""
    attempts = await cache_service.incr(f"rate_limit:{key}", window_seconds)
    return attempts is None or attempts <= max_attempts


async def _check_rate_limit(key: str, max_attempts: int = 5, window_seconds: int = 300) -> None:
    if not await _within_rate_limit(key, max_attempts, window_seconds):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many attempts. Please try again in {window_seconds // 60} minutes.",
        )


def _client_host(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def _within_email_budget(scope: str, email: str) -> bool:
    """Counted for every request, known address or not, so the budget reveals nothing."""
    return await _within_rate_limit(f"{scope}_email:{email.strip().casefold()}", max_attempts=3, window_seconds=3600)


async def _lookup_user_for_login(user_repo: UserRepository, username: str) -> dict | None:
    """Try username then email lookup."""
    user = await user_repo.get_raw_by_username(username)
    if not user:
        user = await user_repo.get_raw_by_email(username)
    return user


async def _verify_totp_or_raise(user_repo: UserRepository, user: dict, otp: str | None) -> None:
    """Verify TOTP code. Raises HTTPException on failure."""
    if not otp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="2FA required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    totp_secret = user.get("totp_secret")
    if not totp_secret:
        logger.error(f"User {user.get('username')} has totp_enabled=True but no totp_secret")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="2FA configuration error. Please contact support.",
        )

    step = security.verify_totp(totp_secret, otp)
    if step is None or not await user_repo.claim_totp_step(user["_id"], step):
        auth_2fa_verifications_total.labels(result="failed").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OTP code",
            headers={"WWW-Authenticate": "Bearer"},
        )
    auth_2fa_verifications_total.labels(result="success").inc()


def _ensure_email_verified(user: dict, system_config: SystemSettings) -> None:
    # An SSO account's address is its identity provider's to vouch for.
    if (
        system_config.enforce_email_verification
        and not user.get("is_verified", False)
        and is_local_account(user.get("auth_provider"))
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _session_tokens(user: dict, system_config: SystemSettings) -> dict[str, str]:
    """A token pair for a password session; only the setup-2FA scope while enforced 2FA is unconfigured."""
    if (
        system_config.enforce_2fa
        and not user.get("totp_enabled", False)
        and is_local_account(user.get("auth_provider"))
    ):
        permissions = [Permissions.AUTH_SETUP_2FA]
    else:
        permissions = list(user.get("permissions", []))
    access_token, refresh_token = security.create_token_pair(str(user["_id"]), permissions)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post(
    "/login/access-token",
    response_model=Token,
    summary="Login to get access token",
    responses=RESP_400_401_500,
)
async def login_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DatabaseDep,
    otp: Annotated[str | None, Form()] = None,
) -> Any:
    """OAuth2-compatible token login; accepts username/email, password, and otp when 2FA is enabled."""
    await _check_rate_limit(f"login:{form_data.username.strip().casefold()}")
    user_repo = UserRepository(db)
    user = await _lookup_user_for_login(user_repo, form_data.username)

    if not user or not security.verify_password(form_data.password, user.get("hashed_password")):
        auth_login_attempts_total.labels(status="failed").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.get("is_active", True):
        auth_login_attempts_total.labels(status="inactive_user").inc()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )

    system_config = await deps.get_system_settings(db)
    _ensure_email_verified(user, system_config)
    if user.get("totp_enabled", False):
        await _verify_totp_or_raise(user_repo, user, otp)

    auth_login_attempts_total.labels(status="success").inc()

    return _session_tokens(user, system_config)


@router.post(
    "/login/refresh-token",
    response_model=Token,
    summary="Refresh access token",
    responses=RESP_400_403_404,
)
async def refresh_token(
    refresh_token: Annotated[str, Body(embed=True, description="The refresh token obtained during login")],
    db: DatabaseDep,
) -> Any:
    """Exchange a refresh token for a new pair; the presented refresh token is spent."""
    try:
        claims, user = await deps.decode_token(refresh_token, "refresh", db)
    except deps.TokenRejected as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=_MSG_CREDENTIALS) from exc
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )

    system_config = await deps.get_system_settings(db)
    _ensure_email_verified(user, system_config)
    # The insert is the atomic step: of two concurrent exchanges of one token only one lists it.
    if not await TokenBlacklistRepository(db).blacklist_token(
        claims.jti, datetime.fromtimestamp(claims.exp, tz=timezone.utc), reason="refresh_rotated"
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=_MSG_CREDENTIALS)
    return _session_tokens(user, system_config)


@router.post(
    "/signup",
    response_model=UserResponse,
    summary="Register a new user",
    responses={**RESP_400_403, 503: {"description": "Signup needs a verification email nobody can send"}},
)
async def create_user(
    background_tasks: BackgroundTasks,
    user_in: UserSignup,
    db: DatabaseDep,
) -> Any:
    """Register a new user (public signup)."""
    system_config = await deps.get_system_settings(db)
    signup_enabled = system_config.allow_public_registration

    if not signup_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Signup is currently disabled.",
        )

    if system_config.enforce_email_verification and not system_config.email_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Registration is temporarily unavailable.",
        )

    new_user = User(
        email=user_in.email,
        username=user_in.username,
        hashed_password=security.get_password_hash(user_in.password),
        slack_username=user_in.slack_username,
        mattermost_username=user_in.mattermost_username,
        notification_preferences=user_in.notification_preferences,
        permissions=[],
        is_active=True,
        is_verified=False,
        auth_provider=AUTH_PROVIDER_LOCAL,
    )
    await UserRepository(db).create(new_user)

    send_verification_email(background_tasks, new_user.email, system_config)

    auth_signups_total.labels(status="success").inc()

    return new_user


@router.post("/logout", summary="Logout user", responses=RESP_AUTH)
async def logout(current_user: Annotated[User, Depends(deps.get_current_user)], db: DatabaseDep) -> LogoutResponse:
    """Logout the current user by bumping last_logout_at, which revokes every token issued before it."""
    await UserRepository(db).update(current_user.id, {"last_logout_at": datetime.now(timezone.utc)})
    return LogoutResponse(message="Successfully logged out")


@router.post(
    "/send-verification-email",
    summary="Send verification email",
    responses=RESP_AUTH_400_501,
)
async def request_verification_email(
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(deps.get_current_active_user)],
    system_config: Annotated[SystemSettings, Depends(deps.get_system_settings)],
) -> VerificationEmailResponse:
    """Send a new verification email to the current user."""
    if current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already verified",
        )

    require_email_configured(system_config)
    send_verification_email(background_tasks, current_user.email, system_config)

    return VerificationEmailResponse(message="Verification email sent")


@router.get(
    "/verify-email",
    summary="Verify email address",
    responses=RESP_400_404,
)
async def verify_email(token: str, db: DatabaseDep) -> EmailVerifyResponse:
    """Verify email address using the token sent via email."""
    email = security.verify_email_verification_token(token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )

    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_email(email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_MSG_USER_INACTIVE,
        )

    if user.get("is_verified"):
        return EmailVerifyResponse(message="Email already verified")

    await user_repo.update(user["_id"], {"is_verified": True})

    return EmailVerifyResponse(message="Email successfully verified")


@router.post(
    "/confirm-email-change",
    summary="Confirm a pending email change",
    responses=RESP_400,
)
async def confirm_email_change(token: Annotated[str, Body(embed=True)], db: DatabaseDep) -> EmailVerifyResponse:
    """Swap in the pending email the token was mailed to; the address is verified by the click."""
    change = security.verify_email_change_token(token)
    if not change:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired confirmation link")
    user_id, new_email = change

    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_id(user_id)
    # A newer request or an earlier confirmation replaced the pending address this link was mailed to.
    if not user or user.get("pending_email") != new_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This email change is no longer pending")

    await user_repo.update(user_id, {"email": new_email, "pending_email": None, "is_verified": True})

    return EmailVerifyResponse(message="Your email address has been changed")


@router.post(
    "/resend-verification",
    summary="Resend verification email (Public)",
    responses=RESP_501,
)
async def resend_verification_email_public(
    request: Request,
    background_tasks: BackgroundTasks,
    email: Annotated[str, Body(embed=True)],
    db: DatabaseDep,
    system_config: Annotated[SystemSettings, Depends(deps.get_system_settings)],
) -> VerificationEmailResponse:
    """Resend a verification email; public so unverified users can request a new token."""
    await _check_rate_limit(f"resend_verif:{_client_host(request)}", max_attempts=10, window_seconds=600)
    generic_response = VerificationEmailResponse(
        message="If an account with this email exists, a verification email has been sent."
    )

    require_email_configured(system_config)
    if not await _within_email_budget("resend_verif", email):
        return generic_response

    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_email(email)

    # Return a generic response regardless to prevent email enumeration.
    if user and user.get("is_active", True) and not user.get("is_verified"):
        send_verification_email(background_tasks, user["email"], system_config)

    return generic_response


_OIDC_CALLBACK_PATH = "/login/oidc/callback"
_OIDC_EXCHANGE_PATH = "/login/oidc/exchange"
_OIDC_STATE_COOKIE = "oidc_state"
_OIDC_HANDOFF_COOKIE = "oidc_handoff"
_SSO_COOKIE_FLAGS: dict[str, Any] = {"secure": True, "httponly": True, "samesite": "lax"}


class _OidcLoginError(Exception):
    """A failed SSO login; ``code`` is the metric status and the fixed error the login page maps to text."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@router.get(
    "/login/oidc/authorize",
    summary="Initiate OIDC login",
    description="Redirects the user to the configured OIDC provider for authentication.",
    responses=RESP_400_500,
)
async def login_oidc_authorize(request: Request, db: DatabaseDep) -> RedirectResponse:
    """Initiate OIDC login flow by redirecting to the identity provider."""
    system_config = await deps.get_system_settings(db)
    if not system_config.oidc_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OIDC is not enabled")

    if not system_config.oidc_client_id or not system_config.oidc_authorization_endpoint:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC is not properly configured",
        )

    state = secrets.token_urlsafe(32)
    if not await cache_service.set(f"oidc_state:{state}", True, OIDC_STATE_TTL_SECONDS):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service temporarily unavailable. Please try again.",
        )

    params = {
        "client_id": system_config.oidc_client_id,
        "response_type": "code",
        "scope": system_config.oidc_scopes,
        "redirect_uri": _resolve_oidc_redirect_uri(request),
        "state": state,
    }
    response = RedirectResponse(f"{system_config.oidc_authorization_endpoint}?{urlencode(params)}")
    response.set_cookie(
        _OIDC_STATE_COOKIE,
        state,
        max_age=OIDC_STATE_TTL_SECONDS,
        path=f"{settings.API_V1_STR}{_OIDC_CALLBACK_PATH}",
        **_SSO_COOKIE_FLAGS,
    )
    return response


async def _consume_oidc_state(request: Request, state: str | None) -> None:
    """Spend the state, which only the browser it was issued to can present."""
    cookie = request.cookies.get(_OIDC_STATE_COOKIE, "")
    if not (
        state
        and hmac.compare_digest(cookie.encode(), state.encode())
        and await cache_service.pop(f"oidc_state:{state}")
    ):
        raise _OidcLoginError("state_expired")


def _resolve_oidc_redirect_uri(request: Request) -> str:
    """Prefer FRONTEND_BASE_URL (external URL behind a reverse proxy), else request.url_for for local dev."""
    if settings.FRONTEND_BASE_URL and not settings.FRONTEND_BASE_URL.startswith("http://localhost"):
        return f"{settings.FRONTEND_BASE_URL}{settings.API_V1_STR}{_OIDC_CALLBACK_PATH}"
    return str(request.url_for("login_oidc_callback"))


async def _idp_json(call: Awaitable[httpx.Response], failure: str) -> dict[str, Any]:
    """The IdP's JSON object answer; raises ``failure`` for any other answer."""
    try:
        response = await call
    except httpx.RequestError as exc:
        logger.warning("OIDC provider unreachable at %s: %s", exc.request.url, exc)
        raise _OidcLoginError("provider_unreachable") from exc
    if response.status_code != 200:
        logger.error("OIDC %s (HTTP %s): %s", failure, response.status_code, response.text)
        raise _OidcLoginError(failure)
    try:
        body = response.json()
    except ValueError as exc:
        raise _OidcLoginError(failure) from exc
    if not isinstance(body, dict):
        raise _OidcLoginError(failure)
    return body


async def _generate_unique_oidc_username(user_repo: UserRepository, user_info: dict, email: str) -> str:
    """Generate a unique username for a new OIDC user."""
    preferred = str(user_info.get("preferred_username") or "").strip()
    base_username = preferred if preferred and "@" not in preferred else email.split("@")[0]
    username = base_username
    suffix = 0
    while await user_repo.exists_by_username(username):
        suffix += 1
        username = f"{base_username}{suffix}"
        if suffix > 100:  # Safety limit
            username = f"{email.split('@')[0]}_{secrets.token_hex(4)}"
            break
    return username


async def _create_oidc_user(
    user_repo: UserRepository, user_info: dict, email: str, system_config: SystemSettings
) -> dict:
    """Create a new OIDC user, return the persisted user dict."""
    username = await _generate_unique_oidc_username(user_repo, user_info, email)
    new_user = User(
        email=email,
        username=username,
        is_active=True,
        is_verified=True,  # Trusted provider
        auth_provider=system_config.oidc_provider_name,
        permissions=[],
    )

    await user_repo.create(new_user)
    return new_user.model_dump(by_alias=True)


def _validate_existing_oidc_user(user: dict, email: str) -> None:
    """Verify an existing user can use OIDC and is active."""
    if is_local_account(user.get("auth_provider")):
        logger.warning(f"OIDC login attempt blocked for local user: {email}")
        raise _OidcLoginError("local_user_blocked")
    if not user.get("is_active", True):
        raise _OidcLoginError("inactive_user")


async def _fetch_oidc_user_info(system_config: SystemSettings, code: str, redirect_uri: str) -> dict[str, Any]:
    if not system_config.oidc_token_endpoint or not system_config.oidc_userinfo_endpoint:
        raise _OidcLoginError("not_configured")
    token_data = {
        "client_id": system_config.oidc_client_id,
        "client_secret": system_config.oidc_client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    async with InstrumentedAsyncClient("OIDC Provider", timeout=OIDC_HTTP_TIMEOUT_SECONDS) as client:
        tokens = await _idp_json(client.post(system_config.oidc_token_endpoint, data=token_data), "token_error")
        access_token = tokens.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            logger.error("OIDC token answer carries no access_token: %s", tokens.get("error"))
            raise _OidcLoginError("token_error")
        return await _idp_json(
            client.get(system_config.oidc_userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"}),
            "userinfo_error",
        )


async def _oidc_login_user(
    request: Request, db: DatabaseDep, code: str | None, state: str | None, error: str | None
) -> dict:
    """The account an SSO callback signs in; raises _OidcLoginError with the reason otherwise."""
    system_config = await deps.get_system_settings(db)
    if not system_config.oidc_enabled:
        raise _OidcLoginError("not_configured")
    await _consume_oidc_state(request, state)
    if error or not code:
        raise _OidcLoginError("idp_error")

    user_info = await _fetch_oidc_user_info(system_config, code, _resolve_oidc_redirect_uri(request))
    email = user_info.get("email")
    if not email:
        raise _OidcLoginError("no_email")

    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_email(email)
    if user:
        _validate_existing_oidc_user(user, email)
        return user
    if not system_config.oidc_auto_provision:
        raise _OidcLoginError("not_provisioned")
    return await _create_oidc_user(user_repo, user_info, email, system_config)


@router.get(
    _OIDC_CALLBACK_PATH,
    summary="OIDC callback",
    description="Finishes the login the OIDC provider redirected back and sends the browser to the login page.",
)
async def login_oidc_callback(
    request: Request,
    db: DatabaseDep,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    """Leave the session for POST /login/oidc/exchange in a cookie, or send the browser a fixed error code."""
    landing = f"{settings.FRONTEND_BASE_URL}/login/callback"
    try:
        user = await _oidc_login_user(request, db, code, state, error)
        # OIDC users are exempt from 2FA enforcement; we trust the provider.
        access_token, refresh_token = security.create_token_pair(str(user["_id"]), list(user.get("permissions", [])))
        handoff = secrets.token_urlsafe(32)
        tokens = {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}
        if not await cache_service.set(f"oidc_handoff:{handoff}", tokens, OIDC_HANDOFF_TTL_SECONDS):
            raise _OidcLoginError("unavailable")
    except _OidcLoginError as exc:
        outcome, response = exc.code, RedirectResponse(f"{landing}#error={exc.code}")
    else:
        outcome, response = "success", RedirectResponse(landing)
        response.set_cookie(
            _OIDC_HANDOFF_COOKIE,
            handoff,
            max_age=OIDC_HANDOFF_TTL_SECONDS,
            path=f"{settings.API_V1_STR}{_OIDC_EXCHANGE_PATH}",
            **_SSO_COOKIE_FLAGS,
        )
    response.delete_cookie(_OIDC_STATE_COOKIE, path=f"{settings.API_V1_STR}{_OIDC_CALLBACK_PATH}", **_SSO_COOKIE_FLAGS)
    auth_oidc_logins_total.labels(status=outcome).inc()
    return response


@router.post(
    _OIDC_EXCHANGE_PATH,
    response_model=Token,
    summary="Collect the OIDC session",
    responses=RESP_400,
)
async def login_oidc_exchange(request: Request, response: Response) -> Any:
    """Hand this browser the session its finished OIDC callback left, once."""
    handoff = request.cookies.get(_OIDC_HANDOFF_COOKIE)
    tokens = await cache_service.pop(f"oidc_handoff:{handoff}") if handoff else None
    response.delete_cookie(
        _OIDC_HANDOFF_COOKIE, path=f"{settings.API_V1_STR}{_OIDC_EXCHANGE_PATH}", **_SSO_COOKIE_FLAGS
    )
    if not tokens:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No pending single sign-on")
    return tokens


@router.post(
    "/forgot-password",
    summary="Request password reset",
    responses=RESP_501,
)
async def forgot_password(
    request: Request,
    background_tasks: BackgroundTasks,
    email: Annotated[str, Body(embed=True)],
    db: DatabaseDep,
) -> ForgotPasswordResponse:
    """Request a password reset email; always returns success with a constant-time response to prevent email enumeration and timing attacks."""
    await _check_rate_limit(f"forgot_pw:{_client_host(request)}", max_attempts=3, window_seconds=600)
    import asyncio
    import time

    start_time = time.monotonic()

    generic_response = ForgotPasswordResponse(
        message="If an account with this email exists, a password reset email has been sent."
    )

    system_config = await deps.get_system_settings(db)
    require_email_configured(system_config)

    within_budget = await _within_email_budget("forgot_pw", email)
    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_email(email)

    if within_budget and user and user.get("is_active", True) and is_local_account(user.get("auth_provider")):
        send_password_reset_email(background_tasks, user, system_config)

    # Pad to a constant ~200ms so response time never reveals whether the email exists.
    elapsed = time.monotonic() - start_time
    target_duration = 0.2
    if elapsed < target_duration:
        await asyncio.sleep(target_duration - elapsed)

    return generic_response


@router.post(
    "/reset-password",
    summary="Reset password with token",
    responses=RESP_400_404,
)
async def reset_password(request: Request, reset_in: UserPasswordReset, db: DatabaseDep) -> PasswordResetResponse:
    """Reset password using the token from email; a reset voids that link and every other one issued before it."""
    await _check_rate_limit(f"reset_pw:{_client_host(request)}", max_attempts=5, window_seconds=600)
    verified = security.verify_password_reset_token(reset_in.token)
    if not verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_MSG_INVALID_RESET_TOKEN)
    email, fingerprint = verified

    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_email(email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    current_hash = user.get("hashed_password")
    if security.password_fingerprint(current_hash) != fingerprint:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_MSG_INVALID_RESET_TOKEN)

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_MSG_USER_INACTIVE,
        )

    if not is_local_account(user.get("auth_provider")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password reset not available for {user['auth_provider']} accounts. Please use your identity provider.",
        )

    # Guarded on the hash the link was checked against, so of two concurrent uses only one writes.
    if not await user_repo.update_raw(
        user["_id"],
        {
            "$set": {
                "hashed_password": security.get_password_hash(reset_in.new_password),
                "last_logout_at": datetime.now(timezone.utc),
            }
        },
        guard={"hashed_password": current_hash},
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_MSG_INVALID_RESET_TOKEN)

    auth_password_resets_total.labels(status="success").inc()

    return PasswordResetResponse(message="Password successfully reset")
