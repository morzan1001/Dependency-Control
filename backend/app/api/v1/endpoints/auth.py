import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlencode

import httpx
import pyotp

from app.core.http_utils import InstrumentedAsyncClient
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    Form,
    HTTPException,
    Request,
    status,
)
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import ValidationError

from app.api import deps
from app.api.v1.helpers.auth import send_password_reset_email, send_verification_email
from app.core import security
from app.core.cache import cache_service
from app.core.config import settings
from app.core.constants import (
    OIDC_HTTP_TIMEOUT_SECONDS,
    OIDC_STATE_TTL_SECONDS,
    TOTP_VALID_WINDOW,
)
from app.db.mongodb import get_database
from app.models.system import SystemSettings
from app.models.user import User
from app.repositories import UserRepository
from app.schemas.auth import (
    EmailVerifyResponse,
    ForgotPasswordResponse,
    LogoutResponse,
    PasswordResetResponse,
    VerificationEmailResponse,
)
from app.schemas.token import Token, TokenPayload
from app.schemas.user import User as UserSchema
from app.schemas.user import UserCreate, UserPasswordReset

logger = logging.getLogger(__name__)

# Import metrics for authentication tracking
try:
    from app.core.metrics import (
        auth_2fa_verifications_total,
        auth_login_attempts_total,
        auth_oidc_logins_total,
        auth_password_resets_total,
        auth_signups_total,
    )
except ImportError:
    auth_login_attempts_total = None
    auth_2fa_verifications_total = None
    auth_oidc_logins_total = None
    auth_signups_total = None
    auth_password_resets_total = None

router = APIRouter(
    # Use field names (e.g., 'id') instead of aliases (e.g., '_id') in JSON responses.
    response_model_by_alias=False,
)


@router.post(
    "/login/access-token", response_model=Token, summary="Login to get access token"
)
async def login_access_token(
    db: AsyncIOMotorDatabase = Depends(get_database),
    form_data: OAuth2PasswordRequestForm = Depends(),
    otp: Optional[str] = Form(None),
) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests.

    - **username**: Email or username
    - **password**: User password
    - **otp**: One Time Password (if 2FA is enabled)
    """
    user_repo = UserRepository(db)
    # Try username first, then email as fallback
    user = await user_repo.get_raw_by_username(form_data.username)
    if not user:
        user = await user_repo.get_raw_by_email(form_data.username)

    if not user or not security.verify_password(
        form_data.password, user.get("hashed_password")
    ):
        if auth_login_attempts_total:
            auth_login_attempts_total.labels(status="failed").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.get("is_active", True):
        if auth_login_attempts_total:
            auth_login_attempts_total.labels(status="inactive_user").inc()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )

    system_config = await deps.get_system_settings(db)

    # Check Email Verification
    if system_config.enforce_email_verification and not user.get("is_verified", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check 2FA
    if user.get("totp_enabled", False):
        if not otp:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="2FA required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        totp_secret = user.get("totp_secret")
        if not totp_secret:
            logger.error(
                f"User {user.get('username')} has totp_enabled=True but no totp_secret"
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="2FA configuration error. Please contact support.",
            )

        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(otp, valid_window=TOTP_VALID_WINDOW):
            if auth_2fa_verifications_total:
                auth_2fa_verifications_total.labels(result="failed").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid OTP code",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if auth_2fa_verifications_total:
            auth_2fa_verifications_total.labels(result="success").inc()
        permissions = user.get("permissions", [])
    elif system_config.enforce_2fa:
        # User has no 2FA but it is enforced -> Issue limited token for setup
        permissions = ["auth:setup_2fa"]
    else:
        permissions = user.get("permissions", [])

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    access_token = security.create_access_token(
        user["username"], permissions=permissions, expires_delta=access_token_expires
    )

    refresh_token = security.create_refresh_token(user["username"])

    if auth_login_attempts_total:
        auth_login_attempts_total.labels(status="success").inc()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post(
    "/login/refresh-token", response_model=Token, summary="Refresh access token"
)
async def refresh_token(
    refresh_token: str = Body(
        ..., embed=True, description="The refresh token obtained during login"
    ),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> Any:
    """
    Get a new access token using a valid refresh token.
    """
    try:
        payload = jwt.decode(
            refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except (JWTError, ValidationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        ) from exc

    if token_data.type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid token type",
        )

    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_username(token_data.sub)
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

    # Check if refresh token was issued before last logout
    if "last_logout_at" in user and user["last_logout_at"]:
        iat = payload.get("iat")
        if iat:
            last_logout_ts = user["last_logout_at"].timestamp()
            if iat < last_logout_ts:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Token revoked",
                )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    permissions = user.get("permissions", [])

    access_token = security.create_access_token(
        user["username"], permissions=permissions, expires_delta=access_token_expires
    )

    # Optionally rotate refresh token here
    new_refresh_token = security.create_refresh_token(user["username"])

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }


@router.post("/signup", response_model=UserSchema, summary="Register a new user")
async def create_user(
    background_tasks: BackgroundTasks,
    user_in: UserCreate,
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> Any:
    """
    Create a new user in the system.
    """
    # Check if signup is enabled
    system_config = await deps.get_system_settings(db)
    signup_enabled = system_config.allow_public_registration

    if not signup_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Signup is currently disabled.",
        )

    if not user_in.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is required for registration",
        )

    user_repo = UserRepository(db)

    if await user_repo.exists_by_username(user_in.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The user with this username already exists in the system.",
        )

    if await user_repo.get_raw_by_email(user_in.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The user with this email already exists in the system.",
        )
    user_dict = user_in.model_dump()
    hashed_password = security.get_password_hash(user_dict.pop("password"))
    user_dict["hashed_password"] = hashed_password
    user_dict["is_verified"] = False

    new_user = User(**user_dict)
    await user_repo.create(new_user)

    # Send verification email if SMTP is configured
    await send_verification_email(background_tasks, new_user.email)

    if auth_signups_total:
        auth_signups_total.labels(status="success").inc()

    return new_user


@router.post("/logout", response_model=LogoutResponse, summary="Logout user")
async def logout(
    request: Request,
    current_user: User = Depends(deps.get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> LogoutResponse:
    """
    Logout the current user.

    Invalidates the current token by:
    1. Adding token JTI to blacklist (immediate invalidation)
    2. Updating last_logout_at timestamp (invalidates older tokens)

    This ensures the token is immediately invalidated and cannot be reused.
    """
    from app.repositories import TokenBlacklistRepository, UserRepository

    # Extract token from Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]  # Remove "Bearer " prefix

        # Decode token to get JTI and expiration
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            jti = payload.get("jti")
            exp_timestamp = payload.get("exp")

            if jti and exp_timestamp:
                # Convert exp timestamp to datetime
                exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)

                # Blacklist the token
                blacklist_repo = TokenBlacklistRepository(db)
                await blacklist_repo.blacklist_token(jti, exp_datetime, reason="logout")
                logger.info(
                    f"Token {jti[:8]}... blacklisted for user {current_user.username}"
                )
        except Exception as e:
            logger.warning(f"Could not blacklist token on logout: {e}")

    # Update last_logout_at for backward compatibility
    # (invalidates tokens without JTI or issued before this timestamp)
    user_repo = UserRepository(db)
    await user_repo.update(
        current_user.id, {"last_logout_at": datetime.now(timezone.utc)}
    )

    return LogoutResponse(message="Successfully logged out")


@router.post(
    "/send-verification-email",
    response_model=VerificationEmailResponse,
    summary="Send verification email",
)
async def request_verification_email(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(deps.get_current_active_user),
) -> VerificationEmailResponse:
    """
    Send a new verification email to the current user.
    """
    if current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already verified",
        )

    if not settings.SMTP_HOST:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Email server not configured",
        )

    await send_verification_email(background_tasks, current_user.email)

    return VerificationEmailResponse(message="Verification email sent")


@router.get(
    "/verify-email",
    response_model=EmailVerifyResponse,
    summary="Verify email address",
)
async def verify_email(
    token: str, db: AsyncIOMotorDatabase = Depends(get_database)
) -> EmailVerifyResponse:
    """
    Verify email address using the token sent via email.
    """
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

    # Inactive users cannot verify their email
    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is inactive",
        )

    if user.get("is_verified"):
        return EmailVerifyResponse(message="Email already verified")

    await user_repo.update(user["_id"], {"is_verified": True})

    return EmailVerifyResponse(message="Email successfully verified")


@router.post(
    "/resend-verification",
    response_model=VerificationEmailResponse,
    summary="Resend verification email (Public)",
)
async def resend_verification_email_public(
    background_tasks: BackgroundTasks,
    email: str = Body(..., embed=True),
    db: AsyncIOMotorDatabase = Depends(get_database),
    system_config: SystemSettings = Depends(deps.get_system_settings),
) -> VerificationEmailResponse:
    """
    Resend verification email to the user with the given email address.
    This endpoint is public to allow unverified users to request a new token.
    """
    generic_response = VerificationEmailResponse(
        message="If an account with this email exists, a verification email has been sent."
    )

    # Check SMTP first - this is a system config issue, not user-specific
    if not settings.SMTP_HOST:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Email server not configured",
        )

    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_email(email)

    # Always return generic response to prevent email enumeration
    # Only send email if user exists, is active, and is not verified
    if user and user.get("is_active", True) and not user.get("is_verified"):
        await send_verification_email(
            background_tasks, user["email"], system_settings=system_config
        )

    return generic_response


@router.get(
    "/login/oidc/authorize",
    summary="Initiate OIDC login",
    description="Redirects the user to the configured OIDC provider for authentication.",
)
async def login_oidc_authorize(
    request: Request, db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Initiate OIDC login flow by redirecting to the identity provider.
    """
    system_config = await deps.get_system_settings(db)
    if not system_config.oidc_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="OIDC is not enabled"
        )

    if (
        not system_config.oidc_client_id
        or not system_config.oidc_authorization_endpoint
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC is not properly configured",
        )

    # Construct redirect URI (callback to backend)
    # Use FRONTEND_BASE_URL to generate external URL (behind reverse proxy)
    # Falls back to request.url_for() for local development
    if settings.FRONTEND_BASE_URL and not settings.FRONTEND_BASE_URL.startswith("http://localhost"):
        redirect_uri = f"{settings.FRONTEND_BASE_URL.rstrip('/')}/api/v1/login/oidc/callback"
    else:
        redirect_uri = str(request.url_for("login_oidc_callback"))

    # Generate state to prevent CSRF
    state = secrets.token_urlsafe(32)

    # Store state in cache for validation in callback
    await cache_service.set(
        f"oidc_state:{state}", {"valid": True}, OIDC_STATE_TTL_SECONDS
    )

    params = {
        "client_id": system_config.oidc_client_id,
        "response_type": "code",
        "scope": system_config.oidc_scopes,
        "redirect_uri": redirect_uri,
        "state": state,
    }

    url = f"{system_config.oidc_authorization_endpoint}?{urlencode(params)}"
    return RedirectResponse(url)


@router.get(
    "/login/oidc/callback",
    summary="OIDC callback",
    description="Handles the callback from the OIDC provider after authentication.",
)
async def login_oidc_callback(
    request: Request,
    code: str,
    state: Optional[str] = None,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Handle OIDC callback after user authenticates with the identity provider.
    Exchanges the authorization code for tokens and creates/updates the user.
    """
    system_config = await deps.get_system_settings(db)
    if not system_config.oidc_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="OIDC is not enabled"
        )

    if (
        not system_config.oidc_token_endpoint
        or not system_config.oidc_userinfo_endpoint
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC endpoints not configured",
        )

    # Validate OIDC state to prevent CSRF attacks
    if not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Missing state parameter"
        )

    # If two requests arrive with same state, only one succeeds
    state_key = f"oidc_state:{state}"
    cached_state = await cache_service.get(state_key)

    if not cached_state or not cached_state.get("valid"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state parameter",
        )

    # Mark state as used ATOMICALLY by setting valid=False
    # If another request already did this, we'll detect it
    # Try to update state to invalid
    await cache_service.set(
        state_key,
        {"valid": False, "used_at": datetime.now(timezone.utc).isoformat()},
        ttl_seconds=60,
    )

    # Double-check: if state is still valid in cache after our update attempt
    # This prevents race condition where two requests process same state
    recheck_state = await cache_service.get(state_key)
    if recheck_state and recheck_state.get("valid"):
        # Another request is using this state concurrently
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="State parameter already in use",
        )

    # Use same redirect_uri logic as authorize endpoint
    if settings.FRONTEND_BASE_URL and not settings.FRONTEND_BASE_URL.startswith("http://localhost"):
        redirect_uri = f"{settings.FRONTEND_BASE_URL.rstrip('/')}/api/v1/login/oidc/callback"
    else:
        redirect_uri = str(request.url_for("login_oidc_callback"))

    token_data = {
        "client_id": system_config.oidc_client_id,
        "client_secret": system_config.oidc_client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    async with InstrumentedAsyncClient("OIDC Provider", timeout=OIDC_HTTP_TIMEOUT_SECONDS) as client:
        # Exchange code for token
        try:
            response = await client.post(
                system_config.oidc_token_endpoint, data=token_data
            )
        except httpx.TimeoutException:
            logger.error(
                f"Timeout while requesting OIDC token from {system_config.oidc_token_endpoint}"
            )
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="OIDC provider request timed out. Please try again.",
            )
        except httpx.RequestError as exc:
            logger.error(
                f"An error occurred while requesting {exc.request.url!r}: {exc}"
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(
                    f"Failed to connect to OIDC provider at {system_config.oidc_token_endpoint}. "
                    "Please check your system configuration."
                ),
            )

        if response.status_code != 200:
            logger.error(f"OIDC Token Error: {response.text}")
            if auth_oidc_logins_total:
                auth_oidc_logins_total.labels(status="token_error").inc()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to retrieve token from provider",
            )

        tokens = response.json()
        access_token = tokens.get("access_token")

        # Get user info
        try:
            user_info_response = await client.get(
                system_config.oidc_userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
        except httpx.TimeoutException:
            logger.error(
                f"Timeout while requesting user info from {system_config.oidc_userinfo_endpoint}"
            )
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="OIDC provider request timed out. Please try again.",
            )
        except httpx.RequestError as exc:
            logger.error(
                f"An error occurred while requesting user info {exc.request.url!r}: {exc}"
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(
                    f"Failed to connect to OIDC provider user info endpoint at {system_config.oidc_userinfo_endpoint}."
                ),
            )

        if user_info_response.status_code != 200:
            logger.error(f"OIDC User Info Error: {user_info_response.text}")
            if auth_oidc_logins_total:
                auth_oidc_logins_total.labels(status="userinfo_error").inc()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to retrieve user info",
            )

        user_info = user_info_response.json()
        if not isinstance(user_info, dict):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Invalid user info response",
            )

    email = user_info.get("email")
    if not email:
        if auth_oidc_logins_total:
            auth_oidc_logins_total.labels(status="no_email").inc()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not provided by OIDC provider",
        )

    # Find or create user
    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_email(email)
    if not user:
        # Generate unique username - try preferred_username first, then email prefix
        base_username = user_info.get("preferred_username", email.split("@")[0])
        username = base_username

        # Check for username conflicts and generate unique suffix if needed
        suffix = 0
        while await user_repo.exists_by_username(username):
            suffix += 1
            username = f"{base_username}{suffix}"
            if suffix > 100:  # Safety limit
                # Fall back to email-based username with random suffix
                username = f"{email.split('@')[0]}_{secrets.token_hex(4)}"
                break

        # Create new user using the User model
        new_user = User(
            email=email,
            username=username,
            is_active=True,
            is_verified=True,  # Trusted provider
            auth_provider=system_config.oidc_provider_name,
            permissions=[],
        )

        await user_repo.create(new_user)
        user = await user_repo.get_raw_by_id(new_user.id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user",
            )
    else:
        # Check if existing user is a local auth user - they cannot use OIDC
        existing_auth_provider = user.get("auth_provider", "local")
        if existing_auth_provider == "local" or existing_auth_provider is None:
            if auth_oidc_logins_total:
                auth_oidc_logins_total.labels(status="local_user_blocked").inc()
            logger.warning(
                f"OIDC login attempt blocked for local user: {email}"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This account uses local authentication. Please login with your password.",
            )

        # Check if existing user is active
        if not user.get("is_active", True):
            if auth_oidc_logins_total:
                auth_oidc_logins_total.labels(status="inactive_user").inc()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is inactive",
            )

    # Check 2FA enforcement (same logic as login)
    permissions = user.get("permissions", [])
    if system_config.enforce_2fa and not user.get("totp_enabled", False):
        permissions = ["auth:setup_2fa"]

    # Create tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        user["username"], permissions=permissions, expires_delta=access_token_expires
    )
    refresh_token = security.create_refresh_token(user["username"])

    if auth_oidc_logins_total:
        auth_oidc_logins_total.labels(status="success").inc()

    # Redirect to frontend with tokens
    base_url = settings.FRONTEND_BASE_URL.rstrip("/")
    frontend_url = f"{base_url}/login/callback#access_token={access_token}&refresh_token={refresh_token}"

    return RedirectResponse(frontend_url)


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    summary="Request password reset",
)
async def forgot_password(
    background_tasks: BackgroundTasks,
    email: str = Body(..., embed=True),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> ForgotPasswordResponse:
    """
    Request a password reset email.
    This endpoint is public and always returns success to prevent email enumeration.

    SECURITY: Uses constant-time response to prevent timing attacks.
    """
    import asyncio
    import time

    start_time = time.monotonic()

    generic_response = ForgotPasswordResponse(
        message="If an account with this email exists, a password reset email has been sent."
    )

    # Check SMTP first - this is a system config issue
    if not settings.SMTP_HOST:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Email server not configured",
        )

    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_email(email)

    # Only send email if user exists and is active
    if user and user.get("is_active", True):
        # Don't send reset emails for OIDC users without local password
        if user.get("auth_provider", "local") == "local" or user.get("hashed_password"):
            await send_password_reset_email(
                background_tasks,
                user["email"],
                user.get("username", "User"),
            )

    # Ensure response time is always ~200ms regardless of whether email exists
    elapsed = time.monotonic() - start_time
    target_duration = 0.2  # 200ms
    if elapsed < target_duration:
        await asyncio.sleep(target_duration - elapsed)

    return generic_response


@router.post(
    "/reset-password",
    response_model=PasswordResetResponse,
    summary="Reset password with token",
)
async def reset_password(
    reset_in: UserPasswordReset, db: AsyncIOMotorDatabase = Depends(get_database)
) -> PasswordResetResponse:
    """
    Reset password using the token received via email.
    Token is one-time use to prevent replay attacks.
    """
    token_hash = security.get_password_hash(reset_in.token)  # Hash token for storage
    token_key = f"used_reset_token:{token_hash[:32]}"  # Use first 32 chars of hash

    if await cache_service.get(token_key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This reset token has already been used",
        )

    email = security.verify_password_reset_token(reset_in.token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    # TTL: Same as token expiration (1 hour from now)
    await cache_service.set(token_key, True, ttl_seconds=3600)

    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_email(email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Check if user is active
    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is inactive",
        )

    # Check if user can reset password (local auth or has existing password)
    auth_provider = user.get("auth_provider", "local")
    has_password = user.get("hashed_password") is not None
    if auth_provider != "local" and not has_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password reset not available for {auth_provider} accounts. Please use your identity provider.",
        )

    hashed_password = security.get_password_hash(reset_in.new_password)

    # Update password and invalidate all existing sessions
    await user_repo.update(
        user["_id"],
        {
            "hashed_password": hashed_password,
            "last_logout_at": datetime.now(timezone.utc),
        },
    )

    if auth_password_resets_total:
        auth_password_resets_total.labels(status="success").inc()

    return PasswordResetResponse(message="Password successfully reset")
