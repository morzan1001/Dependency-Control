"""Shared JWKS key-lookup + JWT decode logic used by GitHubService and GitLabService."""

import logging
import time
from typing import Any, Callable, Awaitable, Dict, Optional, Type, TypeVar

from jose import jwt
from pydantic import BaseModel

from app.core.cache import cache_service

T = TypeVar("T", bound=BaseModel)

logger = logging.getLogger(__name__)

# Cooldown between forced JWKS cache invalidations per provider. The `kid` driving a
# forced refresh comes from an unverified header on an unauthenticated request, so this
# throttle stops an attacker looping random kids to bust the cache and hammer upstream.
JWKS_FORCED_REFRESH_COOLDOWN_SECONDS = 60


async def find_jwks_key(
    kid: str,
    get_jwks: Callable[[], Awaitable[Optional[Dict[str, Any]]]],
    invalidate_cache: Callable[[], Awaitable[None]],
    provider_name: str = "OIDC",
) -> Optional[Dict[str, Any]]:
    """Find a signing key in the JWKS by key ID, refreshing the cache once on a miss."""
    jwks = await get_jwks()

    if jwks:
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                matching_key: Dict[str, Any] = k
                return matching_key

    # Unknown kid: may be a legitimate rotation, but the kid is unauthenticated, so
    # rate-limit forced refreshes via a shared Redis cooldown; kids inside the window fail fast.
    cooldown_key = f"jwks:forced_refresh_cooldown:{provider_name}"
    if await cache_service.get(cooldown_key):
        logger.warning(
            "%s key %s not in cache; forced JWKS refresh skipped (cooldown active, "
            "%ss). Failing fast to avoid unauthenticated cache-busting.",
            provider_name,
            kid,
            JWKS_FORCED_REFRESH_COOLDOWN_SECONDS,
        )
        return None

    # Mark the cooldown BEFORE refreshing so concurrent / subsequent unknown-kid
    # requests within the window fail fast instead of piling on more refetches.
    await cache_service.set(
        cooldown_key,
        time.time(),
        ttl_seconds=JWKS_FORCED_REFRESH_COOLDOWN_SECONDS,
    )

    logger.info(f"{provider_name} key {kid} not in cache, refreshing JWKS...")
    await invalidate_cache()
    jwks = await get_jwks()

    if jwks:
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                matching_key = k
                return matching_key

    logger.error(f"No matching {provider_name} key found for kid: {kid} after refresh")
    return None


async def validate_oidc_token(
    token: str,
    get_jwks: Callable[[], Awaitable[Optional[Dict[str, Any]]]],
    invalidate_cache: Callable[[], Awaitable[None]],
    issuer: str,
    audience: Optional[str],
    payload_model: Type[T],
    provider_name: str = "OIDC",
) -> Optional[T]:
    """Validate an OIDC JWT via JWKS, returning the parsed ``payload_model`` or None.

    Audience verification is mandatory and fails closed: a missing ``audience`` rejects
    the token before decode, and the JWT is always decoded with ``verify_aud=True``.
    """
    try:
        # Fail closed: no expected audience must never accept a token.
        if not audience:
            logger.error(
                "%s OIDC token rejected: no expected audience configured for this instance. "
                "Set 'oidc_audience' on the instance and request the CI token with a matching "
                "'aud' claim. (fail-closed, Finding 7 / W1.1)",
                provider_name,
            )
            return None

        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        if not kid:
            logger.warning(f"{provider_name} OIDC Token missing 'kid' in header")
            return None

        key = await find_jwks_key(kid, get_jwks, invalidate_cache, provider_name)
        if not key:
            return None

        # require_aud=True is critical: python-jose only verifies an 'aud' claim that is
        # present, so without it a token with no 'aud' would slip through verify_aud.
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=issuer,
            audience=audience,
            options={"verify_aud": True, "require_aud": True},
        )
        return payload_model(**payload)

    except Exception as e:
        logger.exception("%s OIDC Token validation error: %s", provider_name, e)
        return None
