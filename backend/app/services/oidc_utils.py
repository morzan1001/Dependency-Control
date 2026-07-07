"""
Shared OIDC token validation utilities.

Extracts the common JWKS key-lookup + JWT decode logic used by both
GitHubService and GitLabService to avoid code duplication.
"""

import logging
import time
from typing import Any, Callable, Awaitable, Dict, Optional, Type, TypeVar

from jose import jwt
from pydantic import BaseModel

from app.core.cache import cache_service

T = TypeVar("T", bound=BaseModel)

logger = logging.getLogger(__name__)

# Cooldown (seconds) between *forced* JWKS cache invalidations for a given
# provider. JWKS signing-key rotation is rare, so once we have force-refreshed
# the cache we refuse to do so again for this window. The `kid` that drives a
# forced refresh comes from the UNVERIFIED header of an unauthenticated ingest
# request, so without this throttle an attacker can loop requests bearing random
# `kid` values to repeatedly bust the shared Redis JWKS cache and hammer the
# upstream (GitLab/GitHub) JWKS endpoint into rate-limiting — a DoS that also
# makes legitimate CI token validation fail intermittently.
JWKS_FORCED_REFRESH_COOLDOWN_SECONDS = 60


async def find_jwks_key(
    kid: str,
    get_jwks: Callable[[], Awaitable[Optional[Dict[str, Any]]]],
    invalidate_cache: Callable[[], Awaitable[None]],
    provider_name: str = "OIDC",
) -> Optional[Dict[str, Any]]:
    """
    Find a signing key in the JWKS by key ID, with automatic cache refresh
    for key rotation scenarios.

    Args:
        kid: Key ID from the JWT header
        get_jwks: Async function that returns the JWKS dict
        invalidate_cache: Async function that invalidates the JWKS cache
        provider_name: Name for log messages (e.g. "GitHub", "GitLab")

    Returns:
        The matching key dict, or None if not found
    """
    jwks = await get_jwks()

    if jwks:
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                matching_key: Dict[str, Any] = k
                return matching_key

    # Key not found in the cached JWKS. This *may* be a legitimate key rotation,
    # but the kid comes from the unverified JWT header of an unauthenticated
    # request, so we must not let an unknown kid force an unbounded number of
    # cache invalidations + upstream refetches. Rate-limit the forced refresh
    # across all pods via a shared Redis cooldown key; unknown kids that arrive
    # inside the cooldown fail fast without touching the cache or upstream.
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

    # Try refreshing cache (key rotation scenario)
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
    """
    Validate an OIDC JWT token using JWKS.

    Args:
        token: The raw JWT token string
        get_jwks: Async function that returns the JWKS dict
        invalidate_cache: Async function that invalidates the JWKS cache
        issuer: Expected token issuer
        audience: Expected audience. SECURITY: this is hard-required. If it is
            unset (None / empty), the token is rejected (fail closed) — see note
            below.
        payload_model: Pydantic model class to parse the payload into
        provider_name: Name for log messages

    Returns:
        Parsed payload model instance, or None if validation fails

    SECURITY (Finding 7 / W1.1) — fail-closed audience verification:
        OIDC audience verification is mandatory and fails closed. If the
        instance has no resolvable expected audience we REJECT the token up
        front (before any decode), and the JWT is always decoded with
        ``verify_aud=True``. Previously an instance configured WITHOUT an
        ``oidc_audience`` accepted ANY validly-signed token from its issuer,
        enabling cross-tenant ingest/tamper.

        BREAKING CHANGE: an instance without an ``oidc_audience`` configured
        will now return 403 on ingest until an audience is set. CI pipelines
        must request the OIDC token with a matching audience, e.g. GitLab:
            id_tokens:
              ID_TOKEN:
                aud: <the instance's oidc_audience>
        and GitHub Actions: ``with: { audience: <oidc_audience> }`` on the
        token request.
    """
    try:
        # Fail closed: an instance with no expected audience must NEVER accept a
        # token, regardless of how valid its signature is.
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

        # Audience verification is always enforced (never optional).
        # require_aud=True is critical: python-jose only *verifies* an 'aud'
        # claim that is present, so without require_aud a token with NO 'aud'
        # claim would slip through verify_aud. Requiring it closes that gap.
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
