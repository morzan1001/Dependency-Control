"""JWKS fetch and key lookup, and OIDC JWT validation."""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

import httpx
import jwt
from pydantic import BaseModel, ValidationError

from app.core.cache import cache_service
from app.core.constants import JWKS_CACHE_TTL, JWKS_URI_CACHE_TTL
from app.core.http_utils import InstrumentedAsyncClient

T = TypeVar("T", bound=BaseModel)

logger = logging.getLogger(__name__)

# The kid that forces a refresh comes from an unverified header, so random kids must not hammer the IdP.
JWKS_FORCED_REFRESH_COOLDOWN_SECONDS = 60
# One deadline over every candidate, so an unreachable IdP holds a CI request for seconds, not minutes.
_JWKS_FETCH_TIMEOUT_SECONDS = 10.0
_JWKS_FETCH_FAILURE_TTL = 30


async def discover_jwks_uri(base_url: str, cache_key: str) -> str | None:
    """The ``jwks_uri`` of the issuer's discovery document; only a discovered URI is cached."""
    cached: str | None = await cache_service.get(cache_key)
    if cached:
        return cached
    try:
        async with InstrumentedAsyncClient("OIDC discovery", timeout=_JWKS_FETCH_TIMEOUT_SECONDS) as client:
            response = await client.get(f"{base_url}/.well-known/openid-configuration")
        document = response.json() if response.status_code == 200 else {}
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as e:
        logger.warning("OIDC discovery failed for %s: %s", base_url, e)
        return None
    jwks_uri = document.get("jwks_uri") if isinstance(document, dict) else None
    if not isinstance(jwks_uri, str) or not jwks_uri:
        return None
    await cache_service.set(cache_key, jwks_uri, ttl_seconds=JWKS_URI_CACHE_TTL)
    return jwks_uri


async def _jwks_from(client: InstrumentedAsyncClient, uri: str) -> dict[str, Any] | None:
    try:
        response = await client.get(uri)
        body = response.json() if response.status_code == 200 else None
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as e:
        logger.warning("JWKS fetch from %s failed: %s", uri, e)
        return None
    return body if isinstance(body, dict) and isinstance(body.get("keys"), list) else None


async def fetch_jwks(
    cache_key: str, candidate_uris: Callable[[], Awaitable[list[str]]], label: str
) -> dict[str, Any] | None:
    """Fetch the first key set a candidate serves and cache it; a failure is remembered briefly instead."""
    failure_key = f"{cache_key}:fetch_failed"
    if await cache_service.get(failure_key):
        return None
    try:
        async with (
            asyncio.timeout(_JWKS_FETCH_TIMEOUT_SECONDS),
            InstrumentedAsyncClient(f"{label} JWKS", timeout=_JWKS_FETCH_TIMEOUT_SECONDS) as client,
        ):
            for uri in await candidate_uris():
                if jwks := await _jwks_from(client, uri):
                    await cache_service.set(cache_key, jwks, ttl_seconds=JWKS_CACHE_TTL)
                    return jwks
    except TimeoutError:
        logger.error("%s JWKS fetch timed out after %ss", label, _JWKS_FETCH_TIMEOUT_SECONDS)
    else:
        logger.error("%s JWKS unavailable from every known endpoint", label)
    await cache_service.set(failure_key, True, ttl_seconds=_JWKS_FETCH_FAILURE_TTL)
    return None


def _key_with_kid(jwks: dict[str, Any] | None, kid: str) -> dict[str, Any] | None:
    keys: list[dict[str, Any]] = (jwks or {}).get("keys", [])
    return next((key for key in keys if key.get("kid") == kid), None)


async def find_jwks_key(
    kid: str,
    get_jwks: Callable[[], Awaitable[dict[str, Any] | None]],
    refresh_jwks: Callable[[], Awaitable[dict[str, Any] | None]],
    provider_name: str,
    issuer: str,
) -> dict[str, Any] | None:
    """Find a signing key by key ID, refetching the key set once per cooldown on a miss."""
    jwks = await get_jwks()
    if jwks is None:
        return None
    if matching_key := _key_with_kid(jwks, kid):
        return matching_key

    cooldown_key = f"jwks:forced_refresh_cooldown:{provider_name}:{issuer}"
    if await cache_service.get(cooldown_key):
        logger.warning("%s key %s unknown; forced JWKS refresh is cooling down", provider_name, kid)
        return None
    # Set before refreshing so concurrent unknown kids fail fast instead of piling on refetches.
    await cache_service.set(cooldown_key, time.time(), ttl_seconds=JWKS_FORCED_REFRESH_COOLDOWN_SECONDS)

    logger.info("%s key %s unknown, refreshing JWKS", provider_name, kid)
    matching_key = _key_with_kid(await refresh_jwks(), kid)
    if matching_key is None:
        logger.error("No %s key with kid %s after refresh", provider_name, kid)
    return matching_key


async def validate_oidc_token(
    token: str,
    get_jwks: Callable[[], Awaitable[dict[str, Any] | None]],
    refresh_jwks: Callable[[], Awaitable[dict[str, Any] | None]],
    issuer: str,
    audience: str | None,
    payload_model: type[T],
    provider_name: str,
) -> T | None:
    """Validate an OIDC JWT via JWKS into ``payload_model``; fails closed when no audience is configured."""
    if not audience:
        logger.error(
            "%s OIDC token rejected: no expected audience configured. Set 'oidc_audience' on the instance "
            "and request the CI token with a matching 'aud' claim.",
            provider_name,
        )
        return None

    try:
        kid = jwt.get_unverified_header(token).get("kid")
        if not kid:
            logger.warning("%s OIDC token has no 'kid' in its header", provider_name)
            return None

        key = await find_jwks_key(kid, get_jwks, refresh_jwks, provider_name, issuer)
        if not key:
            return None

        payload = jwt.decode(
            token,
            jwt.PyJWK(key, algorithm="RS256"),
            algorithms=["RS256"],
            issuer=issuer,
            audience=audience,
            # IdPs backdate nbf to absorb clock skew; a zero-leeway check on iat would undo that.
            options={"verify_iat": False},
        )
        return payload_model(**payload)
    except (jwt.PyJWTError, ValidationError) as e:
        logger.warning("%s OIDC token rejected: %s", provider_name, e)
        return None
