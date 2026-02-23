"""
Shared OIDC token validation utilities.

Extracts the common JWKS key-lookup + JWT decode logic used by both
GitHubService and GitLabService to avoid code duplication.
"""

import logging
from typing import Any, Callable, Awaitable, Dict, Optional, Type, TypeVar

from jose import jwt
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

logger = logging.getLogger(__name__)


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

    # Key not found - try refreshing cache (key rotation scenario)
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
        audience: Expected audience (or None to skip verification)
        payload_model: Pydantic model class to parse the payload into
        provider_name: Name for log messages

    Returns:
        Parsed payload model instance, or None if validation fails
    """
    try:
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        if not kid:
            logger.warning(f"{provider_name} OIDC Token missing 'kid' in header")
            return None

        key = await find_jwks_key(kid, get_jwks, invalidate_cache, provider_name)
        if not key:
            return None

        jwt_options = {"verify_aud": bool(audience)}

        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=issuer,
            audience=audience if audience else None,
            options=jwt_options,
        )
        return payload_model(**payload)

    except Exception as e:
        logger.error(f"{provider_name} OIDC Token validation error: {e}")
        return None
