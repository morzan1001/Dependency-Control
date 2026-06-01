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
