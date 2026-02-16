import logging
import re
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx
from jose import jwt

from app.core.http_utils import InstrumentedAsyncClient
from app.core.cache import cache_service
from app.core.constants import (
    GITHUB_JWKS_CACHE_TTL,
    GITHUB_JWKS_URI_CACHE_TTL,
)
from app.models.github_api import GitHubOIDCPayload
from app.models.github_instance import GitHubInstance

logger = logging.getLogger(__name__)

# Well-known JWKS endpoint for github.com
_GITHUB_COM_JWKS_URI = "https://token.actions.githubusercontent.com/.well-known/jwks"


_GITHUB_API_TIMEOUT = 10.0


class GitHubService:
    """
    GitHub service for OIDC token validation and API operations.

    Supports both github.com and GitHub Enterprise Server instances.
    """

    def __init__(self, github_instance: GitHubInstance):
        self.instance = github_instance
        self.base_url = github_instance.url.rstrip("/")
        self._cache_key_prefix = f"gh_instance:{github_instance.id}"

        # Derive API URL from github_url
        github_url = (github_instance.github_url or "").rstrip("/")
        if not github_url or "github.com" in github_url:
            self.api_url = "https://api.github.com"
        else:
            # GHES: https://{host}/api/v3
            self.api_url = f"{github_url}/api/v3"

    def _get_cache_key(self, suffix: str) -> str:
        """Generate cache key for this specific instance."""
        return f"github:{self._cache_key_prefix}:{suffix}"

    def _get_auth_headers(self) -> Dict[str, str]:
        if not self.instance.access_token:
            raise ValueError(f"No access token configured for GitHub instance '{self.instance.name}'")
        return {"Authorization": f"Bearer {self.instance.access_token}", "Accept": "application/vnd.github+json"}

    @asynccontextmanager
    async def _api_client(self) -> AsyncIterator[InstrumentedAsyncClient]:
        async with InstrumentedAsyncClient("GitHub API", timeout=_GITHUB_API_TIMEOUT) as client:
            yield client

    async def _api_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Optional[httpx.Response]:
        if not self.instance.access_token:
            return None

        try:
            async with self._api_client() as client:
                return await client.get(
                    f"{self.api_url}{endpoint}",
                    headers=self._get_auth_headers(),
                    params=params,
                )
        except Exception as e:
            logger.error(f"GitHub API GET {endpoint} failed: {e}")
            return None

    async def _api_get_paginated(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        max_pages: int = 10,
    ) -> List[Dict[str, Any]]:
        """Paginated GET using GitHub's Link header pagination."""
        if not self.instance.access_token:
            return []

        all_items: List[Dict[str, Any]] = []
        page = 1
        per_page = 100

        try:
            async with self._api_client() as client:
                while page <= max_pages:
                    request_params = {**(params or {}), "page": page, "per_page": per_page}
                    response = await client.get(
                        f"{self.api_url}{endpoint}",
                        headers=self._get_auth_headers(),
                        params=request_params,
                    )

                    if response.status_code != 200:
                        logger.error(f"GitHub API GET {endpoint} page {page} failed: {response.status_code}")
                        break

                    items = response.json()
                    if not items:
                        break

                    all_items.extend(items)

                    # Check Link header for next page
                    link_header = response.headers.get("link", "")
                    if 'rel="next"' not in link_header:
                        break

                    page += 1

        except Exception as e:
            logger.error(f"GitHub API paginated GET {endpoint} failed: {e}")

        return all_items

    async def list_branches(self, owner: str, repo: str) -> List[str]:
        """Fetches all branch names from a GitHub repository."""
        branches = await self._api_get_paginated(f"/repos/{owner}/{repo}/branches")
        return [b["name"] for b in branches]

    async def _get_jwks_uri(self) -> Optional[str]:
        """
        Fetches the JWKS URI from the OpenID Connect discovery document.
        For github.com, uses the well-known endpoint directly.
        For GHES, discovers via .well-known/openid-configuration.
        """
        cache_key = self._get_cache_key("jwks_uri")

        cached_uri = await cache_service.get(cache_key)
        if cached_uri:
            return cached_uri

        # Fast path for github.com
        if "token.actions.githubusercontent.com" in self.base_url:
            await cache_service.set(cache_key, _GITHUB_COM_JWKS_URI, ttl_seconds=GITHUB_JWKS_URI_CACHE_TTL)
            return _GITHUB_COM_JWKS_URI

        # GHES: Try OpenID discovery
        async with InstrumentedAsyncClient("GitHub OIDC", timeout=10.0) as client:
            try:
                response = await client.get(f"{self.base_url}/.well-known/openid-configuration")
                if response.status_code == 200:
                    config = response.json()
                    jwks_uri = config.get("jwks_uri")
                    if jwks_uri:
                        await cache_service.set(cache_key, jwks_uri, ttl_seconds=GITHUB_JWKS_URI_CACHE_TTL)
                        return jwks_uri
            except Exception as e:
                logger.warning(f"Error fetching GitHub OIDC discovery: {e}")

        # Fallback: try .well-known/jwks directly
        fallback_uri = f"{self.base_url}/.well-known/jwks"
        await cache_service.set(cache_key, fallback_uri, ttl_seconds=GITHUB_JWKS_URI_CACHE_TTL)
        return fallback_uri

    async def get_jwks(self) -> Optional[dict]:
        """
        Fetches and caches the JWKS from GitHub.
        Uses Redis cache for multi-pod compatibility in Kubernetes.
        """
        cache_key = self._get_cache_key("jwks")

        cached_jwks = await cache_service.get(cache_key)
        if cached_jwks:
            return cached_jwks

        async with InstrumentedAsyncClient("GitHub JWKS", timeout=10.0) as client:
            try:
                jwks_uri = await self._get_jwks_uri()

                if jwks_uri:
                    response = await client.get(jwks_uri)
                    if response.status_code == 200:
                        jwks = response.json()
                        await cache_service.set(cache_key, jwks, ttl_seconds=GITHUB_JWKS_CACHE_TTL)
                        return jwks

                logger.error("Failed to fetch GitHub JWKS")
            except Exception as e:
                logger.error(f"Error fetching GitHub JWKS: {e}")
        return {}

    async def _invalidate_jwks_cache(self) -> None:
        """Invalidate the JWKS cache to force a refresh on next request."""
        cache_key = self._get_cache_key("jwks")
        await cache_service.delete(cache_key)

    async def validate_oidc_token(self, token: str) -> Optional[GitHubOIDCPayload]:
        """
        Validates a GitHub Actions OIDC token (JWT).

        Handles key rotation by refreshing JWKS cache if key is not found.
        """
        try:
            # 1. Get Key ID from Header
            headers = jwt.get_unverified_header(token)
            kid = headers.get("kid")
            if not kid:
                logger.warning("GitHub OIDC Token missing 'kid' in header")
                return None

            # 2. Fetch JWKS
            jwks = await self.get_jwks()

            # 3. Find Key
            key = None
            for k in jwks.get("keys", []):
                if k.get("kid") == kid:
                    key = k
                    break

            # 4. If key not found, try refreshing cache (key rotation scenario)
            if not key:
                logger.info(f"GitHub key {kid} not in cache, refreshing JWKS...")
                await self._invalidate_jwks_cache()
                jwks = await self.get_jwks()

                for k in jwks.get("keys", []):
                    if k.get("kid") == kid:
                        key = k
                        break

            if not key:
                logger.error(f"No matching GitHub key found for kid: {kid} after refresh")
                return None

            # 5. Verify JWT
            jwt_options = {}
            if self.instance.oidc_audience:
                jwt_options["verify_aud"] = True
            else:
                jwt_options["verify_aud"] = False

            payload = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self.base_url,
                audience=(self.instance.oidc_audience if self.instance.oidc_audience else None),
                options=jwt_options,
            )
            return GitHubOIDCPayload(**payload)
        except Exception as e:
            logger.error(f"GitHub OIDC Token validation error: {e}")
            return None
