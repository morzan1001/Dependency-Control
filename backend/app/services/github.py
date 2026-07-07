import logging
import urllib.parse
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from app.core.http_utils import InstrumentedAsyncClient
from app.core.cache import cache_service
from app.core.constants import (
    GITHUB_JWKS_CACHE_TTL,
    GITHUB_JWKS_URI_CACHE_TTL,
)
from app.models.github_api import GitHubOIDCPayload
from app.models.github_instance import GitHubInstance
from app.services.oidc_utils import validate_oidc_token as _validate_oidc_token

logger = logging.getLogger(__name__)

_GITHUB_COM_JWKS_URI = "https://token.actions.githubusercontent.com/.well-known/jwks"


_GITHUB_API_TIMEOUT = 10.0


class GitHubService:
    """OIDC token validation and API operations for github.com and GHES instances."""

    def __init__(self, github_instance: GitHubInstance):
        self.instance = github_instance
        self.base_url = github_instance.url.rstrip("/")
        self._cache_key_prefix = f"gh_instance:{github_instance.id}"

        # Derive API URL from github_url. Match on the parsed host (not a
        # substring): hostnames like "github.company.com" or
        # "github.com.mycorp.internal" contain "github.com" but are GHES
        # instances that must NOT have their PAT sent to public api.github.com.
        github_url = (github_instance.github_url or "").rstrip("/")
        host = (urllib.parse.urlsplit(github_url).hostname or "").lower()
        if not github_url or host in ("github.com", "www.github.com"):
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
            logger.exception("GitHub API GET %s failed: %s", endpoint, e)
            return None

    async def _api_get_paginated(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        max_pages: int = 10,
    ) -> Optional[List[Dict[str, Any]]]:
        """Paginated GET via GitHub's Link header; returns all items or None on failure."""
        if not self.instance.access_token:
            return None

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
                        logger.error(f"GitHub API GET {endpoint} failed: {response.status_code}")
                        return None

                    items = response.json()
                    if not items:
                        break

                    all_items.extend(items)

                    link_header = response.headers.get("link", "")
                    if 'rel="next"' not in link_header:
                        break

                    page += 1

        except Exception as e:
            logger.exception("GitHub API paginated GET %s failed: %s", endpoint, e)
            return None

        return all_items

    async def list_branches(self, owner: str, repo: str) -> Optional[List[str]]:
        """Fetches all branch names from a GitHub repository. Returns None on API failure."""
        branches = await self._api_get_paginated(f"/repos/{owner}/{repo}/branches")
        if branches is None:
            return None
        return [b["name"] for b in branches]

    async def _get_jwks_uri(self) -> Optional[str]:
        """Resolve the JWKS URI: well-known endpoint for github.com, OIDC discovery for GHES."""
        cache_key = self._get_cache_key("jwks_uri")

        cached_uri = await cache_service.get(cache_key)
        if cached_uri:
            result: str = cached_uri
            return result

        if "token.actions.githubusercontent.com" in self.base_url:
            await cache_service.set(cache_key, _GITHUB_COM_JWKS_URI, ttl_seconds=GITHUB_JWKS_URI_CACHE_TTL)
            return _GITHUB_COM_JWKS_URI

        async with InstrumentedAsyncClient("GitHub OIDC", timeout=10.0) as client:
            try:
                response = await client.get(f"{self.base_url}/.well-known/openid-configuration")
                if response.status_code == 200:
                    config = response.json()
                    jwks_uri: str | None = config.get("jwks_uri")
                    if jwks_uri:
                        await cache_service.set(cache_key, jwks_uri, ttl_seconds=GITHUB_JWKS_URI_CACHE_TTL)
                        return jwks_uri
            except Exception as e:
                logger.warning(f"Error fetching GitHub OIDC discovery: {e}")

        fallback_uri = f"{self.base_url}/.well-known/jwks"
        await cache_service.set(cache_key, fallback_uri, ttl_seconds=GITHUB_JWKS_URI_CACHE_TTL)
        return fallback_uri

    async def get_jwks(self) -> Optional[dict]:
        """Fetch and Redis-cache the JWKS from GitHub."""
        cache_key = self._get_cache_key("jwks")

        cached_jwks = await cache_service.get(cache_key)
        if cached_jwks:
            result_jwks: dict[Any, Any] = cached_jwks
            return result_jwks

        async with InstrumentedAsyncClient("GitHub JWKS", timeout=10.0) as client:
            try:
                jwks_uri = await self._get_jwks_uri()

                if jwks_uri:
                    response = await client.get(jwks_uri)
                    if response.status_code == 200:
                        jwks: dict[Any, Any] = response.json()
                        await cache_service.set(cache_key, jwks, ttl_seconds=GITHUB_JWKS_CACHE_TTL)
                        return jwks

                logger.error("Failed to fetch GitHub JWKS")
            except Exception as e:
                logger.exception("Error fetching GitHub JWKS: %s", e)
        return {}

    async def _invalidate_jwks_cache(self) -> None:
        """Invalidate the JWKS cache to force a refresh on next request."""
        cache_key = self._get_cache_key("jwks")
        await cache_service.delete(cache_key)

    async def validate_oidc_token(self, token: str) -> Optional[GitHubOIDCPayload]:
        """Validate a GitHub Actions OIDC JWT, refreshing JWKS on key rotation."""
        return await _validate_oidc_token(
            token=token,
            get_jwks=self.get_jwks,
            invalidate_cache=self._invalidate_jwks_cache,
            issuer=self.base_url,
            # `or None` normalizes "" -> None so unconfigured instances fail the audience check closed.
            audience=self.instance.oidc_audience or None,
            payload_model=GitHubOIDCPayload,
            provider_name="GitHub",
        )
