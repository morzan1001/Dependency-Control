import asyncio
import logging
from typing import Dict, List, Optional

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import GHSA_API_URL
from app.schemas.enrichment import GHSAData

logger = logging.getLogger(__name__)


class GHSAProvider:
    """Provider for GitHub Security Advisory (GHSA) data."""

    def __init__(self):
        self._github_token: Optional[str] = None

    def set_token(self, token: Optional[str]) -> None:
        """Set the GitHub Personal Access Token for authenticated API requests."""
        self._github_token = token
        if token:
            logger.info("GitHub token configured - using authenticated API access")

    def _get_github_headers(self) -> Dict[str, str]:
        """Get headers for GitHub API requests, including auth if available."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._github_token:
            headers["Authorization"] = f"Bearer {self._github_token}"
        return headers

    async def fetch_ghsa_advisory(
        self, client: httpx.AsyncClient, ghsa_id: str
    ) -> Optional[GHSAData]:
        """
        Fetch a single GitHub Security Advisory by its GHSA ID.

        Uses the GitHub Advisory Database API. If a GitHub token is configured,
        authenticated requests are made for higher rate limits.

        Checks Redis cache first before making API call.
        """
        # Check Redis cache first
        cache_key = CacheKeys.ghsa(ghsa_id)
        cached = await cache_service.get(cache_key)
        if cached:
            logger.debug(f"GHSA {ghsa_id} loaded from Redis cache")
            return GHSAData(**cached)

        try:
            # GitHub Advisory API endpoint
            url = f"{GHSA_API_URL}/{ghsa_id}"
            headers = self._get_github_headers()

            response = await client.get(url, headers=headers, timeout=15.0)

            if response.status_code == 404:
                logger.debug(f"GHSA advisory not found: {ghsa_id}")
                # Cache negative result with shorter TTL
                empty_data = GHSAData(
                    ghsa_id=ghsa_id,
                    github_url=f"https://github.com/advisories/{ghsa_id}",
                )
                await cache_service.set(
                    cache_key, empty_data.model_dump(), CacheTTL.NEGATIVE_RESULT
                )
                return None

            if response.status_code == 403:
                # Rate limited
                logger.warning(f"GitHub API rate limited when fetching {ghsa_id}")
                return None

            response.raise_for_status()
            data = response.json()

            # Extract CVE from identifiers
            cve_id = None
            aliases = []
            for identifier in data.get("identifiers", []):
                id_type = identifier.get("type", "")
                id_value = identifier.get("value", "")
                if id_type == "CVE" and id_value:
                    cve_id = id_value
                elif id_value and id_value != ghsa_id:
                    aliases.append(id_value)

            # Also check aliases field
            for alias in data.get("aliases", []):
                if alias.startswith("CVE-") and not cve_id:
                    cve_id = alias
                elif alias not in aliases and alias != ghsa_id:
                    aliases.append(alias)

            ghsa_data = GHSAData(
                ghsa_id=ghsa_id,
                cve_id=cve_id,
                summary=data.get("summary"),
                severity=data.get("severity"),
                published_at=data.get("published_at"),
                updated_at=data.get("updated_at"),
                withdrawn_at=data.get("withdrawn_at"),
                github_url=data.get(
                    "html_url", f"https://github.com/advisories/{ghsa_id}"
                ),
                aliases=aliases,
            )

            # Cache in Redis
            await cache_service.set(
                cache_key, ghsa_data.model_dump(), CacheTTL.GHSA_DATA
            )
            logger.debug(f"GHSA {ghsa_id} fetched and cached in Redis")

            return ghsa_data

        except httpx.TimeoutException:
            logger.warning(f"Timeout fetching GHSA advisory: {ghsa_id}")
            return None
        except Exception as e:
            logger.warning(f"Failed to fetch GHSA advisory {ghsa_id}: {e}")
            return None

    async def resolve_ghsa_to_cve(
        self, client: httpx.AsyncClient, ghsa_ids: List[str]
    ) -> Dict[str, GHSAData]:
        """
        Resolve multiple GHSA IDs to CVEs and get advisory metadata.

        Uses Redis cache for previously resolved GHSAs.

        Args:
            client: HTTP client
            ghsa_ids: List of GHSA IDs (e.g., ["GHSA-xxxx-xxxx-xxxx"])

        Returns:
            Dict mapping GHSA ID to GHSAData (includes CVE if available)
        """
        if not ghsa_ids:
            return {}

        results = {}
        missing_ghsas = []

        # Check Redis cache for each GHSA (batch get)
        cache_keys = [CacheKeys.ghsa(ghsa_id) for ghsa_id in ghsa_ids]
        cached_data = await cache_service.mget(cache_keys)

        for ghsa_id, cached in zip(ghsa_ids, cached_data.values()):
            if cached:
                results[ghsa_id] = GHSAData(**cached)
            else:
                missing_ghsas.append(ghsa_id)

        if missing_ghsas:
            logger.debug(f"Fetching {len(missing_ghsas)} GHSA advisories (cache miss)")

        # Fetch missing (one at a time to avoid rate limits)
        for ghsa_id in missing_ghsas:
            ghsa_data = await self.fetch_ghsa_advisory(client, ghsa_id)
            if ghsa_data:
                results[ghsa_id] = ghsa_data
            else:
                # Create empty data for failed lookups
                empty_data = GHSAData(
                    ghsa_id=ghsa_id,
                    github_url=f"https://github.com/advisories/{ghsa_id}",
                )
                results[ghsa_id] = empty_data

            # Small delay to avoid rate limiting
            await asyncio.sleep(0.1)

        logger.info(
            f"Resolved {len(results)} GHSA IDs ({len(ghsa_ids) - len(missing_ghsas)} from cache)"
        )
        return results
