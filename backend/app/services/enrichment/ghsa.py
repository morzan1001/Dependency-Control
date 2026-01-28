import asyncio
import logging
from typing import Dict, List, Optional

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.config import settings
from app.core.constants import (
    ANALYZER_TIMEOUTS,
    GHSA_API_URL,
    GHSA_CONCURRENT_REQUESTS_AUTHENTICATED,
    GHSA_CONCURRENT_REQUESTS_UNAUTHENTICATED,
)
from app.schemas.enrichment import GHSAData

logger = logging.getLogger(__name__)


class GHSAProvider:
    """Provider for GitHub Security Advisory (GHSA) data."""

    def __init__(
        self,
        max_retries: Optional[int] = None,
        retry_delay: Optional[float] = None,
    ):
        self._github_token: Optional[str] = None
        self._max_retries = (
            max_retries if max_retries is not None else settings.ENRICHMENT_MAX_RETRIES
        )
        self._retry_delay = (
            retry_delay if retry_delay is not None else settings.ENRICHMENT_RETRY_DELAY
        )

    def set_token(self, token: Optional[str]) -> None:
        """Set the GitHub Personal Access Token for authenticated API requests."""
        self._github_token = token
        if token:
            logger.info("GitHub token configured - using authenticated API access")

    def _get_concurrency_limit(self) -> int:
        """Get concurrency limit based on authentication status."""
        if self._github_token:
            return GHSA_CONCURRENT_REQUESTS_AUTHENTICATED
        return GHSA_CONCURRENT_REQUESTS_UNAUTHENTICATED

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

        Uses distributed lock to prevent multiple pods fetching same advisory.
        """
        cache_key = CacheKeys.ghsa(ghsa_id)
        timeout = ANALYZER_TIMEOUTS.get("ghsa", ANALYZER_TIMEOUTS["default"])

        async def fetch_from_github() -> Optional[Dict]:
            """Fetch GHSA advisory from GitHub API with retry logic."""
            last_error = None

            for attempt in range(self._max_retries):
                try:
                    url = f"{GHSA_API_URL}/{ghsa_id}"
                    headers = self._get_github_headers()

                    response = await client.get(url, headers=headers, timeout=timeout)

                    if response.status_code == 404:
                        logger.debug(f"GHSA advisory not found: {ghsa_id}")
                        # Return empty data for negative cache
                        return GHSAData(
                            ghsa_id=ghsa_id,
                            github_url=f"https://github.com/advisories/{ghsa_id}",
                        ).model_dump()

                    if response.status_code == 403:
                        # Rate limited - exponential backoff
                        wait_time = self._retry_delay * (2**attempt)
                        logger.warning(
                            f"GitHub API rate limited for {ghsa_id}, "
                            f"waiting {wait_time}s (attempt {attempt + 1})"
                        )
                        if attempt < self._max_retries - 1:
                            await asyncio.sleep(wait_time)
                            continue
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

                    logger.debug(f"GHSA {ghsa_id} fetched from GitHub API")
                    return ghsa_data.model_dump()

                except httpx.TimeoutException:
                    last_error = "Timeout"
                    logger.warning(
                        f"Timeout fetching GHSA {ghsa_id} "
                        f"(attempt {attempt + 1}/{self._max_retries})"
                    )
                except httpx.ConnectError:
                    last_error = "Connection error"
                    logger.warning(
                        f"Connection error fetching GHSA {ghsa_id} "
                        f"(attempt {attempt + 1}/{self._max_retries})"
                    )
                except httpx.HTTPStatusError as e:
                    last_error = f"HTTP {e.response.status_code}"
                    if e.response.status_code >= 500:
                        logger.warning(
                            f"GitHub API server error for {ghsa_id}: "
                            f"{e.response.status_code} "
                            f"(attempt {attempt + 1}/{self._max_retries})"
                        )
                    else:
                        # Client error (4xx except 403) - don't retry
                        logger.warning(f"GitHub API client error for {ghsa_id}: {e}")
                        return None
                except Exception as e:
                    last_error = str(e)
                    logger.warning(
                        f"Failed to fetch GHSA {ghsa_id} "
                        f"(attempt {attempt + 1}/{self._max_retries}): {e}"
                    )

                if attempt < self._max_retries - 1:
                    await asyncio.sleep(self._retry_delay)

            logger.error(
                f"GHSA {ghsa_id} fetch failed after {self._max_retries} attempts: "
                f"{last_error}"
            )
            return None

        # Use distributed lock to prevent multiple pods fetching same advisory
        cached = await cache_service.get_or_fetch_with_lock(
            key=cache_key,
            fetch_fn=fetch_from_github,
            ttl_seconds=CacheTTL.GHSA_DATA,
        )

        if cached:
            return GHSAData(**cached)
        return None

    async def resolve_ghsa_to_cve(
        self, client: httpx.AsyncClient, ghsa_ids: List[str]
    ) -> Dict[str, GHSAData]:
        """
        Resolve multiple GHSA IDs to CVEs and get advisory metadata.

        Uses Redis cache for previously resolved GHSAs.
        Uses semaphore-based concurrency for parallel fetching with rate limit awareness.

        Args:
            client: HTTP client
            ghsa_ids: List of GHSA IDs (e.g., ["GHSA-xxxx-xxxx-xxxx"])

        Returns:
            Dict mapping GHSA ID to GHSAData (includes CVE if available)
        """
        if not ghsa_ids:
            return {}

        results: Dict[str, GHSAData] = {}
        missing_ghsas: List[str] = []

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

            # Use semaphore to limit concurrent requests based on auth status
            concurrency = self._get_concurrency_limit()
            semaphore = asyncio.Semaphore(concurrency)

            async def fetch_with_semaphore(
                ghsa_id: str,
            ) -> tuple[str, Optional[GHSAData]]:
                """Fetch single GHSA with semaphore for rate limiting."""
                async with semaphore:
                    ghsa_data = await self.fetch_ghsa_advisory(client, ghsa_id)
                    return ghsa_id, ghsa_data

            # Fetch all missing GHSAs concurrently (limited by semaphore)
            tasks = [fetch_with_semaphore(ghsa_id) for ghsa_id in missing_ghsas]
            fetch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in fetch_results:
                if isinstance(result, Exception):
                    logger.warning(f"Exception during GHSA fetch: {result}")
                    continue

                ghsa_id, ghsa_data = result
                if ghsa_data:
                    results[ghsa_id] = ghsa_data
                else:
                    # Create empty data for failed lookups
                    results[ghsa_id] = GHSAData(
                        ghsa_id=ghsa_id,
                        github_url=f"https://github.com/advisories/{ghsa_id}",
                    )

        logger.info(
            f"Resolved {len(results)} GHSA IDs "
            f"({len(ghsa_ids) - len(missing_ghsas)} from cache, "
            f"concurrency: {self._get_concurrency_limit()})"
        )
        return results
