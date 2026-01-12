import asyncio
import logging
from typing import Dict, List

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import EPSS_API_URL
from app.schemas.enrichment import EPSSData

logger = logging.getLogger(__name__)


class EPSSProvider:
    """Provider for Exploit Prediction Scoring System (EPSS) data."""

    BATCH_SIZE = 100  # Max CVEs per EPSS API request

    def __init__(self, max_retries: int = 3, retry_delay: float = 1.0):
        self._max_retries = max_retries
        self._retry_delay = retry_delay

    async def fetch_epss_batch(
        self, client: httpx.AsyncClient, cves: List[str]
    ) -> Dict[str, EPSSData]:
        """Fetch EPSS scores for a batch of CVEs with retry logic."""
        if not cves:
            return {}

        last_error = None
        for attempt in range(self._max_retries):
            try:
                # EPSS API accepts comma-separated CVE list
                cve_param = ",".join(cves)
                response = await client.get(
                    f"{EPSS_API_URL}?cve={cve_param}", timeout=30.0
                )
                response.raise_for_status()

                data = response.json()
                results = {}

                for entry in data.get("data", []):
                    cve = entry.get("cve", "")
                    if cve:
                        results[cve] = EPSSData(
                            cve=cve,
                            epss_score=float(entry.get("epss", 0)),
                            percentile=float(entry.get("percentile", 0))
                            * 100,  # Convert to percentage
                            date=entry.get("date", ""),
                        )

                # Log if some CVEs weren't found (not an error, just info)
                if len(results) < len(cves):
                    missing = set(cves) - set(results.keys())
                    if missing:
                        logger.debug(
                            f"EPSS: No data for {len(missing)} CVEs (may be too new or invalid)"
                        )

                return results

            except httpx.TimeoutException:
                last_error = "Timeout"
                logger.warning(
                    f"EPSS API timeout (attempt {attempt + 1}/{self._max_retries})"
                )
            except httpx.HTTPStatusError as e:
                last_error = f"HTTP {e.response.status_code}"
                if e.response.status_code == 429:  # Rate limited
                    wait_time = self._retry_delay * (2**attempt)  # Exponential backoff
                    logger.warning(f"EPSS API rate limited, waiting {wait_time}s")
                    await asyncio.sleep(wait_time)
                elif e.response.status_code >= 500:  # Server error
                    logger.warning(
                        f"EPSS API server error {e.response.status_code} (attempt {attempt + 1})"
                    )
                else:
                    # Client error (4xx except 429) - don't retry
                    logger.warning(f"EPSS API client error: {e}")
                    return {}
            except Exception as e:
                last_error = str(e)
                logger.warning(
                    f"Failed to fetch EPSS data (attempt {attempt + 1}): {e}"
                )

            if attempt < self._max_retries - 1:
                await asyncio.sleep(self._retry_delay)

        logger.error(
            f"EPSS API failed after {self._max_retries} attempts: {last_error}"
        )
        return {}

    async def load_epss_scores(
        self, client: httpx.AsyncClient, cves: List[str]
    ) -> Dict[str, EPSSData]:
        """Load EPSS scores for given CVEs, using Redis cache where available."""
        result = {}
        missing_cves = []

        # Check Redis cache first (batch get)
        cache_keys = [CacheKeys.epss(cve) for cve in cves]
        cached_data = await cache_service.mget(cache_keys)

        for cve, cached in zip(cves, cached_data.values()):
            if cached:
                result[cve] = EPSSData(**cached)
            else:
                missing_cves.append(cve)

        # Fetch missing in batches from API
        if missing_cves:
            logger.debug(
                f"Fetching EPSS data for {len(missing_cves)} CVEs ({len(cves) - len(missing_cves)} from cache)"
            )

            for i in range(0, len(missing_cves), self.BATCH_SIZE):
                batch = missing_cves[i : i + self.BATCH_SIZE]
                batch_results = await self.fetch_epss_batch(client, batch)

                # Cache each result individually in Redis
                cache_mapping = {}
                for cve, data in batch_results.items():
                    cache_mapping[CacheKeys.epss(cve)] = data.model_dump()
                    result[cve] = data

                if cache_mapping:
                    await cache_service.mset(cache_mapping, CacheTTL.EPSS_SCORE)

                # Small delay between batches to be nice to the API
                if i + self.BATCH_SIZE < len(missing_cves):
                    await asyncio.sleep(0.5)

        return result
