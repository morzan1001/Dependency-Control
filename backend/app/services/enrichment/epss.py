import logging
from typing import Any

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.config import settings
from app.core.constants import ANALYZER_BATCH_SIZES, ANALYZER_TIMEOUTS, EPSS_API_URL, EPSS_CONCURRENT_BATCHES
from app.core.http_utils import InstrumentedAsyncClient, gather_bounded
from app.schemas.enrichment import EPSSData

logger = logging.getLogger(__name__)


class EPSSProvider:
    """Provider for Exploit Prediction Scoring System (EPSS) data."""

    def __init__(self) -> None:
        self._batch_size = ANALYZER_BATCH_SIZES.get("epss", 100)
        self._timeout = ANALYZER_TIMEOUTS.get("epss", ANALYZER_TIMEOUTS["default"])

    async def _fetch_batch(self, client: InstrumentedAsyncClient, cves: list[str]) -> dict[str, EPSSData]:
        response = await client.send_with_backoff(
            "GET",
            f"{EPSS_API_URL}?cve={','.join(cves)}",
            attempts=settings.ENRICHMENT_MAX_RETRIES,
            base_delay=settings.ENRICHMENT_RETRY_DELAY,
        )
        response.raise_for_status()
        return {
            entry["cve"]: EPSSData(
                cve=entry["cve"],
                epss_score=float(entry.get("epss") or 0.0),
                percentile=float(entry.get("percentile") or 0.0) * 100,
                date=entry.get("date") or "",
            )
            for entry in response.json().get("data", [])
            if entry.get("cve")
        }

    async def _fetch_and_cache(self, cves: list[str]) -> tuple[dict[str, EPSSData], bool]:
        """Fetch uncached CVEs; True when every batch answered, so a CVE it left out has no score."""
        batches = [cves[i : i + self._batch_size] for i in range(0, len(cves), self._batch_size)]
        async with InstrumentedAsyncClient("EPSS API", timeout=self._timeout) as client:
            outcomes = await gather_bounded(
                batches, lambda batch: self._fetch_batch(client, batch), EPSS_CONCURRENT_BATCHES
            )

        scores: dict[str, EPSSData] = {}
        unscored: dict[str, Any] = {}
        failed = 0
        for batch, outcome in zip(batches, outcomes, strict=True):
            if isinstance(outcome, BaseException):
                failed += 1
                logger.warning(f"EPSS batch of {len(batch)} CVEs failed: {outcome}")
                continue
            scores |= outcome
            unscored |= {CacheKeys.epss(cve): {} for cve in batch if cve not in outcome}

        await cache_service.mset(
            {CacheKeys.epss(cve): data.model_dump() for cve, data in scores.items()}, CacheTTL.EPSS_SCORE
        )
        await cache_service.mset(unscored, CacheTTL.NEGATIVE_RESULT)
        return scores, failed == 0

    async def load_epss_scores(self, cves: list[str]) -> tuple[dict[str, EPSSData], bool]:
        """EPSS scores for `cves` from Redis, then FIRST.org; False when some could not be fetched."""
        cached_data = await cache_service.mget([CacheKeys.epss(cve) for cve in cves])
        result: dict[str, EPSSData] = {}
        missing: list[str] = []
        for cve in dict.fromkeys(cves):
            cached = cached_data[CacheKeys.epss(cve)]
            if cached is None:
                missing.append(cve)
            elif cached:
                result[cve] = EPSSData(**cached)

        if not missing:
            return result, True
        logger.debug(f"Fetching EPSS data for {len(missing)} CVEs ({len(result)} from cache)")
        fetched, complete = await self._fetch_and_cache(missing)
        return result | fetched, complete
