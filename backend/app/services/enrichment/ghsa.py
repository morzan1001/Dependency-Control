import logging
import time
from typing import Any

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.config import settings
from app.core.constants import (
    ANALYZER_TIMEOUTS,
    GHSA_API_URL,
    GHSA_CONCURRENT_REQUESTS_AUTHENTICATED,
    GHSA_CONCURRENT_REQUESTS_UNAUTHENTICATED,
)
from app.core.http_utils import InstrumentedAsyncClient, gather_bounded
from app.schemas.enrichment import GHSAData
from app.services.github import github_api_headers

logger = logging.getLogger(__name__)


def _parse_ghsa_advisory(data: dict[str, Any], ghsa_id: str) -> GHSAData:
    return GHSAData(ghsa_id=ghsa_id, cve_id=data.get("cve_id") or None, github_url=data.get("html_url") or "")


class GHSAProvider:
    """Provider for GitHub Security Advisory (GHSA) data."""

    def __init__(self) -> None:
        # Anonymous and token lookups spend separate GitHub quotas, keyed by whether a token was sent.
        self._rate_limited_until: dict[bool, float] = {}

    async def fetch_ghsa_advisory(
        self, client: InstrumentedAsyncClient, ghsa_id: str, token: str | None
    ) -> GHSAData | None:
        """One advisory through the cross-pod lock; None while GitHub's quota is exhausted."""
        authenticated = bool(token)
        if time.time() < self._rate_limited_until.get(authenticated, 0.0):
            return None

        async def fetch_from_github() -> dict[str, Any]:
            response = await client.send_with_backoff(
                "GET",
                f"{GHSA_API_URL}/{ghsa_id}",
                attempts=settings.ENRICHMENT_MAX_RETRIES,
                base_delay=settings.ENRICHMENT_RETRY_DELAY,
                headers=github_api_headers(token),
            )
            if response.status_code == 404:
                # 404 is authoritative: cache the unresolved placeholder for the GHSA TTL, not the 1 h failure TTL.
                return GHSAData(ghsa_id=ghsa_id).model_dump()
            # A secondary limit sends Retry-After, which GitHub ranks above the primary quota's reset.
            retry_after = response.headers.get("Retry-After")
            if response.status_code in (403, 429) and (
                retry_after or response.headers.get("X-RateLimit-Remaining") == "0"
            ):
                self._rate_limited_until[authenticated] = (
                    time.time() + float(retry_after)
                    if retry_after
                    else float(response.headers.get("X-RateLimit-Reset") or 0)
                )
            response.raise_for_status()
            return _parse_ghsa_advisory(response.json(), ghsa_id).model_dump()

        cached = await cache_service.get_or_fetch_with_lock(
            key=CacheKeys.ghsa(ghsa_id),
            fetch_fn=fetch_from_github,
            ttl_seconds=CacheTTL.GHSA_DATA,
            reraise_fetch_errors=True,
        )
        return GHSAData(**cached) if cached else None

    async def resolve_ghsa_to_cve(self, ghsa_ids: list[str], token: str | None) -> dict[str, GHSAData]:
        """Resolve GHSA IDs to CVEs from Redis, then GitHub; an id that could not be looked up comes back unresolved."""
        cached_data = await cache_service.mget([CacheKeys.ghsa(ghsa_id) for ghsa_id in ghsa_ids])
        results: dict[str, GHSAData] = {}
        missing: list[str] = []
        for ghsa_id in dict.fromkeys(ghsa_ids):
            cached = cached_data[CacheKeys.ghsa(ghsa_id)]
            if cached:
                results[ghsa_id] = GHSAData(**cached)
            else:
                missing.append(ghsa_id)
        if not missing:
            return results

        concurrency = GHSA_CONCURRENT_REQUESTS_AUTHENTICATED if token else GHSA_CONCURRENT_REQUESTS_UNAUTHENTICATED
        timeout = ANALYZER_TIMEOUTS["ghsa"]
        async with InstrumentedAsyncClient("GitHub Advisory API", timeout=timeout) as client:
            outcomes = await gather_bounded(
                missing, lambda ghsa_id: self.fetch_ghsa_advisory(client, ghsa_id, token), concurrency
            )
        for ghsa_id, outcome in zip(missing, outcomes, strict=True):
            if isinstance(outcome, BaseException):
                logger.warning(f"GHSA {ghsa_id} lookup failed: {outcome}")
            results[ghsa_id] = outcome if isinstance(outcome, GHSAData) else GHSAData(ghsa_id=ghsa_id)

        logger.info(
            f"Resolved {len(results)} GHSA IDs ({len(results) - len(missing)} from cache, concurrency: {concurrency})"
        )
        return results
