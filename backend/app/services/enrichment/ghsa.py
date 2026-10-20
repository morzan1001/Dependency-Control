import logging
import time
from contextlib import suppress
from typing import Any

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.config import settings
from app.core.constants import (
    ANALYZER_TIMEOUTS,
    GHSA_API_URL,
    GHSA_CONCURRENT_REQUESTS_AUTHENTICATED,
    GHSA_CONCURRENT_REQUESTS_UNAUTHENTICATED,
)
from app.core.http_utils import UNNAMED_QUOTA_WAIT_SECONDS, InstrumentedAsyncClient, gather_bounded, quota_lifts_at
from app.schemas.enrichment import GHSAData
from app.services.github import github_api_headers

logger = logging.getLogger(__name__)


def _parse_ghsa_advisory(data: dict[str, Any], ghsa_id: str) -> GHSAData:
    return GHSAData(ghsa_id=ghsa_id, cve_id=data.get("cve_id") or None, github_url=data.get("html_url") or "")


def _bare_secondary_limit(response: httpx.Response) -> bool:
    """GitHub can refuse a secondary limit with a plain 403 that only its message names."""
    if response.status_code != 403:
        return False
    with suppress(ValueError):
        body = response.json()
        return isinstance(body, dict) and "rate limit" in str(body.get("message", "")).lower()
    return False


class GHSAProvider:
    def __init__(self) -> None:
        # Anonymous and token lookups spend separate GitHub quotas, keyed by whether a token was sent.
        self._rate_limited_until: dict[bool, float] = {}

    async def fetch_ghsa_advisory(
        self, client: InstrumentedAsyncClient, ghsa_id: str, token: str | None
    ) -> GHSAData | None:
        authenticated = bool(token)
        if time.time() < self._rate_limited_until.get(authenticated, 0.0):
            return None

        async def fetch_from_github() -> dict[str, Any]:
            response = await client.send_with_backoff(
                "GET",
                f"{GHSA_API_URL}/{ghsa_id}",
                attempts=1 + settings.ENRICHMENT_MAX_RETRIES,
                base_delay=settings.ENRICHMENT_RETRY_DELAY,
                headers=github_api_headers(token),
            )
            if response.status_code == 404:
                # 404 is authoritative: cache the unresolved placeholder for the GHSA TTL, not the 1 h failure TTL.
                return GHSAData(ghsa_id=ghsa_id).model_dump()
            lifts_at = quota_lifts_at(response)
            if lifts_at is None and _bare_secondary_limit(response):
                lifts_at = time.time() + UNNAMED_QUOTA_WAIT_SECONDS
            if lifts_at is not None:
                # Answers in flight land in any order; a short secondary limit must not end a longer quota hold.
                self._rate_limited_until[authenticated] = max(
                    self._rate_limited_until.get(authenticated, 0.0), lifts_at
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

    async def resolve_ghsa_to_cve(self, ghsa_ids: list[str], token: str | None) -> tuple[dict[str, GHSAData], bool]:
        """True when GitHub answered every lookup; an advisory it does not know counts as answered."""
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
            return results, True

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
        return results, all(isinstance(outcome, GHSAData) for outcome in outcomes)
