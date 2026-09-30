import logging
import time
from typing import Any

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.config import settings
from app.core.constants import ANALYZER_TIMEOUTS, KEV_CATALOG_URL
from app.core.http_utils import InstrumentedAsyncClient
from app.schemas.enrichment import KEVEntry

logger = logging.getLogger(__name__)

_MEMO_SECONDS = 15 * 60


async def _fetch_kev_catalog() -> dict[str, Any]:
    timeout = ANALYZER_TIMEOUTS.get("kev", ANALYZER_TIMEOUTS["default"])
    async with InstrumentedAsyncClient("CISA KEV", timeout=timeout) as client:
        response = await client.send_with_backoff(
            "GET",
            KEV_CATALOG_URL,
            attempts=settings.ENRICHMENT_MAX_RETRIES,
            base_delay=settings.ENRICHMENT_RETRY_DELAY,
        )
    response.raise_for_status()
    catalog = {
        vuln["cveID"]: KEVEntry(
            cve=vuln["cveID"],
            date_added=vuln.get("dateAdded") or "",
            required_action=vuln.get("requiredAction") or "",
            due_date=vuln.get("dueDate") or "",
            known_ransomware_use=(vuln.get("knownRansomwareCampaignUse") or "").lower() == "known",
        ).model_dump()
        for vuln in response.json().get("vulnerabilities", [])
        if vuln.get("cveID")
    }
    if not catalog:
        raise ValueError("CISA KEV catalog is empty")
    logger.info(f"Fetched {len(catalog)} entries from CISA KEV catalog")
    return catalog


class KEVProvider:
    """Provider for CISA Known Exploited Vulnerabilities (KEV) catalog."""

    def __init__(self) -> None:
        self._memo: dict[str, KEVEntry] = {}
        self._memo_expires = 0.0

    async def load_kev_catalog(self) -> dict[str, KEVEntry] | None:
        """The KEV catalog from this process, Redis or CISA, in that order; None when it could not be read."""
        if self._memo and time.monotonic() < self._memo_expires:
            return self._memo
        cached = await cache_service.get_or_fetch_with_lock(
            key=CacheKeys.kev_catalog(),
            fetch_fn=_fetch_kev_catalog,
            ttl_seconds=CacheTTL.KEV_CATALOG,
        )
        if not cached:
            return None
        self._memo = {cve: KEVEntry(**entry) for cve, entry in cached.items()}
        self._memo_expires = time.monotonic() + _MEMO_SECONDS
        return self._memo
