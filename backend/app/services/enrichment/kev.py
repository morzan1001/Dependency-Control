import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.config import settings
from app.core.constants import ANALYZER_TIMEOUTS, KEV_CATALOG_URL
from app.schemas.enrichment import KEVEntry

logger = logging.getLogger(__name__)


class KEVProvider:
    """Provider for CISA Known Exploited Vulnerabilities (KEV) catalog."""

    def __init__(
        self,
        max_retries: Optional[int] = None,
        retry_delay: Optional[float] = None,
    ):
        self._max_retries = (
            max_retries if max_retries is not None else settings.ENRICHMENT_MAX_RETRIES
        )
        self._retry_delay = (
            retry_delay if retry_delay is not None else settings.ENRICHMENT_RETRY_DELAY
        )
        # In-memory fallback caches (used only if Redis is unavailable)
        self._kev_cache_fallback: Dict[str, KEVEntry] = {}
        self._kev_cache_time_fallback: Optional[datetime] = None

    async def load_kev_catalog(self, client: httpx.AsyncClient) -> Dict[str, KEVEntry]:
        """Load CISA KEV catalog, using Redis cache with distributed lock."""
        cache_key = CacheKeys.kev_catalog()
        timeout = ANALYZER_TIMEOUTS.get("kev", ANALYZER_TIMEOUTS["default"])

        async def fetch_kev_catalog() -> Optional[Dict[str, Any]]:
            """Fetch KEV catalog from CISA API with retry logic."""
            last_error = None

            for attempt in range(self._max_retries):
                try:
                    response = await client.get(KEV_CATALOG_URL, timeout=timeout)
                    response.raise_for_status()

                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])

                    kev_dict: Dict[str, Any] = {}
                    for vuln in vulnerabilities:
                        cve = vuln.get("cveID", "")
                        if cve:
                            # Handle potential None value for ransomware field
                            ransomware_value = (
                                vuln.get("knownRansomwareCampaignUse") or ""
                            )
                            kev_entry = KEVEntry(
                                cve=cve,
                                vendor_project=vuln.get("vendorProject") or "",
                                product=vuln.get("product") or "",
                                vulnerability_name=vuln.get("vulnerabilityName") or "",
                                date_added=vuln.get("dateAdded") or "",
                                short_description=vuln.get("shortDescription") or "",
                                required_action=vuln.get("requiredAction") or "",
                                due_date=vuln.get("dueDate") or "",
                                known_ransomware_use=ransomware_value.lower()
                                == "known",
                            )
                            kev_dict[cve] = kev_entry.model_dump()

                    logger.info(
                        f"Fetched {len(kev_dict)} entries from CISA KEV catalog"
                    )
                    # Don't cache empty results - likely an API issue
                    # KEV catalog has 1000+ entries, empty is suspicious
                    if not kev_dict:
                        logger.warning("KEV catalog returned empty - not caching")
                        return None
                    return kev_dict

                except httpx.TimeoutException:
                    last_error = "Timeout"
                    logger.warning(
                        f"KEV catalog fetch timeout "
                        f"(attempt {attempt + 1}/{self._max_retries})"
                    )
                except httpx.ConnectError:
                    last_error = "Connection error"
                    logger.warning(
                        f"KEV catalog connection error "
                        f"(attempt {attempt + 1}/{self._max_retries})"
                    )
                except httpx.HTTPStatusError as e:
                    last_error = f"HTTP {e.response.status_code}"
                    if e.response.status_code >= 500:
                        logger.warning(
                            f"KEV catalog server error {e.response.status_code} "
                            f"(attempt {attempt + 1}/{self._max_retries})"
                        )
                    else:
                        # Client error (4xx) - don't retry
                        logger.warning(f"KEV catalog client error: {e}")
                        return None
                except Exception as e:
                    last_error = str(e)
                    logger.warning(
                        f"Failed to fetch CISA KEV catalog "
                        f"(attempt {attempt + 1}/{self._max_retries}): {e}"
                    )

                if attempt < self._max_retries - 1:
                    await asyncio.sleep(self._retry_delay * (attempt + 1))

            logger.error(
                f"KEV catalog fetch failed after {self._max_retries} attempts: "
                f"{last_error}"
            )
            return None

        # Use distributed lock to prevent multiple pods fetching simultaneously
        cached = await cache_service.get_or_fetch_with_lock(
            key=cache_key,
            fetch_fn=fetch_kev_catalog,
            ttl_seconds=CacheTTL.KEV_CATALOG,
        )

        if cached:
            # Update in-memory fallback cache
            kev_data = {k: KEVEntry(**v) for k, v in cached.items()}
            self._kev_cache_fallback = kev_data
            self._kev_cache_time_fallback = datetime.now(timezone.utc)
            logger.debug(f"KEV catalog loaded ({len(kev_data)} entries)")
            return kev_data

        # Fallback: check in-memory cache if Redis failed
        if self._kev_cache_time_fallback:
            cache_age = datetime.now(timezone.utc) - self._kev_cache_time_fallback
            if cache_age < timedelta(hours=24) and self._kev_cache_fallback:
                logger.debug("KEV catalog loaded from in-memory fallback cache")
                return self._kev_cache_fallback

        return self._kev_cache_fallback or {}
