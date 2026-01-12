import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import KEV_CATALOG_URL
from app.schemas.enrichment import KEVEntry

logger = logging.getLogger(__name__)


class KEVProvider:
    """Provider for CISA Known Exploited Vulnerabilities (KEV) catalog."""

    def __init__(self):
        # In-memory fallback caches (used only if Redis is unavailable)
        self._kev_cache_fallback: Dict[str, KEVEntry] = {}
        self._kev_cache_time_fallback: Optional[datetime] = None

    async def load_kev_catalog(self, client: httpx.AsyncClient) -> Dict[str, KEVEntry]:
        """Load CISA KEV catalog, using Redis cache if available."""
        cache_key = CacheKeys.kev_catalog()

        # Try Redis cache first
        cached = await cache_service.get(cache_key)
        if cached:
            logger.debug("KEV catalog loaded from Redis cache")
            return {k: KEVEntry(**v) for k, v in cached.items()}

        # Fallback: check in-memory cache
        if self._kev_cache_time_fallback:
            cache_age = datetime.now(timezone.utc) - self._kev_cache_time_fallback
            if cache_age < timedelta(hours=24) and self._kev_cache_fallback:
                logger.debug("KEV catalog loaded from in-memory fallback cache")
                return self._kev_cache_fallback

        # Fetch fresh data from CISA
        try:
            response = await client.get(KEV_CATALOG_URL)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            kev_data = {}
            for vuln in vulnerabilities:
                cve = vuln.get("cveID", "")
                if cve:
                    kev_entry = KEVEntry(
                        cve=cve,
                        vendor_project=vuln.get("vendorProject", ""),
                        product=vuln.get("product", ""),
                        vulnerability_name=vuln.get("vulnerabilityName", ""),
                        date_added=vuln.get("dateAdded", ""),
                        short_description=vuln.get("shortDescription", ""),
                        required_action=vuln.get("requiredAction", ""),
                        due_date=vuln.get("dueDate", ""),
                        known_ransomware_use=vuln.get(
                            "knownRansomwareCampaignUse", ""
                        ).lower()
                        == "known",
                    )
                    kev_data[cve] = kev_entry

            # Cache in Redis (serialize to dict for JSON storage)
            kev_dict = {k: v.model_dump() for k, v in kev_data.items()}
            await cache_service.set(cache_key, kev_dict, CacheTTL.KEV_CATALOG)

            # Update fallback cache too
            self._kev_cache_fallback = kev_data
            self._kev_cache_time_fallback = datetime.now(timezone.utc)

            logger.info(
                f"Loaded {len(kev_data)} entries from CISA KEV catalog (cached in Redis)"
            )
            return kev_data

        except Exception as e:
            logger.warning(f"Failed to load CISA KEV catalog: {e}")
            # Return fallback cache if available
            return self._kev_cache_fallback
