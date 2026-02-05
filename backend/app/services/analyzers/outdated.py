import asyncio
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.http_utils import InstrumentedAsyncClient
from app.core.constants import ANALYZER_BATCH_SIZES, ANALYZER_TIMEOUTS, DEPS_DEV_API_URL
from app.models.finding import Severity

from .base import Analyzer
from .purl_utils import parse_purl

logger = logging.getLogger(__name__)


class OutdatedAnalyzer(Analyzer):
    """
    Analyzer that checks for outdated packages via deps.dev API.

    Uses Redis cache for latest version info to reduce API calls.
    """

    name = "outdated_packages"
    base_url = f"{DEPS_DEV_API_URL}/systems"

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        components = self._get_components(sbom, parsed_components)
        results = []

        # Check cache for latest versions first
        cached_versions, uncached_components = await self._get_cached_latest_versions(
            components
        )

        # Process cached versions
        for component, latest_version in cached_versions:
            name = component.get("name", "")
            version = component.get("version", "")
            purl = component.get("purl", "")

            if latest_version and latest_version != version:
                results.append(
                    {
                        "component": name,
                        "current_version": version,
                        "latest_version": latest_version,
                        "purl": purl,
                        "severity": Severity.INFO.value,
                        "message": f"Update available: {latest_version}",
                    }
                )

        logger.debug(
            f"Outdated: {len(cached_versions)} from cache, {len(uncached_components)} to fetch"
        )

        # Process uncached components with distributed locking to prevent cache stampede
        if uncached_components:
            timeout = ANALYZER_TIMEOUTS.get("outdated", ANALYZER_TIMEOUTS["default"])

            async with InstrumentedAsyncClient("deps.dev API", timeout=timeout) as client:
                # Process in batches to avoid overwhelming deps.dev API
                batch_size = ANALYZER_BATCH_SIZES.get("outdated", 25)
                for i in range(0, len(uncached_components), batch_size):
                    batch = uncached_components[i : i + batch_size]
                    tasks = [
                        self._check_component_for_batch(client, comp) for comp in batch
                    ]

                    component_results: List[Any] = await asyncio.gather(
                        *tasks, return_exceptions=True
                    )

                    for comp, result in zip(batch, component_results):
                        if isinstance(result, Exception):
                            continue
                        if result:
                            # Remove internal fields before adding to results
                            result_clean = {
                                k: v for k, v in result.items() if not k.startswith("_")
                            }
                            if result_clean:
                                results.append(result_clean)

                    # Small delay between batches to avoid rate limits
                    if i + batch_size < len(uncached_components):
                        await asyncio.sleep(0.1)

        return {"outdated_dependencies": results}

    async def _get_cached_latest_versions(
        self, components: List[Dict[str, Any]]
    ) -> tuple[List[tuple[Dict[str, Any], str]], List[Dict[str, Any]]]:
        """Check cache for latest versions, return cached and uncached components."""
        cached_results = []
        uncached_components = []

        # Build cache keys
        cache_keys = []
        component_map = {}
        skipped_count = 0

        for component in components:
            purl = component.get("purl", "")

            parsed = parse_purl(purl)
            if not parsed or not parsed.registry_system:
                skipped_count += 1
                continue

            cache_key = CacheKeys.latest_version(
                parsed.registry_system, parsed.deps_dev_name
            )
            cache_keys.append(cache_key)
            component_map[cache_key] = component

        if skipped_count > 0:
            logger.debug(
                f"Outdated: Skipped {skipped_count} components without valid registry system"
            )

        if not cache_keys:
            return [], components

        # Batch get from Redis
        cached_data: Dict[str, Any] = await cache_service.mget(cache_keys)

        for cache_key, latest_version in cached_data.items():
            component = component_map.get(cache_key)
            if not component:
                continue

            # Distinguish between "not cached" (None) and "cached empty" ("")
            if latest_version is not None:
                if latest_version:  # Non-empty cached value
                    cached_results.append((component, latest_version))
                # Empty string = negative cache, skip without re-fetching
            else:
                # None = not in cache, need to fetch
                uncached_components.append(component)

        return cached_results, uncached_components

    async def _check_component_for_batch(
        self, client: httpx.AsyncClient, component: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Check component and return result with distributed lock to prevent stampede."""
        purl_str = component.get("purl", "")
        # Fallback name/version if parse fails (though parse is better)
        name = component.get("name", "")
        version = component.get("version", "")

        parsed = parse_purl(purl_str)
        if not parsed:
            return None

        system = parsed.registry_system
        if not system or not version:
            return None

        cache_key = CacheKeys.latest_version(system, parsed.deps_dev_name)

        async def fetch_latest_version() -> Optional[str]:
            """Fetch latest version from deps.dev API."""
            encoded_name = quote(parsed.deps_dev_name, safe="")
            url = f"{self.base_url}/{system}/packages/{encoded_name}"

            try:
                response = await client.get(url, follow_redirects=True)
                if response.status_code == 200:
                    data = response.json()
                    versions_info = data.get("versions", [])

                    # Find the version marked as default (usually the latest stable)
                    for v in versions_info:
                        if v.get("isDefault"):
                            return v.get("versionKey", {}).get("version")
                return ""  # Empty string for negative cache
            except httpx.TimeoutException:
                logger.debug(f"Timeout checking outdated for {name}")
                return None
            except httpx.ConnectError:
                logger.debug(f"Connection error checking outdated for {name}")
                return None
            except Exception as e:
                logger.debug(f"Error checking outdated for {name}: {e}")
                return None

        # Use distributed lock to prevent multiple pods fetching same package
        latest_version = await cache_service.get_or_fetch_with_lock(
            key=cache_key,
            fetch_fn=fetch_latest_version,
            ttl_seconds=CacheTTL.LATEST_VERSION,
        )

        # Build result if version is outdated
        if latest_version and latest_version != version:
            return {
                "component": name,
                "current_version": version,
                "latest_version": latest_version,
                "purl": purl_str,
                "severity": Severity.INFO.value,
                "message": f"Update available: {latest_version}",
                "_cache_key": cache_key,
                "_latest_version": latest_version,
            }
        elif latest_version:
            # Version is current, return metadata for tracking
            return {
                "_cache_key": cache_key,
                "_latest_version": latest_version,
            }
        return None
