import asyncio
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx
from packaging.version import Version, InvalidVersion

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.http_utils import InstrumentedAsyncClient
from app.core.constants import ANALYZER_BATCH_SIZES, ANALYZER_TIMEOUTS, DEPS_DEV_API_URL
from app.models.finding import Severity

from .base import Analyzer
from .purl_utils import parse_purl

logger = logging.getLogger(__name__)


def _is_older_than(current: str, latest: str) -> bool:
    """Return True if current version is strictly older than latest.

    Uses semantic version comparison via ``packaging.version.Version``.
    Falls back to string inequality when either version string cannot be
    parsed (e.g. non-PEP-440 / non-semver), preserving the previous
    behaviour for exotic version schemes.
    """
    try:
        return Version(current) < Version(latest)
    except InvalidVersion:
        return current != latest


def _is_ahead_of(current: str, latest: str) -> bool:
    """Return True if current version is strictly newer than latest.

    This detects cases where the installed version is ahead of the version
    that deps.dev reports as the default (e.g. 1.26.0 installed but
    deps.dev still flags 1.25.5 as default).
    """
    try:
        return Version(current) > Version(latest)
    except InvalidVersion:
        return False


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
        outdated: List[Dict[str, Any]] = []
        ahead: List[Dict[str, Any]] = []

        # Check cache for latest versions first
        cached_versions, uncached_components = await self._get_cached_latest_versions(components)

        # Process cached versions
        for component, latest_version in cached_versions:
            if not latest_version:
                continue
            self._classify_version(component, latest_version, outdated, ahead)

        logger.debug(f"Outdated: {len(cached_versions)} from cache, {len(uncached_components)} to fetch")

        # Process uncached components with distributed locking to prevent cache stampede
        if uncached_components:
            await self._fetch_and_classify(uncached_components, outdated, ahead)

        return {"outdated_dependencies": outdated, "ahead_of_default": ahead}

    def _classify_version(
        self,
        component: Dict[str, Any],
        latest_version: str,
        outdated: List[Dict[str, Any]],
        ahead: List[Dict[str, Any]],
    ) -> None:
        """Classify a component as outdated, ahead-of-default, or up-to-date."""
        name = component.get("name", "")
        version = component.get("version", "")
        purl = component.get("purl", "")

        if _is_older_than(version, latest_version):
            outdated.append(
                {
                    "component": name,
                    "current_version": version,
                    "latest_version": latest_version,
                    "purl": purl,
                    "severity": Severity.INFO.value,
                    "message": f"Update available: {latest_version}",
                }
            )
        elif _is_ahead_of(version, latest_version):
            ahead.append(
                {
                    "component": name,
                    "current_version": version,
                    "default_version": latest_version,
                    "purl": purl,
                    "severity": Severity.INFO.value,
                    "message": (
                        f"Installed {version} is newer than the registry default "
                        f"{latest_version}. The registry may not have flagged this "
                        f"release as default yet."
                    ),
                }
            )

    async def _fetch_and_classify(
        self,
        uncached_components: List[Dict[str, Any]],
        outdated: List[Dict[str, Any]],
        ahead: List[Dict[str, Any]],
    ) -> None:
        """Fetch latest versions for uncached components and classify them."""
        timeout = ANALYZER_TIMEOUTS.get("outdated", ANALYZER_TIMEOUTS["default"])

        async with InstrumentedAsyncClient("deps.dev API", timeout=timeout) as client:
            batch_size = ANALYZER_BATCH_SIZES.get("outdated", 25)
            for i in range(0, len(uncached_components), batch_size):
                batch = uncached_components[i : i + batch_size]
                tasks = [self._check_component_for_batch(client, comp) for comp in batch]

                component_results: List[Any] = await asyncio.gather(*tasks, return_exceptions=True)

                for comp, result in zip(batch, component_results):
                    if isinstance(result, Exception) or not result:
                        continue
                    # Remove internal fields before adding to results
                    result_clean = {k: v for k, v in result.items() if not k.startswith("_")}
                    if not result_clean:
                        continue
                    if result.get("_ahead"):
                        ahead.append(result_clean)
                    else:
                        outdated.append(result_clean)

                # Small delay between batches to avoid rate limits
                if i + batch_size < len(uncached_components):
                    await asyncio.sleep(0.1)

    async def _get_cached_latest_versions(
        self, components: List[Dict[str, Any]]
    ) -> tuple[List[tuple[Dict[str, Any], str]], List[Dict[str, Any]]]:
        """Check cache for latest versions, return cached and uncached components."""
        cached_results = []
        uncached_components = []

        # Build cache keys
        cache_keys = []
        component_map: Dict[str, Any] = {}
        skipped_count = 0

        for component in components:
            purl = component.get("purl", "")

            parsed = parse_purl(purl)
            if not parsed or not parsed.registry_system:
                skipped_count += 1
                continue

            cache_key = CacheKeys.latest_version(parsed.registry_system, parsed.deps_dev_name)
            cache_keys.append(cache_key)
            component_map[cache_key] = component

        if skipped_count > 0:
            logger.debug(f"Outdated: Skipped {skipped_count} components without valid registry system")

        if not cache_keys:
            return [], components

        # Batch get from Redis
        cached_data: Dict[str, Any] = await cache_service.mget(cache_keys)

        for cache_key, latest_version in cached_data.items():
            cached_comp = component_map.get(cache_key)
            if not cached_comp:
                continue

            # Distinguish between "not cached" (None) and "cached empty" ("")
            if latest_version is not None:
                if latest_version:  # Non-empty cached value
                    cached_results.append((cached_comp, latest_version))
                # Empty string = negative cache, skip without re-fetching
            else:
                # None = not in cache, need to fetch
                uncached_components.append(cached_comp)

        return cached_results, uncached_components

    def _find_default_version(self, versions_info: List[Any]) -> Optional[str]:
        """Find the version marked as default (usually the latest stable)."""
        for v in versions_info:
            if v.get("isDefault"):
                version = v.get("versionKey", {}).get("version")
                return str(version) if version is not None else None
        return None

    def _build_outdated_result(
        self, name: str, version: str, latest_version: Optional[str], purl_str: str, cache_key: str
    ) -> Optional[Dict[str, Any]]:
        """Build result dict based on whether the version is outdated or ahead."""
        if not latest_version:
            return None

        base = {"_cache_key": cache_key, "_latest_version": latest_version}

        if _is_older_than(version, latest_version):
            return {
                **base,
                "component": name,
                "current_version": version,
                "latest_version": latest_version,
                "purl": purl_str,
                "severity": Severity.INFO.value,
                "message": f"Update available: {latest_version}",
            }

        if _is_ahead_of(version, latest_version):
            return {
                **base,
                "_ahead": True,
                "component": name,
                "current_version": version,
                "default_version": latest_version,
                "purl": purl_str,
                "severity": Severity.INFO.value,
                "message": (
                    f"Installed {version} is newer than the registry default "
                    f"{latest_version}. The registry may not have flagged this "
                    f"release as default yet."
                ),
            }

        # Version matches default — metadata only
        return base

    async def _check_component_for_batch(
        self, client: InstrumentedAsyncClient, component: Dict[str, Any]
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
                    latest = self._find_default_version(data.get("versions", []))
                    return latest if latest else ""
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

        return self._build_outdated_result(name, version, latest_version, purl_str, cache_key)
