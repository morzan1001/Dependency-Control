import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple
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
    """Strict ``<`` via ``packaging.Version``; falls back to string inequality on InvalidVersion."""
    try:
        return Version(current) < Version(latest)
    except InvalidVersion:
        return current != latest


def _is_ahead_of(current: str, latest: str) -> bool:
    """Strict ``>``; covers cases where the install is newer than deps.dev's default."""
    try:
        return Version(current) > Version(latest)
    except InvalidVersion:
        return False


def is_version_withdrawn(versions_info: List[Any], target_version: str) -> bool:
    """True iff ``target_version`` is present and marked ``isWithdrawn`` in the deps.dev payload.

    Strips a leading ``v`` so ``v1.0.0`` matches ``1.0.0`` in the response.
    """
    target = target_version.lstrip("v") if target_version else ""
    if not target:
        return False
    for entry in versions_info or []:
        version_key = entry.get("versionKey") or {}
        if version_key.get("version") == target:
            return bool(entry.get("isWithdrawn"))
    return False


class OutdatedAnalyzer(Analyzer):
    """Outdated / ahead-of-default / yanked detection via deps.dev.

    Each package document is fetched at most once per scan; its default version and
    isWithdrawn flags drive all three classifications from that single fetch.
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
        yanked: List[Dict[str, Any]] = []

        # Resolve one deps.dev document per distinct package, then classify every component
        # against it (keyed by package so multiple installed versions each get classified).
        package_infos = await self._resolve_package_infos(components)

        for component in components:
            parsed = parse_purl(component.get("purl", ""))
            if not parsed or not parsed.registry_system:
                continue

            info = package_infos.get(
                CacheKeys.latest_version(parsed.registry_system, parsed.deps_dev_name)
            )
            if not info:
                continue

            default_version = info.get("default")
            if default_version:
                self._classify_version(component, default_version, outdated, ahead)

            yanked_finding = self._build_yanked_finding(component, info.get("withdrawn") or [])
            if yanked_finding is not None:
                yanked.append(yanked_finding)

        return {
            "outdated_dependencies": outdated,
            "ahead_of_default": ahead,
            "yanked_versions": yanked,
        }

    async def _resolve_package_infos(
        self, components: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """Return ``{cache_key: {"default": str|None, "withdrawn": [str, ...]}}``.

        Warm entries come from a batched ``mget``; misses are fetched concurrently with a
        distributed lock, so each package document is requested at most once.
        """
        # Dedupe by cache key so a package at several versions is fetched only once.
        key_targets: Dict[str, Tuple[str, str]] = {}
        skipped_count = 0

        for component in components:
            parsed = parse_purl(component.get("purl", ""))
            if not parsed or not parsed.registry_system:
                skipped_count += 1
                continue
            cache_key = CacheKeys.latest_version(parsed.registry_system, parsed.deps_dev_name)
            key_targets.setdefault(cache_key, (parsed.registry_system, parsed.deps_dev_name))

        if skipped_count > 0:
            logger.debug(f"Outdated: Skipped {skipped_count} components without valid registry system")

        if not key_targets:
            return {}

        infos: Dict[str, Dict[str, Any]] = {}
        missing: List[str] = []

        cached_data: Dict[str, Any] = await cache_service.mget(list(key_targets.keys()))
        for cache_key in key_targets:
            normalized = self._normalize_cached_info(cached_data.get(cache_key))
            if normalized is None:
                missing.append(cache_key)
            else:
                infos[cache_key] = normalized

        logger.debug(f"Outdated: {len(infos)} packages from cache, {len(missing)} to fetch")

        if missing:
            await self._fetch_missing_infos(missing, key_targets, infos)

        return infos

    @staticmethod
    def _normalize_cached_info(value: Any) -> Optional[Dict[str, Any]]:
        """Coerce a cached value into a package-info dict.

        ``None`` means the key is absent (needs fetching); an empty dict is a negative cache.
        A bare string is a legacy cache entry holding just the version.
        """
        if value is None:
            return None
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            # Legacy entries stored just the latest version string ("" = negative).
            if not value:
                return {}
            return {"default": value, "withdrawn": []}
        return {}

    async def _fetch_missing_infos(
        self,
        missing_keys: List[str],
        key_targets: Dict[str, Tuple[str, str]],
        infos: Dict[str, Dict[str, Any]],
    ) -> None:
        """Fetch package documents for uncached packages, concurrently in batches."""
        timeout = ANALYZER_TIMEOUTS.get("outdated", ANALYZER_TIMEOUTS["default"])
        batch_size = ANALYZER_BATCH_SIZES.get("outdated", 25)

        async with InstrumentedAsyncClient("deps.dev API", timeout=timeout) as client:
            for i in range(0, len(missing_keys), batch_size):
                batch = missing_keys[i : i + batch_size]
                tasks = [
                    self._fetch_package_info(client, cache_key, *key_targets[cache_key])
                    for cache_key in batch
                ]
                results: List[Any] = await asyncio.gather(*tasks, return_exceptions=True)

                for cache_key, result in zip(batch, results):
                    if isinstance(result, Exception) or result is None:
                        # Transient failure this scan: treat as "no signal".
                        infos[cache_key] = {}
                    else:
                        infos[cache_key] = result

                # Small delay between batches to avoid rate limits.
                if i + batch_size < len(missing_keys):
                    await asyncio.sleep(0.1)

    async def _fetch_package_info(
        self,
        client: InstrumentedAsyncClient,
        cache_key: str,
        system: str,
        deps_dev_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Fetch (once, cached, lock-protected) a package's default + withdrawn versions."""

        async def fetch() -> Optional[Dict[str, Any]]:
            data = await self._get_package_document(client, system, deps_dev_name)
            if data is None:
                return None
            if not data:
                return {}  # Negative cache for "package not found".
            versions = data.get("versions", [])
            return {
                "default": self._find_default_version(versions),
                "withdrawn": self._collect_withdrawn_versions(versions),
            }

        # Distributed lock prevents multiple pods fetching the same package.
        info = await cache_service.get_or_fetch_with_lock(
            key=cache_key,
            fetch_fn=fetch,
            ttl_seconds=CacheTTL.LATEST_VERSION,
        )
        return self._normalize_cached_info(info)

    async def _get_package_document(
        self,
        client: InstrumentedAsyncClient,
        system: str,
        deps_dev_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Return the raw deps.dev package document.

        ``None`` signals a transient failure (skip this scan); an empty dict
        signals a definitive "not found" (safe to negative-cache).
        """
        url = f"{self.base_url}/{system}/packages/{quote(deps_dev_name, safe='')}"
        try:
            response = await client.get(url, follow_redirects=True)
            if response.status_code != 200:
                return {}
            return response.json()
        except (httpx.TimeoutException, httpx.ConnectError):
            logger.debug(f"Timeout/connection error checking outdated for {deps_dev_name}")
            return None
        except Exception as e:
            logger.debug(f"Error checking outdated for {deps_dev_name}: {e}")
            return None

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

        if not version:
            return

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

    def _build_yanked_finding(
        self, component: Dict[str, Any], withdrawn_versions: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Return a finding dict if the component's installed version was withdrawn, else None."""
        version = component.get("version", "")
        purl_str = component.get("purl", "")
        if not version or not purl_str or not withdrawn_versions:
            return None

        if version.lstrip("v") not in withdrawn_versions:
            return None

        return {
            "component": component.get("name", ""),
            "current_version": version,
            "purl": purl_str,
            "severity": Severity.HIGH.value,
            "message": (
                f"Version {version} was withdrawn from the registry. "
                "Installations should be replaced with a non-yanked release."
            ),
        }

    def _find_default_version(self, versions_info: List[Any]) -> Optional[str]:
        """Find the version marked as default (usually the latest stable)."""
        for v in versions_info:
            if v.get("isDefault"):
                version = v.get("versionKey", {}).get("version")
                return str(version) if version is not None else None
        return None

    @staticmethod
    def _collect_withdrawn_versions(versions_info: List[Any]) -> List[str]:
        """Collect the version strings marked ``isWithdrawn`` in a deps.dev payload."""
        return [
            v
            for entry in versions_info or []
            if entry.get("isWithdrawn") and (v := (entry.get("versionKey") or {}).get("version", ""))
        ]
