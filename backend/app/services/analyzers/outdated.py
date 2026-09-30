import logging
from typing import Any
from urllib.parse import quote

from packaging.version import InvalidVersion, Version

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import ANALYZER_BATCH_SIZES, ANALYZER_TIMEOUTS, DEPS_DEV_API_URL
from app.core.http_utils import InstrumentedAsyncClient
from app.models.finding import Severity
from app.schemas.sbom import has_known_version

from .base import Analyzer, gather_bounded
from .deps_dev import fetch_deps_dev_json
from app.core.purl import parse_purl

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


async def fetch_package_info(client: InstrumentedAsyncClient, system: str, deps_dev_name: str) -> dict[str, Any] | None:
    """A package's deps.dev default version and its publish date, fetched once and cached; a failure raises."""

    async def fetch() -> dict[str, Any] | None:
        url = f"{DEPS_DEV_API_URL}/systems/{system}/packages/{quote(deps_dev_name, safe='')}"
        document = await fetch_deps_dev_json(client, url)
        if document is None:
            return None
        default: dict[str, Any] = next((v for v in document.get("versions", []) if v.get("isDefault")), {})
        return {"default": default.get("versionKey", {}).get("version"), "published_at": default.get("publishedAt")}

    info: dict[str, Any] | None = await cache_service.get_or_fetch_with_lock(
        key=CacheKeys.latest_version(system, deps_dev_name),
        fetch_fn=fetch,
        ttl_seconds=CacheTTL.LATEST_VERSION,
        reraise_fetch_errors=True,
    )
    return info


class OutdatedAnalyzer(Analyzer):
    """Outdated and ahead-of-default detection against deps.dev's default version, cached once per package."""

    name = "outdated_packages"

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        components = parsed_components or []
        outdated: list[dict[str, Any]] = []
        ahead: list[dict[str, Any]] = []
        skipped = 0

        # One deps.dev document per distinct package; every installed version is classified against it.
        infos = await self._resolve_package_infos(components)

        for component, info in zip(components, infos, strict=True):
            if isinstance(info, BaseException):
                skipped += 1
            elif info and info.get("default"):
                self._classify_version(component, info["default"], outdated, ahead)

        result: dict[str, Any] = {"outdated_dependencies": outdated, "ahead_of_default": ahead}
        if skipped:
            result["partial_components_skipped"] = skipped
        return result

    @staticmethod
    def _package_target(component: dict[str, Any]) -> tuple[str, str, str] | None:
        """``(cache key, deps.dev system, deps.dev name)`` of a component deps.dev can compare by version."""
        parsed = parse_purl(component.get("purl", ""))
        if not parsed or not parsed.deps_dev_system or not has_known_version(component.get("version", "")):
            return None
        system, name = parsed.deps_dev_system, parsed.deps_dev_name
        return CacheKeys.latest_version(system, name), system, name

    async def _resolve_package_infos(
        self, components: list[dict[str, Any]]
    ) -> list[dict[str, Any] | BaseException | None]:
        """Each component's ``{"default": str | None}``, its failed lookup, or None; aligned with ``components``."""
        targets = [self._package_target(component) for component in components]
        skipped_count = targets.count(None)
        if skipped_count > 0:
            logger.debug(f"Outdated: Skipped {skipped_count} components deps.dev cannot compare")

        # Dedupe by cache key so a package at several versions is fetched only once.
        key_targets = {target[0]: (target[1], target[2]) for target in targets if target}
        cached: dict[str, Any] = await cache_service.mget(list(key_targets))
        infos: dict[str, Any] = {key: info for key, info in cached.items() if info is not None}
        missing = [key for key in key_targets if key not in infos]
        logger.debug(f"Outdated: {len(infos)} packages from cache, {len(missing)} to fetch")

        if missing:
            timeout = ANALYZER_TIMEOUTS.get("outdated", ANALYZER_TIMEOUTS["default"])
            async with InstrumentedAsyncClient("deps.dev API", timeout=timeout) as client:
                fetched = await gather_bounded(
                    missing,
                    lambda cache_key: fetch_package_info(client, *key_targets[cache_key]),
                    ANALYZER_BATCH_SIZES["outdated"],
                )
            infos.update(zip(missing, fetched, strict=True))

        return [infos.get(target[0]) if target else None for target in targets]

    def _classify_version(
        self,
        component: dict[str, Any],
        latest_version: str,
        outdated: list[dict[str, Any]],
        ahead: list[dict[str, Any]],
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
