import logging
from typing import Any
from urllib.parse import quote

from packaging.version import InvalidVersion, Version

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import ANALYZER_BATCH_SIZES, ANALYZER_TIMEOUTS, DEPS_DEV_API_URL
from app.core.http_utils import InstrumentedAsyncClient
from app.models.finding import Severity
from app.schemas.sbom import has_known_version
from app.services.aggregation.versions import is_stable_release, parse_version_key

from .base import Analyzer
from .deps_dev import fetch_deps_dev_json
from app.core.purl import parse_purl

logger = logging.getLogger(__name__)


def _is_older_than(current: str, latest: str) -> bool:
    try:
        return Version(current) < Version(latest)
    except InvalidVersion:
        return current != latest


def _is_ahead_of(current: str, latest: str) -> bool:
    try:
        return Version(current) > Version(latest)
    except InvalidVersion:
        return False


def _version(entry: dict[str, Any]) -> str:
    return str(entry.get("versionKey", {}).get("version") or "")


def _newest_stable(versions: list[dict[str, Any]], default: dict[str, Any], system: str) -> dict[str, Any]:
    """deps.dev flags Maven's highest version as default, pre-release or not."""
    if is_stable_release(_version(default), system):
        return default
    stable = [v for v in versions if not v.get("isDeprecated") and is_stable_release(_version(v), system)]
    return max(stable, key=lambda v: parse_version_key(_version(v)), default=default)


async def _fetch_package_info(
    client: InstrumentedAsyncClient, system: str, deps_dev_name: str
) -> dict[str, Any] | None:
    url = f"{DEPS_DEV_API_URL}/systems/{system}/packages/{quote(deps_dev_name, safe='')}"
    document = await fetch_deps_dev_json(client, url)
    if document is None:
        return None
    versions: list[dict[str, Any]] = document.get("versions", [])
    default: dict[str, Any] = next((v for v in versions if v.get("isDefault")), {})
    stable = _newest_stable(versions, default, system)
    return {"default": _version(default), "stable": _version(stable), "published_at": stable.get("publishedAt")}


async def fetch_package_info(client: InstrumentedAsyncClient, system: str, deps_dev_name: str) -> dict[str, Any] | None:
    info: dict[str, Any] | None = await cache_service.get_or_fetch_with_lock(
        key=CacheKeys.latest_version(system, deps_dev_name),
        fetch_fn=lambda: _fetch_package_info(client, system, deps_dev_name),
        ttl_seconds=CacheTTL.LATEST_VERSION,
        reraise_fetch_errors=True,
    )
    return info


class OutdatedAnalyzer(Analyzer):
    name = "outdated_packages"

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        *,
        parsed_components: list[dict[str, Any]],
    ) -> dict[str, Any]:
        outdated: list[dict[str, Any]] = []
        ahead: list[dict[str, Any]] = []
        failed: list[str] = []

        infos = await self._resolve_package_infos(parsed_components)

        for component, info in zip(parsed_components, infos, strict=True):
            if isinstance(info, BaseException):
                failed.append(component.get("name", ""))
            elif info and info.get("default"):
                self._classify_version(component, info, outdated, ahead)

        result: dict[str, Any] = {"outdated_dependencies": outdated, "ahead_of_default": ahead}
        if failed:
            result["partial_components_skipped"] = len(failed)
            result["lookup_failed_components"] = sorted(set(failed))
        return result

    @staticmethod
    def _latest_for(component: dict[str, Any], info: dict[str, Any]) -> str:
        """A pre-release install compares against the default, which may be a pre-release itself."""
        parsed = parse_purl(component.get("purl", ""))
        system = parsed.deps_dev_system if parsed else None
        installed_stable = is_stable_release(component.get("version", ""), system or "")
        return str(info["stable"] if installed_stable else info["default"])

    @staticmethod
    def _package_target(component: dict[str, Any]) -> tuple[str, str, str] | None:
        parsed = parse_purl(component.get("purl", ""))
        if not parsed or not parsed.deps_dev_system or not has_known_version(component.get("version", "")):
            return None
        system, name = parsed.deps_dev_system, parsed.deps_dev_name
        return CacheKeys.latest_version(system, name), system, name

    async def _resolve_package_infos(
        self, components: list[dict[str, Any]]
    ) -> list[dict[str, Any] | BaseException | None]:
        targets = [self._package_target(component) for component in components]
        skipped_count = targets.count(None)
        if skipped_count > 0:
            logger.debug(f"Outdated: Skipped {skipped_count} components deps.dev cannot compare")

        # Dedupe by cache key so a package at several versions is fetched only once.
        key_targets = {target[0]: (target[1], target[2]) for target in targets if target}
        async with InstrumentedAsyncClient("deps.dev API", timeout=ANALYZER_TIMEOUTS["outdated"]) as client:
            infos = await cache_service.get_many_or_fetch(
                key_targets,
                lambda key: _fetch_package_info(client, *key_targets[key]),
                CacheTTL.LATEST_VERSION,
                ANALYZER_BATCH_SIZES["outdated"],
            )
        return [infos.get(target[0]) if target else None for target in targets]

    def _classify_version(
        self,
        component: dict[str, Any],
        info: dict[str, Any],
        outdated: list[dict[str, Any]],
        ahead: list[dict[str, Any]],
    ) -> None:
        latest_version = self._latest_for(component, info)
        default_version = str(info["default"])
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
            compared = (
                f"the registry default {latest_version}. The registry may not have flagged this release as default yet."
                if latest_version == default_version
                else f"the newest stable release {latest_version} the registry lists."
            )
            ahead.append(
                {
                    "component": name,
                    "current_version": version,
                    "default_version": default_version,
                    "latest_version": latest_version,
                    "purl": purl,
                    "severity": Severity.INFO.value,
                    "message": f"Installed {version} is newer than {compared}",
                }
            )
