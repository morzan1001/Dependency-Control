import logging
import re
from datetime import datetime, timezone
from typing import Any, cast
from urllib.parse import quote

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import ANALYZER_TIMEOUTS, EOL_API_URL, NAME_TO_EOL_MAPPING
from app.core.http_utils import InstrumentedAsyncClient
from app.models.finding import Severity

from .base import Analyzer

logger = logging.getLogger(__name__)


def _extract_products_from_cpes(cpes: list[str]) -> set[str]:
    """Map CPE strings to endoflife.date product IDs (accepts cpe:2.3:a:, cpe:/2.3:a:, and legacy cpe:/a:)."""
    products: set[str] = set()
    for cpe in cpes:
        match = re.match(r"cpe:/?2\.3:a:([^:]+):([^:]+)", cpe) or re.match(r"cpe:/a:([^:]+):([^:]+)", cpe)
        if not match:
            continue
        vendor = match.group(1).lower()
        product = match.group(2).lower()
        if product in NAME_TO_EOL_MAPPING:
            products.add(NAME_TO_EOL_MAPPING[product])
        elif f"{vendor}_{product}" in NAME_TO_EOL_MAPPING:
            products.add(NAME_TO_EOL_MAPPING[f"{vendor}_{product}"])
        else:
            products.add(product)
    return products


def _resolve_eol_products(name: str, cpes: list[str]) -> set[str]:
    """Map a component to endoflife.date product IDs (CPEs first, then name)."""
    products = _extract_products_from_cpes(cpes)
    if products:
        return products
    mapped = NAME_TO_EOL_MAPPING.get(name)
    return {mapped} if mapped else {name}


def collect_products_to_check(
    components: list[dict[str, Any]],
) -> dict[str, list[tuple[str, str]]]:
    """Build ``product -> [(component_name, version), ...]``; each version is checked independently."""
    out: dict[str, list[tuple[str, str]]] = {}
    for component in components:
        name = component.get("name", "").lower()
        version = component.get("version", "")
        cpes = component.get("cpes") or component.get("_cpes") or []

        for product in _resolve_eol_products(name, cpes):
            entry = (component.get("name") or "", version)
            bucket = out.setdefault(product, [])
            if entry not in bucket:
                bucket.append(entry)
    return out


class EndOfLifeAnalyzer(Analyzer):
    name = "end_of_life"
    api_url = EOL_API_URL

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        components = self._get_components(sbom, parsed_components)
        self._apply_settings(settings)

        products_to_check: dict[str, list[tuple[str, str]]] = collect_products_to_check(components)
        if not products_to_check:
            return {"eol_issues": []}

        results: list[dict[str, Any]] = []
        cached_cycles, products_to_fetch = await self._partition_by_cache(products_to_check)

        for product, cycles in cached_cycles.items():
            self._emit_for_versions(product, products_to_check[product], cycles, results)

        if products_to_fetch:
            await self._fetch_and_emit(products_to_fetch, products_to_check, results)

        return {"eol_issues": results}

    def _apply_settings(self, settings: dict[str, Any] | None) -> None:
        """Stash configurable thresholds on the instance."""
        s = settings or {}
        self._high_after_days = int(s.get("eol_high_after_days", 365))
        self._medium_after_days = int(s.get("eol_medium_after_days", 180))

    def _emit_for_versions(
        self,
        product: str,
        occurrences: list[tuple[str, str]],
        cycles: list[dict[str, Any]],
        results: list[dict[str, Any]],
    ) -> None:
        """Append an EOL issue for each (component, version) of ``product`` that matches an EOL cycle."""
        for comp_name, version in occurrences:
            eol_info = self._check_version(version, cycles)
            if eol_info:
                results.append(self._create_eol_issue(comp_name, version, product, eol_info))

    async def _partition_by_cache(
        self,
        products_to_check: dict[str, list[tuple[str, str]]],
    ) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
        """Split products into already-cached cycles and ones we still have to fetch."""
        cache_keys = [CacheKeys.eol(product) for product in products_to_check]
        cached_data = await cache_service.mget(cache_keys) if cache_keys else {}

        cached_cycles: dict[str, list[dict[str, Any]]] = {}
        to_fetch: list[str] = []
        for product in products_to_check:
            cache_key = CacheKeys.eol(product)
            value = cached_data.get(cache_key)
            if value is None:
                to_fetch.append(product)
                continue
            if value:  # Non-empty list = real EOL data; empty list = negative cache.
                cached_cycles[product] = value
        logger.debug(f"EOL: {len(cached_cycles)} from cache, {len(to_fetch)} to fetch")
        return cached_cycles, to_fetch

    async def _fetch_and_emit(
        self,
        products_to_fetch: list[str],
        products_to_check: dict[str, list[tuple[str, str]]],
        results: list[dict[str, Any]],
    ) -> None:
        """Fetch missing products from endoflife.date and emit issues for each."""
        timeout = ANALYZER_TIMEOUTS.get("end_of_life", ANALYZER_TIMEOUTS["default"])
        async with InstrumentedAsyncClient("endoflife.date API", timeout=timeout) as client:
            for product in products_to_fetch:
                cycles = await cache_service.get_or_fetch_with_lock(
                    key=CacheKeys.eol(product),
                    fetch_fn=self._make_fetch_fn(product, client),
                    ttl_seconds=CacheTTL.EOL_STATUS,
                )
                if cycles:
                    self._emit_for_versions(product, products_to_check[product], cycles, results)

    def _make_fetch_fn(
        self,
        product: str,
        client: InstrumentedAsyncClient,
    ) -> Any:
        """Build the closure ``cache_service`` calls on a miss for ``product``."""

        async def fetch_eol_data() -> list[dict[str, Any]] | None:
            try:
                safe_product = quote(product, safe="")
                response = await client.get(f"{self.api_url}/{safe_product}.json")
                if response.status_code == 200:
                    return cast(list[dict[str, Any]], response.json())
                if response.status_code == 404:
                    return []  # negative cache
            except httpx.TimeoutException:
                logger.debug(f"EOL API timeout for {product}")
            except httpx.ConnectError:
                logger.debug(f"EOL API connection error for {product}")
            except Exception as e:
                logger.debug(f"EOL check failed for {product}: {e}")
            return None

        return fetch_eol_data

    def _create_eol_issue(
        self,
        component: str,
        version: str,
        product: str,
        eol_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Build an EOL finding with severity scaled by days past the EOL date."""
        eol_date = eol_info.get("eol")
        if eol_date is True:
            severity = Severity.HIGH.value
        elif isinstance(eol_date, str):
            try:
                eol_dt = datetime.strptime(eol_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                days_past_eol = (datetime.now(timezone.utc) - eol_dt).days
                high_after = getattr(self, "_high_after_days", 365)
                medium_after = getattr(self, "_medium_after_days", 180)
                if days_past_eol >= high_after:
                    severity = Severity.HIGH.value
                elif days_past_eol >= medium_after:
                    severity = Severity.MEDIUM.value
                else:
                    severity = Severity.LOW.value
            except ValueError:
                severity = Severity.MEDIUM.value
        else:
            severity = Severity.MEDIUM.value

        return {
            "component": component,
            "version": version,
            "product": product,
            "severity": severity,
            "eol_info": eol_info,
            "message": f"Component {product} version {version} has reached end-of-life",
        }

    _extract_products_from_cpes = staticmethod(_extract_products_from_cpes)

    @staticmethod
    def _is_eol(eol: Any) -> bool:
        """Check if an EOL value indicates end-of-life status."""
        if eol is True:
            return True
        if not eol or eol is False:
            return False
        try:
            eol_date = datetime.strptime(str(eol), "%Y-%m-%d").replace(tzinfo=timezone.utc)
            return eol_date < datetime.now(timezone.utc)
        except ValueError:
            return False

    def _check_version(self, version: str, cycles: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Match a version to its most-specific EOL cycle (LTS wins ties); if EOL, add the recommended upgrade cycle."""
        if not version:
            return None

        if not isinstance(version, str):
            version = str(version)

        clean_version = version.lstrip("v").lower()

        # Rank by (specificity desc, LTS desc, original-order asc) for determinism.
        matches: list[tuple[int, int, int, dict[str, Any]]] = []
        for idx, cycle in enumerate(cycles):
            cycle_version = str(cycle.get("cycle", ""))
            if not self._version_matches_cycle(clean_version, cycle_version):
                continue
            lts_score = 1 if cycle.get("lts") else 0
            matches.append((-len(cycle_version), -lts_score, idx, cycle))

        if not matches:
            return None
        matches.sort()
        best_cycle = matches[0][3]

        if not self._is_eol(best_cycle.get("eol")):
            return None

        recommended = self._find_active_cycle(cycles)
        if recommended and recommended.get("latest") != best_cycle.get("latest"):
            best_cycle["recommended_version"] = recommended.get("latest")
            best_cycle["recommended_cycle"] = recommended.get("cycle")
        return best_cycle

    @staticmethod
    def _find_active_cycle(cycles: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Find the newest active (non-EOL) cycle from the list."""
        for cycle in cycles:
            eol = cycle.get("eol")
            if eol is False or eol is None:
                return cycle
            if isinstance(eol, str):
                try:
                    eol_date = datetime.strptime(eol, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    if eol_date > datetime.now(timezone.utc):
                        return cycle
                except ValueError:
                    continue
        return None

    def _version_matches_cycle(self, version: str, cycle: str) -> bool:
        """Check if a version belongs to a cycle."""
        if not version or not cycle:
            return False

        if version == cycle:
            return True

        if version.startswith(f"{cycle}."):
            return True

        if "." in version:
            major = version.split(".")[0]
            if cycle == major:
                return True
            if version.count(".") >= 1:
                major_minor = ".".join(version.split(".")[:2])
                if cycle == major_minor:
                    return True

        return False
