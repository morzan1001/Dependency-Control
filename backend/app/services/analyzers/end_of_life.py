import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, cast
from urllib.parse import quote

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.http_utils import InstrumentedAsyncClient
from app.core.constants import ANALYZER_TIMEOUTS, EOL_API_URL, NAME_TO_EOL_MAPPING
from app.models.finding import Severity

from .base import Analyzer

logger = logging.getLogger(__name__)


# Forward declarations of helpers used by the analyzer's analyze() loop.
def _resolve_eol_products(name: str, cpes: List[str]) -> Set[str]:
    """Translate an SBOM component into the set of endoflife.date product IDs to query.

    Tries CPE entries first (most precise) and falls back to NAME_TO_EOL_MAPPING
    or the component name as-is. Same logic the analyzer used inline; pulled
    out so the (product, version) collector below stays focused.
    """
    products = _extract_products_from_cpes_static(cpes)
    if products:
        return products
    mapped = NAME_TO_EOL_MAPPING.get(name)
    return {mapped} if mapped else {name}


def _extract_products_from_cpes_static(cpes: List[str]) -> Set[str]:
    """Stateless mirror of EndOfLifeAnalyzer._extract_products_from_cpes.

    Used by ``collect_products_to_check`` so the collector doesn't need an
    analyzer instance. Kept in sync with the method below by delegation.
    """
    return EndOfLifeAnalyzer._extract_products_from_cpes_impl(cpes)


def collect_products_to_check(
    components: List[Dict[str, Any]],
) -> Dict[str, List[Tuple[str, str]]]:
    """Build product -> [(component_name, version), ...] from raw SBOM components.

    Earlier the analyzer kept only one (name, version) per product, so a
    second component using the *same* product but a *different* version was
    silently skipped. The list-valued mapping ensures every (product,
    version) pair gets checked against the EOL dataset for that product.
    """
    out: Dict[str, List[Tuple[str, str]]] = {}
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
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        components = self._get_components(sbom, parsed_components)
        results = []

        # Configurable thresholds (defaults preserve existing behavior)
        settings = settings or {}
        self._high_after_days = int(settings.get("eol_high_after_days", 365))
        self._medium_after_days = int(settings.get("eol_medium_after_days", 180))

        # Collect all (product, component_name, version) triples. Multiple
        # components of the same product appear together so we can check each
        # version against the same EOL dataset (one HTTP call per product).
        products_to_check: Dict[str, List[Tuple[str, str]]] = collect_products_to_check(components)

        def _emit_for_versions(
            product: str, occurrences: List[Tuple[str, str]], cycles: List[Dict[str, Any]]
        ) -> None:
            """Apply ``cycles`` against every (component, version) we observed
            for ``product``, appending an EOL issue for each EOL match."""
            for comp_name, version in occurrences:
                eol_info = self._check_version(version, cycles)
                if eol_info:
                    results.append(self._create_eol_issue(comp_name, version, product, eol_info))

        # Check cache for all products first
        cache_keys = [CacheKeys.eol(product) for product in products_to_check.keys()]
        cached_data = await cache_service.mget(cache_keys) if cache_keys else {}

        products_to_fetch: List[str] = []
        for product, occurrences in products_to_check.items():
            cache_key = CacheKeys.eol(product)
            if cache_key in cached_data and cached_data[cache_key] is not None:
                cycles = cached_data[cache_key]
                if cycles:  # Not a negative cache entry
                    _emit_for_versions(product, occurrences, cycles)
            else:
                products_to_fetch.append(product)

        logger.debug(
            f"EOL: {len(products_to_check) - len(products_to_fetch)} from cache, {len(products_to_fetch)} to fetch"
        )

        # Fetch uncached products with distributed locking to prevent stampede
        if products_to_fetch:
            timeout = ANALYZER_TIMEOUTS.get("end_of_life", ANALYZER_TIMEOUTS["default"])
            async with InstrumentedAsyncClient("endoflife.date API", timeout=timeout) as client:
                for product in products_to_fetch:
                    cache_key = CacheKeys.eol(product)

                    async def fetch_eol_data(
                        prod: str = product, cli: InstrumentedAsyncClient = client
                    ) -> Optional[List[Dict[str, Any]]]:
                        """Fetch EOL data for a product."""
                        try:
                            safe_product = quote(prod, safe="")
                            response = await cli.get(f"{self.api_url}/{safe_product}.json")
                            if response.status_code == 200:
                                return cast(List[Dict[str, Any]], response.json())
                            elif response.status_code == 404:
                                return []  # Empty list = negative cache
                        except httpx.TimeoutException:
                            logger.debug(f"EOL API timeout for {prod}")
                        except httpx.ConnectError:
                            logger.debug(f"EOL API connection error for {prod}")
                        except Exception as e:
                            logger.debug(f"EOL check failed for {prod}: {e}")
                        return None

                    # Use locked fetch to prevent multiple pods fetching same product
                    cycles = await cache_service.get_or_fetch_with_lock(
                        key=cache_key,
                        fetch_fn=fetch_eol_data,
                        ttl_seconds=CacheTTL.EOL_STATUS,
                    )

                    if cycles:  # Non-empty list means we have EOL data
                        _emit_for_versions(product, products_to_check[product], cycles)

        return {"eol_issues": results}

    def _create_eol_issue(
        self,
        component: str,
        version: str,
        product: str,
        eol_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create an EOL issue with proper severity."""
        # Determine severity based on EOL status
        eol_date = eol_info.get("eol")
        if eol_date is True:
            # Already marked as EOL without specific date
            severity = Severity.HIGH.value
        elif isinstance(eol_date, str):
            try:
                eol_dt = datetime.strptime(eol_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                days_past_eol = (datetime.now(timezone.utc) - eol_dt).days
                high_after = getattr(self, "_high_after_days", 365)
                medium_after = getattr(self, "_medium_after_days", 180)
                # Inclusive boundaries: a package exactly `high_after` days past
                # EOL should be HIGH, not one tier below. The previous strictly-
                # greater-than comparison made the threshold name lie about its
                # behaviour (`eol_high_after_days=365` actually meant 366+).
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

    def _extract_products_from_cpes(self, cpes: List[str]) -> Set[str]:
        """Instance wrapper around the stateless implementation."""
        return self._extract_products_from_cpes_impl(cpes)

    @staticmethod
    def _extract_products_from_cpes_impl(cpes: List[str]) -> Set[str]:
        """Extract product names from CPE strings and map to endoflife.date IDs."""
        products: Set[str] = set()

        for cpe in cpes:
            # Standard CPE 2.3 (NIST):     cpe:2.3:a:vendor:product:...
            # Less common with leading /:  cpe:/2.3:a:vendor:product:...
            # Legacy CPE 2.2:              cpe:/a:vendor:product:...
            match = re.match(r"cpe:/?2\.3:a:([^:]+):([^:]+)", cpe)
            if not match:
                match = re.match(r"cpe:/a:([^:]+):([^:]+)", cpe)

            if match:
                vendor = match.group(1).lower()
                product = match.group(2).lower()

                # Try product directly
                if product in NAME_TO_EOL_MAPPING:
                    products.add(NAME_TO_EOL_MAPPING[product])
                # Try vendor:product combo
                elif f"{vendor}_{product}" in NAME_TO_EOL_MAPPING:
                    products.add(NAME_TO_EOL_MAPPING[f"{vendor}_{product}"])
                # Try just product name
                else:
                    products.add(product)

        return products

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

    def _check_version(self, version: str, cycles: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Check if a version matches an EOL cycle.

        If EOL, enriches the result with the latest active (non-EOL) version
        as a recommended upgrade target.
        """
        if not version:
            return None

        if not isinstance(version, str):
            version = str(version)

        clean_version = version.lstrip("v").lower()

        for cycle in cycles:
            cycle_version = str(cycle.get("cycle", ""))

            if not self._version_matches_cycle(clean_version, cycle_version):
                continue

            if self._is_eol(cycle.get("eol")):
                # Find the newest active (non-EOL) cycle as upgrade recommendation
                recommended = self._find_active_cycle(cycles)
                if recommended and recommended.get("latest") != cycle.get("latest"):
                    cycle["recommended_version"] = recommended.get("latest")
                    cycle["recommended_cycle"] = recommended.get("cycle")
                return cycle

        return None

    @staticmethod
    def _find_active_cycle(cycles: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
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

        # Direct match
        if version == cycle:
            return True

        # Version starts with cycle (e.g., "3.8.5" matches cycle "3.8")
        if version.startswith(f"{cycle}."):
            return True

        # Major version match (e.g., "3" matches "3.x")
        if "." in version:
            major = version.split(".")[0]
            if cycle == major:
                return True
            # Check major.minor match
            if version.count(".") >= 1:
                major_minor = ".".join(version.split(".")[:2])
                if cycle == major_minor:
                    return True

        return False
