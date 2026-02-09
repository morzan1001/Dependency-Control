import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from urllib.parse import quote

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.http_utils import InstrumentedAsyncClient
from app.core.constants import ANALYZER_TIMEOUTS, EOL_API_URL, NAME_TO_EOL_MAPPING
from app.models.finding import Severity

from .base import Analyzer

logger = logging.getLogger(__name__)


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

        # Collect all unique products to check
        products_to_check: Dict[str, tuple] = {}  # product -> (component_name, version)

        for component in components:
            name = component.get("name", "").lower()
            version = component.get("version", "")
            cpes = component.get("cpes") or component.get("_cpes") or []

            eol_products = self._extract_products_from_cpes(cpes)
            if not eol_products:
                mapped = NAME_TO_EOL_MAPPING.get(name)
                if mapped:
                    eol_products.add(mapped)
                else:
                    eol_products.add(name)

            for product in eol_products:
                if product not in products_to_check:
                    products_to_check[product] = (component.get("name"), version)

        # Check cache for all products first
        cache_keys = [CacheKeys.eol(product) for product in products_to_check.keys()]
        cached_data = await cache_service.mget(cache_keys) if cache_keys else {}

        products_to_fetch = []
        for product, (comp_name, version) in products_to_check.items():
            cache_key = CacheKeys.eol(product)
            if cache_key in cached_data and cached_data[cache_key] is not None:
                cycles = cached_data[cache_key]
                if cycles:  # Not a negative cache entry
                    eol_info = self._check_version(version, cycles)
                    if eol_info:
                        results.append(self._create_eol_issue(comp_name, version, product, eol_info))
            else:
                products_to_fetch.append((product, comp_name, version))

        logger.debug(
            f"EOL: {len(products_to_check) - len(products_to_fetch)} from cache, {len(products_to_fetch)} to fetch"
        )

        # Fetch uncached products with distributed locking to prevent stampede
        if products_to_fetch:
            timeout = ANALYZER_TIMEOUTS.get("end_of_life", ANALYZER_TIMEOUTS["default"])
            async with InstrumentedAsyncClient("endoflife.date API", timeout=timeout) as client:
                for product, comp_name, version in products_to_fetch:
                    cache_key = CacheKeys.eol(product)

                    async def fetch_eol_data(
                        prod: str = product, cli: InstrumentedAsyncClient = client
                    ) -> Optional[List[Dict[str, Any]]]:
                        """Fetch EOL data for a product."""
                        try:
                            safe_product = quote(prod, safe="")
                            response = await cli.get(f"{self.api_url}/{safe_product}.json")
                            if response.status_code == 200:
                                return response.json()
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
                        eol_info = self._check_version(version, cycles)
                        if eol_info:
                            results.append(self._create_eol_issue(comp_name, version, product, eol_info))

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
                if days_past_eol > 365:
                    severity = Severity.HIGH.value
                elif days_past_eol > 180:
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
        """Extract product names from CPE strings and map to endoflife.date IDs."""
        products = set()

        for cpe in cpes:
            # CPE format: cpe:2.3:a:vendor:product:version:...
            # or cpe:/a:vendor:product:version:...
            match = re.match(r"cpe:[:/]2\.3:a:([^:]+):([^:]+)", cpe)
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

    def _check_version(self, version: str, cycles: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Check if a version matches an EOL cycle."""
        if not version:
            return None

        # Ensure version is a string before calling string methods
        if not isinstance(version, str):
            version = str(version)

        # Clean version string
        clean_version = version.lstrip("v").lower()

        for cycle in cycles:
            cycle_version = str(cycle.get("cycle", ""))

            # Check various matching strategies
            if self._version_matches_cycle(clean_version, cycle_version):
                eol = cycle.get("eol")

                # eol can be: date string, True (already EOL), False (not EOL)
                if eol is True:
                    return cycle
                elif eol and eol is not False:
                    try:
                        eol_date = datetime.strptime(str(eol), "%Y-%m-%d").replace(tzinfo=timezone.utc)
                        if eol_date < datetime.now(timezone.utc):
                            return cycle
                    except ValueError:
                        pass
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
