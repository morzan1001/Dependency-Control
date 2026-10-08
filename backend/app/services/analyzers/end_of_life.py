import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import (
    ANALYZER_BATCH_SIZES,
    ANALYZER_TIMEOUTS,
    EOL_API_URL,
    EOL_HIGH_AFTER_DAYS,
    EOL_MEDIUM_AFTER_DAYS,
    NAME_TO_EOL_MAPPING,
    SERVER_NAME_TO_EOL_MAPPING,
)
from app.core.http_utils import InstrumentedAsyncClient, gather_bounded
from app.core.purl import get_purl_type, is_os_package_type
from app.models.finding import Severity

from .base import Analyzer

# endoflife.date's product list lives at the URL a product named "all" would have, so that name is never looked up.
_PRODUCT_INDEX = "all"

# os-release ids and Trivy OS families that are no endoflife.date slug; npm "ol" (OpenLayers) keeps them out of
# NAME_TO_EOL_MAPPING.
_OS_ALIASES = {
    "amzn": "amazon-linux",
    "amazon": "amazon-linux",
    "ol": "oracle-linux",
    "oracle": "oracle-linux",
    "opensuse-leap": "opensuse",
    "opensuse.leap": "opensuse",
    "redhat": "rhel",
    "rocky": "rocky-linux",
    "alma": "almalinux",
}

# Syft guesses CPEs from the package name (pypi redis -> python:redis); Java and Go servers ship as jars and modules.
_CLIENT_REGISTRIES = frozenset({"npm", "pypi", "gem", "cargo", "nuget", "composer"})
_SERVER_PRODUCTS = frozenset(SERVER_NAME_TO_EOL_MAPPING.values())

_CPE_APPLICATION_PRODUCT = re.compile(r"cpe:(?:/?2\.3:|/)a:[^:]+:([^:]+)")
_VERSION_DECORATION = re.compile(r"^(?:\d+:|go(?=\d)|v(?=\d))")
# Debian, Ubuntu, RHEL/Fedora and Amazon rebuilds: the distribution backports fixes until its own end of life.
_DISTRO_REBUILD = re.compile(r"[+~]deb\d+u\d|\+b\d+$|ubuntu\d|\.el\d|\+el\d|\.fc\d|\.amzn\d")


def _mapped_products(key: str) -> set[str]:
    target = NAME_TO_EOL_MAPPING.get(key, key)
    return {target} if isinstance(target, str) else set(target)


def _resolve_eol_products(component: dict[str, Any]) -> set[str]:
    """A component's candidate endoflife.date products: its CPE products and mapped name, else the bare name."""
    name = (component.get("name") or "").lower()
    purl_type = get_purl_type(component.get("purl"))
    products: set[str] = set()
    for cpe in component.get("cpes") or []:
        if match := _CPE_APPLICATION_PRODUCT.match(cpe):
            products |= _mapped_products(match[1].replace("\\", "").lower().replace("_", "-"))
    if name in NAME_TO_EOL_MAPPING:
        products |= _mapped_products(name)
    if component.get("type") == "operating-system" and name in _OS_ALIASES:
        products.add(_OS_ALIASES[name])
    if name == "stdlib" and purl_type == "golang":
        products.add("go")
    products = products or {name}
    return products - _SERVER_PRODUCTS if purl_type in _CLIENT_REGISTRIES else products


def collect_products_to_check(components: list[dict[str, Any]]) -> dict[str, list[tuple[str, str, bool]]]:
    """Build ``product -> [(component_name, version, distro_build), ...]``; each version is checked on its own."""
    out: dict[str, list[tuple[str, str, bool]]] = {}
    for component in components:
        version = component.get("version") or ""
        distro_build = is_os_package_type(component.get("purl"), component.get("type")) and bool(
            _DISTRO_REBUILD.search(version)
        )
        entry = (component.get("name") or "", version, distro_build)
        for product in _resolve_eol_products(component):
            bucket = out.setdefault(product, [])
            if entry not in bucket:
                bucket.append(entry)
    return out


def _parse_eol_date(eol: Any) -> datetime | None:
    try:
        return datetime.strptime(eol, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _version_matches_cycle(version: str, cycle: str) -> bool:
    """A version belongs to a cycle it equals or continues with a non-digit, so 1.1.1w is in 1.1.1 but 1.1.10 is not."""
    return bool(cycle) and version.startswith(cycle) and not version[len(cycle) : len(cycle) + 1].isdigit()


def _check_version(version: str, cycles: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The most specific cycle the version belongs to (LTS wins a tie), if that cycle is end-of-life."""
    comparable = _VERSION_DECORATION.sub("", version.strip().lower())
    matching = [c for c in cycles if _version_matches_cycle(comparable, str(c.get("cycle", "")).lower())]
    if not matching:
        return None
    cycle = min(matching, key=lambda c: (-len(str(c.get("cycle", ""))), not c.get("lts")))
    eol = cycle.get("eol")
    eol_date = _parse_eol_date(eol)
    return cycle if eol is True or (eol_date is not None and eol_date < datetime.now(timezone.utc)) else None


def _find_active_cycle(cycles: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The first still-supported cycle; endoflife.date lists the newest first."""
    now = datetime.now(timezone.utc)
    for cycle in cycles:
        eol = cycle.get("eol")
        if eol is False or eol is None or ((eol_date := _parse_eol_date(eol)) is not None and eol_date > now):
            return cycle
    return None


async def _fetch_list(client: InstrumentedAsyncClient, product: str, item_type: type) -> list[Any]:
    """``/api/<product>.json`` when it is a list of ``item_type``; [] for an unknown product or another shape."""
    response = await client.get(f"{EOL_API_URL}/{quote(product, safe='')}.json")
    if response.status_code == 404:
        return []
    response.raise_for_status()
    data = response.json()
    return data if isinstance(data, list) and all(isinstance(item, item_type) for item in data) else []


class EndOfLifeAnalyzer(Analyzer):
    name = "end_of_life"
    _high_after_days = EOL_HIGH_AFTER_DAYS
    _medium_after_days = EOL_MEDIUM_AFTER_DAYS

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        self._apply_settings(settings)
        products_to_check = collect_products_to_check(parsed_components or [])
        if not products_to_check:
            return {"eol_issues": []}

        # Upstream renames answer 301; following them keeps a renamed product covered.
        async with InstrumentedAsyncClient(
            "endoflife.date API", timeout=ANALYZER_TIMEOUTS["end_of_life"], follow_redirects=True
        ) as client:

            async def cached_list(product: str, item_type: type) -> Any:
                return await cache_service.get_or_fetch_with_lock(
                    key=CacheKeys.eol(product),
                    fetch_fn=lambda: _fetch_list(client, product, item_type),
                    ttl_seconds=CacheTTL.EOL_STATUS,
                )

            index = await cached_list(_PRODUCT_INDEX, str)
            # Without the index every candidate is looked up directly, which costs requests but no findings.
            known = set(index) if isinstance(index, list) and index else set(products_to_check) - {_PRODUCT_INDEX}
            products = [product for product in products_to_check if product in known]
            cycle_lists = await gather_bounded(
                products, lambda product: cached_list(product, dict), ANALYZER_BATCH_SIZES["end_of_life"]
            )

        results = []
        skipped: set[str] = set()
        for product, cycles in zip(products, cycle_lists, strict=True):
            if not isinstance(cycles, list):
                skipped.update(component for component, _, _ in products_to_check[product])
                continue
            recommended = _find_active_cycle(cycles)
            for component, version, distro_build in products_to_check[product]:
                if (cycle := _check_version(version, cycles)) is not None:
                    results.append(
                        self._create_eol_issue(component, version, product, cycle, recommended, distro_build)
                    )
        output: dict[str, Any] = {"eol_issues": results}
        if skipped:
            output["partial_components_skipped"] = len(skipped)
        return output

    def _apply_settings(self, settings: dict[str, Any] | None) -> None:
        """Bind this project's thresholds to this run's instance."""
        s = settings or {}
        self._high_after_days = s.get("eol_high_after_days", EOL_HIGH_AFTER_DAYS)
        self._medium_after_days = s.get("eol_medium_after_days", EOL_MEDIUM_AFTER_DAYS)

    def _create_eol_issue(
        self,
        component: str,
        version: str,
        product: str,
        cycle: dict[str, Any],
        recommended: dict[str, Any] | None,
        distro_build: bool,
    ) -> dict[str, Any]:
        """Grade by days past the cycle's EOL date; a distro rebuild stays LOW and gets no upstream upgrade."""
        eol_date = _parse_eol_date(cycle.get("eol"))
        # No date means endoflife.date marks the cycle end-of-life with ``eol: true``.
        days_past = (datetime.now(timezone.utc) - eol_date).days if eol_date else None
        if distro_build:
            severity = Severity.LOW
        elif days_past is None or days_past >= self._high_after_days:
            severity = Severity.HIGH
        elif days_past >= self._medium_after_days:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        eol_info = dict(cycle)
        if recommended and not distro_build and recommended.get("latest") != cycle.get("latest"):
            eol_info["recommended_version"] = recommended.get("latest")
            eol_info["recommended_cycle"] = recommended.get("cycle")
        return {
            "component": component,
            "version": version,
            "product": product,
            "severity": severity.value,
            "eol_info": eol_info,
            "distro_build": distro_build,
        }
