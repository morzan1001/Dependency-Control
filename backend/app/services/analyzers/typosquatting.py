import difflib
import logging
import re
from typing import Any, Dict, List, Optional, Set

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.http_utils import InstrumentedAsyncClient
from app.core.constants import (
    ANALYZER_TIMEOUTS,
    TOP_PYPI_PACKAGES_URL,
    TYPOSQUATTING_MAX_FALLBACK_PACKAGES,
    TYPOSQUATTING_SIMILARITY_THRESHOLD,
)
from app.models.finding import Severity

from .base import Analyzer
from .purl_utils import is_npm, is_pypi

logger = logging.getLogger(__name__)


_SEPARATOR_RUN = re.compile(r"[-_.]+")
_SEPARATORS = {"-", "_", "."}


def _normalize_pkg_name(name: Optional[str]) -> str:
    """Normalize a package name for typosquat comparison.

    - Strips an npm scope (``@scope/pkg`` → ``pkg``); typosquatting
      targets the unscoped name.
    - Collapses runs of ``- _ .`` to a single ``-`` (PEP 503 for PyPI;
      a reasonable approximation for npm) so ``python_dateutil`` and
      ``python.dateutil`` compare equal to ``python-dateutil``.
    - Lowercases.
    """
    if not name:
        return ""
    if name.startswith("@") and "/" in name:
        name = name.split("/", 1)[1]
    name = _SEPARATOR_RUN.sub("-", name)
    return name.lower()


def _has_legitimate_prefix(longer: str, shorter: str) -> bool:
    """True if ``longer`` extends ``shorter`` with a real separator afterwards.

    Catches the suffix-bypass: ``expresss`` starts with ``express`` but the
    next char (``s``) is not a separator, so we should *not* treat the pair
    as legitimate (it's the typosquat we want to flag). ``react-dom`` is
    fine because it adds ``-dom``.
    """
    if not longer or not shorter or longer == shorter:
        return False
    if not longer.startswith(shorter):
        return False
    next_char = longer[len(shorter)]
    return next_char in _SEPARATORS


def _resolve_ecosystem(component: Dict[str, Any], purl: str) -> str:
    """Map a component to ``pypi`` / ``npm`` / ``unknown`` from PURL or type."""
    if is_pypi(purl) or component.get("type") == "python":
        return "pypi"
    if is_npm(purl) or component.get("type") == "npm":
        return "npm"
    return "unknown"


def _severity_for_ratio(ratio: float, critical_at: float, high_at: float) -> str:
    """Map a similarity ratio onto a typosquat severity tier."""
    if ratio > critical_at:
        return Severity.CRITICAL.value
    if ratio > high_at:
        return Severity.HIGH.value
    return Severity.MEDIUM.value


def _build_typosquat_issue(
    component: Dict[str, Any],
    popular: str,
    ratio: float,
    severity: str,
) -> Dict[str, Any]:
    """Construct the user-facing finding dict for a flagged typosquat."""
    name = component.get("name")
    return {
        "component": name,
        "version": component.get("version"),
        "purl": component.get("purl", ""),
        "imitated_package": popular,
        "similarity": round(ratio, 2),
        "severity": severity,
        "message": (
            f"Potential typosquatting: '{name}' "
            f"is similar to popular package '{popular}'"
        ),
    }


class TyposquattingAnalyzer(Analyzer):
    """
    Analyzer that detects potential typosquatting attacks by comparing
    package names against a list of popular packages.

    Uses Redis cache for the popular packages list across all pods.
    """

    name = "typosquatting"

    # In-memory fallback cache
    _popular_packages_fallback: Dict[str, Set[str]] = {"pypi": set(), "npm": set()}

    async def _ensure_popular_packages(self) -> Dict[str, Set[str]]:
        """Load popular packages from Redis cache or fetch from APIs."""

        # Try Redis cache first
        pypi_cache_key = CacheKeys.popular_packages("pypi")
        npm_cache_key = CacheKeys.popular_packages("npm")

        cached_data = await cache_service.mget([pypi_cache_key, npm_cache_key])

        pypi_packages = cached_data.get(pypi_cache_key)
        npm_packages = cached_data.get(npm_cache_key)

        result: Dict[str, set] = {"pypi": set(), "npm": set()}

        # Load PyPI packages
        if pypi_packages:
            result["pypi"] = set(pypi_packages)
            logger.debug(f"Loaded {len(result['pypi'])} PyPI packages from Redis cache")
        else:
            result["pypi"] = await self._fetch_pypi_packages()

        # Load npm packages (we use static list)
        if npm_packages:
            result["npm"] = set(npm_packages)
            logger.debug(f"Loaded {len(result['npm'])} npm packages from Redis cache")
        else:
            result["npm"] = self._get_static_npm()
            # Cache npm packages
            await cache_service.set(npm_cache_key, list(result["npm"]), CacheTTL.POPULAR_PACKAGES)

        # Update fallback with size limit to prevent memory issues
        for registry in result:
            if len(result[registry]) > TYPOSQUATTING_MAX_FALLBACK_PACKAGES:
                # Keep only a subset if too large
                result[registry] = set(list(result[registry])[:TYPOSQUATTING_MAX_FALLBACK_PACKAGES])
        self._popular_packages_fallback = result
        return result

    async def _fetch_pypi_packages(self) -> Set[str]:
        """Fetch top PyPI packages and cache in Redis."""
        cache_key = CacheKeys.popular_packages("pypi")
        timeout = ANALYZER_TIMEOUTS.get("typosquatting", ANALYZER_TIMEOUTS["default"])

        try:
            async with InstrumentedAsyncClient("PyPI API", timeout=timeout) as client:
                resp = await client.get(TOP_PYPI_PACKAGES_URL)
                if resp.status_code == 200:
                    data = resp.json()
                    packages = {row["project"].lower() for row in data.get("rows", [])[:5000]}
                    # Cache in Redis
                    await cache_service.set(cache_key, list(packages), CacheTTL.POPULAR_PACKAGES)
                    logger.info(f"Loaded {len(packages)} popular PyPI packages (cached in Redis)")
                    return packages
        except httpx.TimeoutException:
            logger.debug("Timeout fetching PyPI top packages, using fallback")
        except httpx.ConnectError:
            logger.debug("Connection error fetching PyPI top packages, using fallback")
        except Exception as e:
            logger.debug(f"Failed to fetch PyPI top packages: {type(e).__name__}")

        # Fallback to static list
        packages = self._get_static_pypi()
        await cache_service.set(cache_key, list(packages), CacheTTL.POPULAR_PACKAGES)
        return packages

    def _get_static_pypi(self) -> Set[str]:
        return {
            "requests",
            "flask",
            "django",
            "numpy",
            "pandas",
            "boto3",
            "urllib3",
            "botocore",
            "typing-extensions",
            "python-dateutil",
            "setuptools",
            "pip",
            "wheel",
            "certifi",
            "idna",
            "charset-normalizer",
            "aiohttp",
            "pydantic",
            "fastapi",
            "uvicorn",
            "sqlalchemy",
            "pytest",
            "docker",
            "kubernetes",
        }

    def _get_static_npm(self) -> Set[str]:
        return {
            "react",
            "react-dom",
            "lodash",
            "express",
            "axios",
            "moment",
            "tslib",
            "commander",
            "chalk",
            "debug",
            "inquirer",
            "async",
            "bluebird",
            "uuid",
            "classnames",
            "prop-types",
            "vue",
            "angular",
            "next",
            "webpack",
            "eslint",
            "prettier",
            "babel",
            "jest",
            "rxjs",
            "yargs",
            "body-parser",
            "cors",
            "dotenv",
            "jsonwebtoken",
            "mongoose",
            "socket.io",
            "redis",
            "aws-sdk",
            "typescript",
            "fs-extra",
            "mkdirp",
            "glob",
            "minimist",
        }

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        popular_packages = await self._ensure_popular_packages()

        components = self._get_components(sbom, parsed_components)
        issues = []

        # Configurable thresholds (defaults preserve existing behavior)
        settings = settings or {}
        similarity_threshold = float(settings.get("similarity_threshold", TYPOSQUATTING_SIMILARITY_THRESHOLD))
        critical_at = float(settings.get("critical_similarity", 0.95))
        high_at = float(settings.get("high_similarity", 0.90))

        # Per-ecosystem normalised popular set, computed lazily so we only
        # pay the cost when at least one component actually maps to it.
        normalized_popular: Dict[str, Set[str]] = {}

        for component in components:
            issue = self._scan_component(
                component,
                popular_packages,
                normalized_popular,
                similarity_threshold,
                critical_at,
                high_at,
            )
            if issue is not None:
                issues.append(issue)

        return {"typosquatting_issues": issues}

    def _scan_component(
        self,
        component: Dict[str, Any],
        popular_packages: Dict[str, Set[str]],
        normalized_popular: Dict[str, Set[str]],
        similarity_threshold: float,
        critical_at: float,
        high_at: float,
    ) -> Optional[Dict[str, Any]]:
        """Return a typosquat finding for ``component``, or ``None`` if clean."""
        purl = component.get("purl", "")
        ecosystem = _resolve_ecosystem(component, purl)
        if ecosystem not in popular_packages:
            return None

        name = _normalize_pkg_name(component.get("name", ""))
        if not name:
            return None

        if ecosystem not in normalized_popular:
            normalized_popular[ecosystem] = {
                _normalize_pkg_name(p) for p in popular_packages[ecosystem]
            }
        popular_list = normalized_popular[ecosystem]

        if name in popular_list:
            return None

        for popular in popular_list:
            if abs(len(name) - len(popular)) > 2:
                continue
            ratio = difflib.SequenceMatcher(None, name, popular).ratio()
            if ratio <= similarity_threshold:
                continue
            if not self._is_suspicious(name, popular):
                continue
            severity = _severity_for_ratio(ratio, critical_at, high_at)
            return _build_typosquat_issue(component, popular, ratio, severity)
        return None

    def _is_suspicious(self, name: str, popular: str) -> bool:
        """Check if a package name is suspiciously similar to a popular package.

        Note: Length difference check is already done in analyze() before calling this.

        Prefix relationships are only considered legitimate when the prefix
        is followed by a separator (``-``/``_``/``.``). Otherwise an
        attacker could bypass the check by appending letters — ``expresss``
        starts with ``express`` but is exactly the typosquat we want to
        flag, while ``react-dom`` is a real sub-package.
        """
        if name == popular:
            return False
        if _has_legitimate_prefix(name, popular) or _has_legitimate_prefix(popular, name):
            return False
        return True
