import difflib
import logging
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

        for component in components:
            name = component.get("name", "").lower()
            purl = component.get("purl", "")

            # Determine ecosystem using centralized utils
            ecosystem = "unknown"
            if is_pypi(purl) or component.get("type") == "python":
                ecosystem = "pypi"
            elif is_npm(purl) or component.get("type") == "npm":
                ecosystem = "npm"

            if ecosystem not in popular_packages:
                continue

            popular_list = popular_packages[ecosystem]

            # If the package itself is in the popular list, it's likely fine
            if name in popular_list:
                continue

            # Check against popular packages
            for popular in popular_list:
                # Optimization: Skip if length difference is too big
                if abs(len(name) - len(popular)) > 2:
                    continue

                # Calculate similarity
                ratio = difflib.SequenceMatcher(None, name, popular).ratio()

                if ratio > TYPOSQUATTING_SIMILARITY_THRESHOLD:
                    if self._is_suspicious(name, popular):
                        # Higher similarity = more suspicious
                        if ratio > 0.95:
                            severity = Severity.CRITICAL.value
                        elif ratio > 0.90:
                            severity = Severity.HIGH.value
                        else:
                            severity = Severity.MEDIUM.value

                        issues.append(
                            {
                                "component": component.get("name"),
                                "version": component.get("version"),
                                "purl": purl,
                                "imitated_package": popular,
                                "similarity": round(ratio, 2),
                                "severity": severity,
                                "message": (
                                    f"Potential typosquatting: '{component.get('name')}' "
                                    f"is similar to popular package '{popular}'"
                                ),
                            }
                        )

        return {"typosquatting_issues": issues}

    def _is_suspicious(self, name: str, popular: str) -> bool:
        """Check if a package name is suspiciously similar to a popular package.

        Note: Length difference check is already done in analyze() before calling this.
        """
        # Not a prefix/suffix (e.g. "react-dom" vs "react" is fine)
        if name.startswith(popular) or popular.startswith(name):
            return False

        return True
