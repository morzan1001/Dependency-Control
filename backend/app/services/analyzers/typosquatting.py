import difflib
import logging
from typing import Any

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import (
    ANALYZER_TIMEOUTS,
    TOP_PYPI_PACKAGES_URL,
    TYPOSQUATTING_CRITICAL_SIMILARITY,
    TYPOSQUATTING_HIGH_SIMILARITY,
    TYPOSQUATTING_POPULAR_PACKAGE_RANKS,
    TYPOSQUATTING_SIMILARITY_THRESHOLD,
)
from app.core.http_utils import InstrumentedAsyncClient
from app.models.finding import Severity

from .base import Analyzer
from app.core.purl import parse_purl, pep503_normalize

logger = logging.getLogger(__name__)


_STATIC_PYPI_FALLBACK = frozenset(
    {
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
)

_STATIC_NPM_PACKAGES = frozenset(
    {
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
)


def _normalize_pkg_name(name: str | None) -> str:
    """PEP 503 name, with an npm ``@scope/`` stripped: the imitated target is the unscoped name."""
    if not name:
        return ""
    if name.startswith("@") and "/" in name:
        name = name.split("/", 1)[1]
    return pep503_normalize(name)


def _has_legitimate_prefix(longer: str, shorter: str) -> bool:
    """True if ``longer`` extends ``shorter`` after a separator (``react-dom`` yes, ``expresss`` no)."""
    return longer.startswith(shorter + "-")


def _severity_for_ratio(ratio: float, critical_at: float, high_at: float) -> str:
    if ratio > critical_at:
        return Severity.CRITICAL.value
    if ratio > high_at:
        return Severity.HIGH.value
    return Severity.MEDIUM.value


def _build_typosquat_issue(
    component: dict[str, Any],
    popular: str,
    ratio: float,
    severity: str,
) -> dict[str, Any]:
    name = component.get("name")
    similarity = round(ratio, 2)
    return {
        "component": name,
        "version": component.get("version"),
        "purl": component.get("purl", ""),
        "imitated_package": popular,
        "similarity": similarity,
        "severity": severity,
        "message": (
            f"Possible typosquatting detected! '{name}' is {similarity * 100:.1f}% similar to popular package '{popular}'"
        ),
    }


class TyposquattingAnalyzer(Analyzer):
    """Detects typosquatting by comparing package names against the popular packages of their ecosystem."""

    name = "typosquatting"

    async def _ensure_popular_packages(self) -> dict[str, set[str]]:
        """PyPI's cached top-package ranking (built-in names while it is unavailable) and the npm constant."""
        # Lock and wait outlast the 30 s fetch, so peers wait for the holder instead of re-downloading.
        pypi = await cache_service.get_or_fetch_with_lock(
            CacheKeys.popular_packages("pypi"),
            self._fetch_pypi_packages,
            CacheTTL.POPULAR_PACKAGES,
            lock_ttl_seconds=60,
            max_wait_seconds=35,
        )
        return {"pypi": set(pypi or _STATIC_PYPI_FALLBACK), "npm": set(_STATIC_NPM_PACKAGES)}

    async def _fetch_pypi_packages(self) -> list[str] | None:
        """The top PyPI package names, or None when the ranking cannot be read."""
        timeout = ANALYZER_TIMEOUTS.get("typosquatting", ANALYZER_TIMEOUTS["default"])
        try:
            # The corpus has moved host before, and a 301 that is not followed leaves the
            # detector comparing against the handful of built-in names.
            async with InstrumentedAsyncClient("PyPI API", timeout=timeout, follow_redirects=True) as client:
                resp = await client.get(TOP_PYPI_PACKAGES_URL)
            reason = f"HTTP {resp.status_code}"
            if resp.status_code == 200:
                rows = resp.json().get("rows", [])[:TYPOSQUATTING_POPULAR_PACKAGE_RANKS]
                packages = sorted({row["project"].lower() for row in rows})
                if packages:
                    logger.info(f"Loaded {len(packages)} popular PyPI packages")
                    return packages
                reason = "empty corpus"
        except Exception as e:
            reason = type(e).__name__

        # A corpus this small is a detector that finds almost nothing, so it is not a debug note.
        logger.warning(
            "PyPI popular-package corpus unavailable (%s); comparing against %d built-in names instead of %d ranks",
            reason,
            len(_STATIC_PYPI_FALLBACK),
            TYPOSQUATTING_POPULAR_PACKAGE_RANKS,
        )
        return None

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        popular_packages = await self._ensure_popular_packages()

        components = parsed_components or []
        issues = []

        settings = settings or {}
        similarity_threshold = float(settings.get("similarity_threshold", TYPOSQUATTING_SIMILARITY_THRESHOLD))
        critical_at = float(settings.get("critical_similarity", TYPOSQUATTING_CRITICAL_SIMILARITY))
        high_at = float(settings.get("high_similarity", TYPOSQUATTING_HIGH_SIMILARITY))

        normalized_popular: dict[str, set[str]] = {}  # lazy per-ecosystem cache

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

        # A name similar to a package outside this corpus produces no finding, so the corpus
        # the comparison ran against travels with the result.
        return {
            "typosquatting_issues": issues,
            "popular_packages_compared": {
                ecosystem: len(names) for ecosystem, names in sorted(popular_packages.items())
            },
        }

    def _scan_component(
        self,
        component: dict[str, Any],
        popular_packages: dict[str, set[str]],
        normalized_popular: dict[str, set[str]],
        similarity_threshold: float,
        critical_at: float,
        high_at: float,
    ) -> dict[str, Any] | None:
        """Return a typosquat finding for ``component``, or ``None`` if clean."""
        parsed = parse_purl(component.get("purl") or "")
        ecosystem = parsed.registry_system if parsed else None
        if ecosystem not in popular_packages:
            return None

        name = _normalize_pkg_name(component.get("name", ""))
        if not name:
            return None

        if ecosystem not in normalized_popular:
            normalized_popular[ecosystem] = {_normalize_pkg_name(p) for p in popular_packages[ecosystem]}
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
        """Whether ``name`` near-matches another ``popular``; a prefix then ``-`` (``react-dom``) is legitimate."""
        return not (_has_legitimate_prefix(name, popular) or _has_legitimate_prefix(popular, name))
