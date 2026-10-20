import asyncio
import difflib
import itertools
import logging
from pathlib import Path
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

# npmHighImpact of wooorm/npm-high-impact, most downloaded first.
_NPM_RANKING = (Path(__file__).parent / "npm_high_impact.txt").read_text().split()


def _normalize_pkg_name(name: str | None) -> str:
    """PEP 503 name, with an npm ``@scope/`` stripped: the imitated target is the unscoped name."""
    if not name:
        return ""
    if name.startswith("@") and "/" in name:
        name = name.split("/", 1)[1]
    return pep503_normalize(name)


def _corpus(ranking: list[str]) -> tuple[set[str], list[str]]:
    # A component is compared with its scope stripped, so a scoped package's bare name is no imitation target.
    unscoped = (name for name in ranking if not name.startswith("@"))
    top = itertools.islice(unscoped, TYPOSQUATTING_POPULAR_PACKAGE_RANKS)
    return {pep503_normalize(name) for name in ranking}, [pep503_normalize(name) for name in top]


def _has_legitimate_prefix(longer: str, shorter: str) -> bool:
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
    name = "typosquatting"

    async def _ensure_popular_packages(self) -> dict[str, list[str]]:
        # Lock and wait outlast the 30 s fetch, so peers wait for the holder instead of re-downloading.
        pypi = await cache_service.get_or_fetch_with_lock(
            CacheKeys.popular_packages("pypi"),
            self._fetch_pypi_packages,
            CacheTTL.POPULAR_PACKAGES,
            lock_ttl_seconds=60,
            max_wait_seconds=35,
        )
        return {"pypi": pypi or sorted(_STATIC_PYPI_FALLBACK), "npm": _NPM_RANKING}

    async def _fetch_pypi_packages(self) -> list[str] | None:
        timeout = ANALYZER_TIMEOUTS["typosquatting"]
        try:
            # The corpus has moved host before; an unfollowed 301 leaves only the handful of built-in names.
            async with InstrumentedAsyncClient("PyPI API", timeout=timeout, follow_redirects=True) as client:
                resp = await client.get(TOP_PYPI_PACKAGES_URL)
            reason = f"HTTP {resp.status_code}"
            if resp.status_code == 200:
                packages = [row["project"] for row in resp.json().get("rows", [])]
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
        *,
        parsed_components: list[dict[str, Any]],
    ) -> dict[str, Any]:
        popular_packages = await self._ensure_popular_packages()
        settings = settings or {}
        issues = await asyncio.to_thread(
            self._scan_components,
            parsed_components,
            popular_packages,
            settings.get("similarity_threshold", TYPOSQUATTING_SIMILARITY_THRESHOLD),
            settings.get("critical_similarity", TYPOSQUATTING_CRITICAL_SIMILARITY),
            settings.get("high_similarity", TYPOSQUATTING_HIGH_SIMILARITY),
        )

        # Names near a package outside this corpus produce no finding, so the corpus travels with the result.
        return {
            "typosquatting_issues": issues,
            "popular_packages_compared": {
                ecosystem: min(len(names), TYPOSQUATTING_POPULAR_PACKAGE_RANKS)
                for ecosystem, names in sorted(popular_packages.items())
            },
        }

    def _scan_components(
        self,
        components: list[dict[str, Any]],
        popular_packages: dict[str, list[str]],
        similarity_threshold: float,
        critical_at: float,
        high_at: float,
    ) -> list[dict[str, Any]]:
        corpora = {ecosystem: _corpus(ranking) for ecosystem, ranking in popular_packages.items()}
        issues = []
        for component in components:
            parsed = parse_purl(component.get("purl") or "")
            ecosystem = parsed.registry_system if parsed else None
            corpus = corpora.get(ecosystem) if ecosystem else None
            if corpus is None:
                continue
            issue = self._scan_component(component, corpus, similarity_threshold, critical_at, high_at)
            if issue is not None:
                issues.append(issue)
        return issues

    def _scan_component(
        self,
        component: dict[str, Any],
        corpus: tuple[set[str], list[str]],
        similarity_threshold: float,
        critical_at: float,
        high_at: float,
    ) -> dict[str, Any] | None:
        full_name = pep503_normalize(component.get("name") or "")
        name = _normalize_pkg_name(full_name)
        if not name:
            return None

        known, top = corpus
        # The bare name of @myorg/axios would otherwise match axios itself.
        if full_name in known or name in known:
            return None

        matcher = difflib.SequenceMatcher(None, b=name)
        best_ratio, best_popular = similarity_threshold, None
        for popular in top:
            if abs(len(name) - len(popular)) > 2:
                continue
            # Both quick ratios bound ratio() from above in either orientation; ratio() itself is not symmetric.
            matcher.set_seq1(popular)
            if matcher.real_quick_ratio() <= best_ratio or matcher.quick_ratio() <= best_ratio:
                continue
            ratio = difflib.SequenceMatcher(None, name, popular).ratio()
            if ratio > best_ratio and self._is_suspicious(name, popular):
                best_ratio, best_popular = ratio, popular
        if best_popular is None:
            return None
        severity = _severity_for_ratio(best_ratio, critical_at, high_at)
        return _build_typosquat_issue(component, best_popular, best_ratio, severity)

    def _is_suspicious(self, name: str, popular: str) -> bool:
        return not (_has_legitimate_prefix(name, popular) or _has_legitimate_prefix(popular, name))
