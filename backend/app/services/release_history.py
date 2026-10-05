"""Upstream release-history analytics: cadence and adoption-latency math.

Pure analysis lives here. HTTP fetching from deps.dev plugs in via the
``ReleaseHistoryFetcher`` protocol so it can be swapped in tests.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any, Protocol
from urllib.parse import quote

from packaging.version import InvalidVersion, Version

from app.core import ensure_utc
from app.core.constants import DEPS_DEV_API_URL

logger = logging.getLogger(__name__)

# Bounded concurrency for per-package release-history fetches: high enough
# that the Redis cache hot-path is effectively a single round-trip across
# all packages, low enough that a cold cache doesn't blast deps.dev.
_FETCH_CONCURRENCY = 16

# Matched by token, not by any "-" suffix, because Maven qualifiers like Guava's 33.0.0-jre are releases.
_PRERELEASE_TAG = re.compile(
    r"[-.](alpha|beta|rc|pre|preview|dev|canary|next|nightly|experimental|snapshot|m\d+)(?![a-z])", re.IGNORECASE
)

# Strict-semver ecosystems mark every prerelease (Go pseudo-versions, npm "4.0.0-0") with "-" before any "+build".
_SEMVER_SYSTEMS = frozenset({"npm", "go", "cargo", "nuget"})


def _is_stable_release(version: str, system: str | None) -> bool:
    """True for X.Y.Z; False for pre-releases under the ecosystem's version scheme."""
    if system in _SEMVER_SYSTEMS:
        return "-" not in version.split("+", 1)[0]
    try:
        return not Version(version).is_prerelease
    except InvalidVersion:
        return _PRERELEASE_TAG.search(version) is None


@dataclass(frozen=True)
class ReleaseInfo:
    version: str
    published_at: datetime


# Keyed by ``(system, name)`` so same-named packages across ecosystems don't collide.
# A plain ``str`` key is treated as name-only (unknown system).
HistoryKey = str | tuple[str, str]
ReleaseHistory = dict[HistoryKey, list[ReleaseInfo]]

# ``(name, version, scan_date)`` or ecosystem-aware ``(system, name, version, scan_date)``:
# the 4-tuple disambiguates same-named packages across ecosystems, the 3-tuple matches name-only.
Observation = tuple[str, str, datetime] | tuple[str, str, str, datetime]


def _split_history_key(key: HistoryKey) -> tuple[str | None, str]:
    """Normalise a history key into ``(system, name)``; ``system`` is None for bare-name keys."""
    if isinstance(key, tuple):
        system, name = key
        return system, name
    return None, key


def _split_observation(obs: Observation) -> tuple[str | None, str, str, datetime]:
    """Normalise an observation into ``(system, name, version, scan_date)``.

    ``system`` is None for the 3-tuple ``(name, version, scan_date)`` form.
    """
    if len(obs) == 4:
        system, name, version, scan_date = obs
        return system, name, version, scan_date
    name, version, scan_date = obs
    return None, name, version, scan_date


@dataclass(frozen=True)
class UpstreamCadenceMetrics:
    upstream_releases_last_12m_median: float | None
    upstream_days_between_releases_median: float | None
    upstream_days_since_latest_release_median: float | None
    adoption_latency_days_median: float | None


class ReleaseHistoryFetcher(Protocol):
    """Loads release histories for a set of packages, with caching."""

    async def fetch(self, packages: Sequence[tuple[str, str]]) -> ReleaseHistory: ...


def releases_in_last_n_days(
    releases: Sequence[ReleaseInfo],
    window_days: int,
    ref: datetime,
) -> int:
    """Count releases within ``window_days`` of ``ref``."""
    cutoff = ref - timedelta(days=window_days)
    return sum(1 for r in releases if r.published_at >= cutoff)


def median_days_between_releases(releases: Sequence[ReleaseInfo]) -> float | None:
    """Median gap (in days) between consecutive releases, or None if <2."""
    if len(releases) < 2:
        return None
    sorted_dates = sorted(r.published_at for r in releases)
    gaps = [(sorted_dates[i] - sorted_dates[i - 1]).total_seconds() / 86400.0 for i in range(1, len(sorted_dates))]
    return float(median(gaps))


def days_since_latest_release(
    releases: Sequence[ReleaseInfo],
    ref: datetime,
) -> int:
    """Days between ``ref`` and the most recent of a non-empty ``releases``."""
    return (ref - max(r.published_at for r in releases)).days


def compute_adoption_latencies(
    history: ReleaseHistory,
    observations: Sequence[Observation],
) -> list[int]:
    """Days between upstream publish and first observed scan, per package/version.

    An ecosystem-aware observation matches its exact ``(system, name, version)`` release;
    a name-only observation matches on name+version. Observations whose version is missing
    from the history are skipped.
    """
    exact_lookup: dict[tuple[str, str, str], datetime] = {}
    name_lookup: dict[tuple[str, str], datetime] = {}
    for key, releases in history.items():
        system, name = _split_history_key(key)
        for r in releases:
            if system is not None:
                exact_lookup[(system, name, r.version)] = r.published_at
            # Name-only fallback for system-less callers; last write wins on a name collision.
            name_lookup[(name, r.version)] = r.published_at

    latencies: list[int] = []
    for obs in observations:
        system, name, version, scan_date = _split_observation(obs)
        published_at: datetime | None = None
        if system is not None:
            published_at = exact_lookup.get((system, name, version))
        if published_at is None:
            published_at = name_lookup.get((name, version))
        if published_at is not None:
            latencies.append((scan_date - published_at).days)
    return latencies


def aggregate_upstream_metrics(
    history: ReleaseHistory,
    observations: Sequence[Observation],
    ref: datetime | None = None,
) -> UpstreamCadenceMetrics:
    """Project-level aggregation: median across all packages with data."""
    ref = ref or datetime.now(tz=timezone.utc)

    if not history:
        return UpstreamCadenceMetrics(None, None, None, None)

    releases_counts: list[int] = []
    gap_medians: list[float] = []
    days_since: list[int] = []

    for key, releases in history.items():
        system, _ = _split_history_key(key)
        stable = [r for r in releases if _is_stable_release(r.version, system)]
        if not stable:
            continue
        releases_counts.append(releases_in_last_n_days(stable, window_days=365, ref=ref))
        gap = median_days_between_releases(stable)
        if gap is not None:
            gap_medians.append(gap)
        days_since.append(days_since_latest_release(stable, ref=ref))

    latencies = compute_adoption_latencies(history, observations)

    return UpstreamCadenceMetrics(
        upstream_releases_last_12m_median=float(median(releases_counts)) if releases_counts else None,
        upstream_days_between_releases_median=float(median(gap_medians)) if gap_medians else None,
        upstream_days_since_latest_release_median=float(median(days_since)) if days_since else None,
        adoption_latency_days_median=float(median(latencies)) if latencies else None,
    )


def parse_deps_dev_response(payload: dict[str, Any]) -> list[ReleaseInfo]:
    """Translate a deps.dev GetPackage response into ReleaseInfo entries.

    Versions without a parsable ``publishedAt`` are dropped — keeping them
    would treat them as released at epoch 0.
    """
    out: list[ReleaseInfo] = []
    for entry in payload.get("versions", []) or []:
        version = (entry.get("versionKey") or {}).get("version")
        published_at_str = entry.get("publishedAt")
        if not version or not published_at_str:
            continue
        try:
            published_at = ensure_utc(datetime.fromisoformat(published_at_str.replace("Z", "+00:00")))
        except ValueError:
            continue
        out.append(ReleaseInfo(version=str(version), published_at=published_at))
    return out


CacheGet = Callable[[str], Awaitable[Any | None]]
CacheSet = Callable[..., Awaitable[None]]
HttpFetch = Callable[[str], Awaitable[dict[str, Any] | None]]


class DepsDevReleaseHistoryFetcher:
    """Per-package release histories from deps.dev, cached. Hooks injected for testability."""

    def __init__(
        self,
        cache_get: CacheGet,
        cache_set: CacheSet,
        http_fetch: HttpFetch,
        cache_key_builder: Callable[[str, str], str],
        cache_ttl_seconds: int,
    ) -> None:
        self._cache_get = cache_get
        self._cache_set = cache_set
        self._http_fetch = http_fetch
        self._cache_key_builder = cache_key_builder
        self._cache_ttl = cache_ttl_seconds

    async def fetch(self, packages: Sequence[tuple[str, str]]) -> ReleaseHistory:
        if not packages:
            return {}

        semaphore = asyncio.Semaphore(_FETCH_CONCURRENCY)

        async def _bounded(system: str, name: str) -> tuple[tuple[str, str], list[ReleaseInfo] | None]:
            async with semaphore:
                # Key by (system, name): two packages sharing a bare name across
                # ecosystems must not overwrite each other in the result dict.
                return (system, name), await self._load_one(system, name)

        pairs = await asyncio.gather(*(_bounded(s, n) for s, n in packages))
        return {key: releases for key, releases in pairs if releases}

    async def _load_one(self, system: str, name: str) -> list[ReleaseInfo] | None:
        key = self._cache_key_builder(system, name)
        cached = await self._cache_get(key)
        if cached is not None:
            return _release_list_from_cache(cached)

        payload = await self._http_fetch(_build_deps_dev_url(system, name))
        if payload is None:
            return None

        releases = parse_deps_dev_response(payload)
        try:
            await self._cache_set(key, _release_list_to_cache(releases), ttl_seconds=self._cache_ttl)
        except Exception:
            logger.debug("Cache set failed for release history (%s/%s)", system, name, exc_info=True)
        return releases


def _build_deps_dev_url(system: str, name: str) -> str:
    return f"{DEPS_DEV_API_URL}/systems/{system}/packages/{quote(name, safe='')}"


def _release_list_to_cache(releases: Sequence[ReleaseInfo]) -> list[dict[str, str]]:
    return [{"version": r.version, "published_at": r.published_at.isoformat()} for r in releases]


def _release_list_from_cache(raw: Any) -> list[ReleaseInfo]:
    if not isinstance(raw, list):
        return []
    out: list[ReleaseInfo] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        version = item.get("version")
        published_at_str = item.get("published_at")
        if not version or not published_at_str:
            continue
        try:
            published_at = ensure_utc(datetime.fromisoformat(str(published_at_str)))
        except ValueError:
            continue
        out.append(ReleaseInfo(version=str(version), published_at=published_at))
    return out
