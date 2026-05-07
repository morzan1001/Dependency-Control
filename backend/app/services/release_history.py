"""Upstream release-history analytics: cadence and adoption-latency math.

Pure analysis lives here. HTTP fetching from deps.dev plugs in via the
``ReleaseHistoryFetcher`` protocol so it can be swapped in tests.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol, Sequence, Tuple
from urllib.parse import quote

from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)


def _is_stable_release(version: str) -> bool:
    """True for X.Y.Z; False for alpha/beta/rc/dev pre-releases.

    Non-PEP-440 versions (calver, hashes) are treated as stable since
    there's no portable way to tell otherwise.
    """
    try:
        return not Version(version).is_prerelease
    except InvalidVersion:
        return True


def _stable_only(releases: Sequence[ReleaseInfo]) -> List[ReleaseInfo]:
    return [r for r in releases if _is_stable_release(r.version)]


@dataclass(frozen=True)
class ReleaseInfo:
    version: str
    published_at: datetime


ReleaseHistory = Dict[str, List[ReleaseInfo]]
Observation = Tuple[str, str, datetime]


@dataclass(frozen=True)
class UpstreamCadenceMetrics:
    upstream_releases_last_12m_median: Optional[float]
    upstream_days_between_releases_median: Optional[float]
    upstream_days_since_latest_release_median: Optional[float]
    adoption_latency_days_median: Optional[float]


class ReleaseHistoryFetcher(Protocol):
    """Loads release histories for a set of packages, with caching."""

    async def fetch(self, packages: Sequence[Tuple[str, str]]) -> ReleaseHistory: ...


def releases_in_last_n_days(
    releases: Sequence[ReleaseInfo],
    window_days: int,
    ref: datetime,
) -> int:
    """Count stable releases within ``window_days`` of ``ref``."""
    cutoff = ref - timedelta(days=window_days)
    return sum(1 for r in _stable_only(releases) if r.published_at >= cutoff)


def median_days_between_releases(releases: Sequence[ReleaseInfo]) -> Optional[float]:
    """Median gap (in days) between consecutive stable releases, or None if <2."""
    stable = _stable_only(releases)
    if len(stable) < 2:
        return None
    sorted_dates = sorted(r.published_at for r in stable)
    gaps = [
        (sorted_dates[i] - sorted_dates[i - 1]).total_seconds() / 86400.0
        for i in range(1, len(sorted_dates))
    ]
    return float(median(gaps))


def days_since_latest_release(
    releases: Sequence[ReleaseInfo],
    ref: datetime,
) -> Optional[int]:
    """Days between ``ref`` and the most recent stable release, or None if empty."""
    stable = _stable_only(releases)
    if not stable:
        return None
    return (ref - max(r.published_at for r in stable)).days


def compute_adoption_latencies(
    history: ReleaseHistory,
    observations: Sequence[Observation],
) -> List[int]:
    """Days between upstream publish and first observed scan, per (pkg, version).

    Observations whose version is missing from the history are skipped.
    """
    publish_lookup: Dict[Tuple[str, str], datetime] = {
        (pkg, r.version): r.published_at
        for pkg, releases in history.items()
        for r in releases
    }
    return [
        (scan_date - publish_lookup[(pkg, version)]).days
        for pkg, version, scan_date in observations
        if (pkg, version) in publish_lookup
    ]


def aggregate_upstream_metrics(
    history: ReleaseHistory,
    observations: Sequence[Observation],
    ref: Optional[datetime] = None,
) -> UpstreamCadenceMetrics:
    """Project-level aggregation: median across all packages with data."""
    ref = ref or datetime.now(tz=timezone.utc)

    if not history:
        return UpstreamCadenceMetrics(None, None, None, None)

    releases_counts: List[int] = []
    gap_medians: List[float] = []
    days_since: List[int] = []

    for releases in history.values():
        releases_counts.append(releases_in_last_n_days(releases, window_days=365, ref=ref))
        gap = median_days_between_releases(releases)
        if gap is not None:
            gap_medians.append(gap)
        latest = days_since_latest_release(releases, ref=ref)
        if latest is not None:
            days_since.append(latest)

    latencies = compute_adoption_latencies(history, observations)

    return UpstreamCadenceMetrics(
        upstream_releases_last_12m_median=float(median(releases_counts)) if releases_counts else None,
        upstream_days_between_releases_median=float(median(gap_medians)) if gap_medians else None,
        upstream_days_since_latest_release_median=float(median(days_since)) if days_since else None,
        adoption_latency_days_median=float(median(latencies)) if latencies else None,
    )


def parse_deps_dev_response(payload: Dict[str, Any]) -> List[ReleaseInfo]:
    """Translate a deps.dev GetPackage response into ReleaseInfo entries.

    Versions without a parsable ``publishedAt`` are dropped — keeping them
    would treat them as released at epoch 0.
    """
    out: List[ReleaseInfo] = []
    for entry in payload.get("versions", []) or []:
        version = (entry.get("versionKey") or {}).get("version")
        published_at_str = entry.get("publishedAt")
        if not version or not published_at_str:
            continue
        try:
            published_at = datetime.fromisoformat(published_at_str.replace("Z", "+00:00"))
            if published_at.tzinfo is None:
                published_at = published_at.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        out.append(ReleaseInfo(version=str(version), published_at=published_at))
    return out


CacheGet = Callable[[str], Awaitable[Optional[Any]]]
CacheSet = Callable[..., Awaitable[None]]
HttpFetch = Callable[[str], Awaitable[Optional[Dict[str, Any]]]]


class DepsDevReleaseHistoryFetcher:
    """Per-package release histories from deps.dev, cached. Hooks injected for testability."""

    def __init__(
        self,
        cache_get: CacheGet,
        cache_set: CacheSet,
        http_fetch: HttpFetch,
        cache_key_builder: Optional[Callable[[str, str], str]] = None,
        cache_ttl_seconds: int = 24 * 3600,
    ) -> None:
        self._cache_get = cache_get
        self._cache_set = cache_set
        self._http_fetch = http_fetch
        self._cache_key_builder = cache_key_builder or (lambda system, name: f"releases:{system}:{name}")
        self._cache_ttl = cache_ttl_seconds

    async def fetch(self, packages: Sequence[Tuple[str, str]]) -> ReleaseHistory:
        result: ReleaseHistory = {}
        for system, name in packages:
            releases = await self._load_one(system, name)
            if releases is not None:
                result[name] = releases
        return result

    async def _load_one(self, system: str, name: str) -> Optional[List[ReleaseInfo]]:
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
    return f"https://api.deps.dev/v3alpha/systems/{system}/packages/{quote(name, safe='')}"


def _release_list_to_cache(releases: Sequence[ReleaseInfo]) -> List[Dict[str, str]]:
    return [{"version": r.version, "published_at": r.published_at.isoformat()} for r in releases]


def _release_list_from_cache(raw: Any) -> List[ReleaseInfo]:
    if not isinstance(raw, list):
        return []
    out: List[ReleaseInfo] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        version = item.get("version")
        published_at_str = item.get("published_at")
        if not version or not published_at_str:
            continue
        try:
            published_at = datetime.fromisoformat(str(published_at_str))
            if published_at.tzinfo is None:
                published_at = published_at.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        out.append(ReleaseInfo(version=str(version), published_at=published_at))
    return out
