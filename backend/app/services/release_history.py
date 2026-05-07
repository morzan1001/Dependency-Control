"""Upstream release-history analytics.

The Update-Frequency report measures *team update velocity* (how often the
team bumps versions between scans). That number is shaped as much by the
team's scan cadence as by the underlying ecosystem. To complement it, this
module computes *upstream release cadence* — how often the upstream packages
themselves are released — plus *adoption latency*, the gap between an
upstream release and the team adopting it.

The pure math lives here; HTTP fetching from deps.dev is a follow-up that
plugs into the ``ReleaseHistoryFetcher`` protocol.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol, Sequence, Tuple
from urllib.parse import quote

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ReleaseInfo:
    """Single release of a package, as reported by the registry."""

    version: str
    published_at: datetime


# Map of package name -> chronologically arbitrary list of releases.
ReleaseHistory = Dict[str, List[ReleaseInfo]]

# An "observation" is a tuple (package_name, version, scan_date_seen) — the
# moment the platform first saw this version in a project's scan history.
Observation = Tuple[str, str, datetime]


@dataclass(frozen=True)
class UpstreamCadenceMetrics:
    """Aggregated upstream-cadence numbers for a single project."""

    upstream_releases_last_12m_median: Optional[float]
    upstream_days_between_releases_median: Optional[float]
    upstream_days_since_latest_release_median: Optional[float]
    adoption_latency_days_median: Optional[float]


class ReleaseHistoryFetcher(Protocol):
    """Loads release histories for a set of packages.

    Implementations call out to ecosystem registries (deps.dev today) and
    cache aggressively — release lists rarely change, so 24h+ TTL is fine.
    """

    async def fetch(self, packages: Sequence[Tuple[str, str]]) -> ReleaseHistory:
        """Return release history per package name.

        ``packages`` is a list of ``(registry_system, package_name)`` tuples.
        The result is keyed by package_name to match how the orchestrator
        identifies packages internally.
        """
        ...


# --- Pure analysis ---


def releases_in_last_n_days(
    releases: Sequence[ReleaseInfo],
    window_days: int,
    ref: datetime,
) -> int:
    """Count releases whose ``published_at`` falls within ``window_days`` of ``ref``."""
    cutoff = ref - timedelta(days=window_days)
    return sum(1 for r in releases if r.published_at >= cutoff)


def median_days_between_releases(releases: Sequence[ReleaseInfo]) -> Optional[float]:
    """Median gap (in days) between consecutive releases. None if fewer than 2."""
    if len(releases) < 2:
        return None
    sorted_dates = sorted(r.published_at for r in releases)
    gaps = [
        (sorted_dates[i] - sorted_dates[i - 1]).total_seconds() / 86400.0
        for i in range(1, len(sorted_dates))
    ]
    return float(median(gaps))


def days_since_latest_release(
    releases: Sequence[ReleaseInfo],
    ref: datetime,
) -> Optional[int]:
    """Days between ``ref`` and the most recent release. None if no releases."""
    if not releases:
        return None
    latest = max(r.published_at for r in releases)
    return (ref - latest).days


def compute_adoption_latencies(
    history: ReleaseHistory,
    observations: Sequence[Observation],
) -> List[int]:
    """For each (package, version, scan_date) observation, return the
    number of days between the upstream publish date and the scan date.

    Observations whose version has no corresponding release date in the
    history are skipped (we can't know latency without an upstream date).
    """
    publish_lookup: Dict[Tuple[str, str], datetime] = {}
    for pkg, releases in history.items():
        for r in releases:
            publish_lookup[(pkg, r.version)] = r.published_at

    latencies: List[int] = []
    for pkg, version, scan_date in observations:
        published = publish_lookup.get((pkg, version))
        if published is None:
            continue
        latencies.append((scan_date - published).days)
    return latencies


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


# --- deps.dev integration ---


def parse_deps_dev_response(payload: Dict[str, Any]) -> List[ReleaseInfo]:
    """Translate a deps.dev ``GetPackage`` response into ReleaseInfo entries.

    Versions without a parsable ``publishedAt`` are dropped — they would
    poison the cadence math (we'd treat them as "released at epoch 0").
    """
    out: List[ReleaseInfo] = []
    for entry in payload.get("versions", []) or []:
        version = (entry.get("versionKey") or {}).get("version")
        published_at_str = entry.get("publishedAt")
        if not version or not published_at_str:
            continue
        try:
            # deps.dev uses ISO 8601 with a "Z" suffix; fromisoformat needs +00:00.
            normalized = published_at_str.replace("Z", "+00:00")
            published_at = datetime.fromisoformat(normalized)
            if published_at.tzinfo is None:
                published_at = published_at.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        out.append(ReleaseInfo(version=str(version), published_at=published_at))
    return out


# Type aliases for the cache + HTTP hooks the fetcher takes. Tests inject
# fakes; production wires them to cache_service and InstrumentedAsyncClient.
CacheGet = Callable[[str], Awaitable[Optional[Any]]]
CacheSet = Callable[..., Awaitable[None]]
HttpFetch = Callable[[str], Awaitable[Optional[Dict[str, Any]]]]


class DepsDevReleaseHistoryFetcher:
    """Fetches per-package release histories from deps.dev with caching.

    The fetcher is constructed with hooks for cache get/set and HTTP fetch
    so it can be exercised without Redis or network in tests.
    """

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
    """deps.dev V3 GetPackage endpoint, with the package name URL-encoded."""
    encoded = quote(name, safe="")
    return f"https://api.deps.dev/v3alpha/systems/{system}/packages/{encoded}"


def _release_list_to_cache(releases: Sequence[ReleaseInfo]) -> List[Dict[str, str]]:
    """Serialize ReleaseInfo list for JSON-friendly caches (e.g. Redis)."""
    return [{"version": r.version, "published_at": r.published_at.isoformat()} for r in releases]


def _release_list_from_cache(raw: Any) -> List[ReleaseInfo]:
    """Reverse of ``_release_list_to_cache``; tolerant of malformed entries."""
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
