from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any, Protocol

from app.core import parse_iso_utc
from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.http_utils import InstrumentedAsyncClient, gather_bounded
from app.services.aggregation.versions import is_stable_release
from app.services.analyzers.deps_dev import deps_dev_package_url, fetch_deps_dev_json

logger = logging.getLogger(__name__)

# Low enough that a cold cache doesn't blast deps.dev.
_FETCH_CONCURRENCY = 16
_FETCH_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class ReleaseInfo:
    version: str
    published_at: datetime


# Keyed by ``(system, name)`` so same-named packages across ecosystems don't collide.
ReleaseHistory = dict[tuple[str, str], list[ReleaseInfo]]

# ``(system, name, version, scan_date)`` of the first scan that held the version.
Observation = tuple[str, str, str, datetime]


@dataclass(frozen=True)
class UpstreamCadenceMetrics:
    upstream_releases_last_12m_median: float | None
    upstream_days_between_releases_median: float | None
    upstream_days_since_latest_release_median: float | None
    adoption_latency_days_median: float | None


class ReleaseHistoryFetcher(Protocol):
    async def fetch(self, packages: Sequence[tuple[str, str]]) -> ReleaseHistory: ...


def releases_in_last_n_days(
    releases: Sequence[ReleaseInfo],
    window_days: int,
    ref: datetime,
) -> int:
    cutoff = ref - timedelta(days=window_days)
    return sum(1 for r in releases if r.published_at >= cutoff)


def median_days_between_releases(releases: Sequence[ReleaseInfo]) -> float | None:
    if len(releases) < 2:
        return None
    sorted_dates = sorted(r.published_at for r in releases)
    gaps = [(sorted_dates[i] - sorted_dates[i - 1]).total_seconds() / 86400.0 for i in range(1, len(sorted_dates))]
    return float(median(gaps))


def days_since_latest_release(
    releases: Sequence[ReleaseInfo],
    ref: datetime,
) -> int:
    return (ref - max(r.published_at for r in releases)).days


def compute_adoption_latencies(
    history: ReleaseHistory,
    observations: Sequence[Observation],
) -> list[int]:
    """Indexes only the observed packages, as a fetched history carries every canary a registry ever published."""
    published: dict[tuple[str, str], dict[str, datetime]] = {}
    latencies: list[int] = []
    for system, name, version, scan_date in observations:
        package = (system, name)
        if package not in published:
            published[package] = {release.version: release.published_at for release in history.get(package, ())}
        if (released := published[package].get(version)) is not None:
            latencies.append((scan_date - released).days)
    return latencies


def aggregate_upstream_metrics(
    history: ReleaseHistory,
    observations: Sequence[Observation],
    ref: datetime | None = None,
) -> UpstreamCadenceMetrics:
    ref = ref or datetime.now(tz=timezone.utc)

    if not history:
        return UpstreamCadenceMetrics(None, None, None, None)

    releases_counts: list[int] = []
    gap_medians: list[float] = []
    days_since: list[int] = []

    for (system, _name), releases in history.items():
        stable = [r for r in releases if is_stable_release(r.version, system)]
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
    """Undated versions are dropped: they would count as released at epoch 0."""
    out: list[ReleaseInfo] = []
    for entry in payload.get("versions", []) or []:
        version = (entry.get("versionKey") or {}).get("version")
        published_at = parse_iso_utc(entry.get("publishedAt"))
        if version and published_at:
            out.append(ReleaseInfo(version=str(version), published_at=published_at))
    return out


class DepsDevReleaseHistoryFetcher:
    async def fetch(self, packages: Sequence[tuple[str, str]]) -> ReleaseHistory:
        keys = {package: CacheKeys.release_history(*package) for package in packages}
        cached = await cache_service.mget(list(keys.values()))
        history = {
            package: _release_list_from_cache(cached[key]) for package, key in keys.items() if cached[key] is not None
        }
        missing = [package for package in keys if package not in history]
        if missing:
            async with InstrumentedAsyncClient("deps.dev API", timeout=_FETCH_TIMEOUT_SECONDS) as client:
                fetched = await gather_bounded(
                    missing, lambda package: _fetch_and_cache(client, package, keys[package]), _FETCH_CONCURRENCY
                )
            # A failed lookup stays uncached; a package deps.dev does not know is remembered as empty.
            history.update(
                (package, releases)
                for package, releases in zip(missing, fetched, strict=True)
                if not isinstance(releases, BaseException)
            )
        return {package: releases for package, releases in history.items() if releases}


async def _fetch_and_cache(client: InstrumentedAsyncClient, package: tuple[str, str], key: str) -> list[ReleaseInfo]:
    """Cached as each lookup lands, so a request cut off by its budget still warms the next one."""
    releases = parse_deps_dev_response(await fetch_deps_dev_json(client, deps_dev_package_url(*package)) or {})
    await cache_service.set(key, release_list_to_cache(releases), ttl_seconds=CacheTTL.RELEASE_HISTORY)
    return releases


def release_list_to_cache(releases: Sequence[ReleaseInfo]) -> list[dict[str, str]]:
    return [{"version": r.version, "published_at": r.published_at.isoformat()} for r in releases]


def _release_list_from_cache(raw: Any) -> list[ReleaseInfo]:
    if not isinstance(raw, list):
        return []
    out: list[ReleaseInfo] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        version = item.get("version")
        published_at = parse_iso_utc(item.get("published_at"))
        if version and published_at:
            out.append(ReleaseInfo(version=str(version), published_at=published_at))
    return out
