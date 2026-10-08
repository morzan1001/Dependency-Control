"""Upstream release-history analytics: cadence and adoption-latency math.

Pure analysis lives here. HTTP fetching from deps.dev plugs in via the
``ReleaseHistoryFetcher`` protocol so it can be swapped in tests.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any, Protocol
from urllib.parse import quote

from packaging.version import InvalidVersion, Version

from app.core import ensure_utc
from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import DEPS_DEV_API_URL
from app.core.http_utils import InstrumentedAsyncClient, gather_bounded
from app.services.analyzers.deps_dev import fetch_deps_dev_json

logger = logging.getLogger(__name__)

# Low enough that a cold cache doesn't blast deps.dev.
_FETCH_CONCURRENCY = 16
_FETCH_TIMEOUT_SECONDS = 10.0

# Matched by token, not by any "-" suffix, because Maven qualifiers like Guava's 33.0.0-jre are releases.
_PRERELEASE_TAG = re.compile(
    r"[-.](alpha|beta|rc|pre|preview|dev|canary|next|nightly|experimental|snapshot|m\d+)(?![a-z])", re.IGNORECASE
)

# Strict-semver ecosystems mark every prerelease (Go pseudo-versions, npm "4.0.0-0") with "-" before any "+build".
_SEMVER_SYSTEMS = frozenset({"npm", "go", "cargo", "nuget"})


def _is_stable_release(version: str, system: str) -> bool:
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

    An observation matches only the release of its own ``(system, name, version)``; one
    whose version is missing from the history is skipped.
    """
    published = {
        (system, name, release.version): release.published_at
        for (system, name), releases in history.items()
        for release in releases
    }
    return [
        (scan_date - published[(system, name, version)]).days
        for system, name, version, scan_date in observations
        if (system, name, version) in published
    ]


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

    for (system, _name), releases in history.items():
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


class DepsDevReleaseHistoryFetcher:
    """Per-package release histories from deps.dev, read through the Redis cache in one round trip."""

    async def fetch(self, packages: Sequence[tuple[str, str]]) -> ReleaseHistory:
        keys = {package: CacheKeys.release_history(*package) for package in packages}
        cached = await cache_service.mget(list(keys.values()))
        history = {
            package: _release_list_from_cache(cached[key]) for package, key in keys.items() if cached[key] is not None
        }
        missing = [package for package in keys if package not in history]
        if missing:
            async with InstrumentedAsyncClient("deps.dev API", timeout=_FETCH_TIMEOUT_SECONDS) as client:
                payloads = await gather_bounded(
                    missing,
                    lambda package: fetch_deps_dev_json(client, _build_deps_dev_url(*package)),
                    _FETCH_CONCURRENCY,
                )
            # A failed lookup stays uncached; a package deps.dev does not know is remembered as empty.
            fetched = {
                package: parse_deps_dev_response(payload or {})
                for package, payload in zip(missing, payloads, strict=True)
                if not isinstance(payload, BaseException)
            }
            await cache_service.mset(
                {keys[package]: _release_list_to_cache(releases) for package, releases in fetched.items()},
                ttl_seconds=CacheTTL.RELEASE_HISTORY,
            )
            history.update(fetched)
        return {package: releases for package, releases in history.items() if releases}


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
