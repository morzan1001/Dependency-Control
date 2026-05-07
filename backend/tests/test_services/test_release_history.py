"""Tests for upstream release-history analytics — the pure math used to
build the "release cadence" metrics that complement team update-velocity."""

from datetime import datetime, timedelta, timezone
from typing import List


async def _async_noop(*_args, **_kwargs):  # noqa: ANN001
    return None

from app.services.release_history import (
    DepsDevReleaseHistoryFetcher,
    ReleaseInfo,
    aggregate_upstream_metrics,
    compute_adoption_latencies,
    days_since_latest_release,
    median_days_between_releases,
    parse_deps_dev_response,
    releases_in_last_n_days,
)


_REF = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _ri(years_ago: float = 0, days_ago: float = 0, version: str = "1.0.0") -> ReleaseInfo:
    """Build a ReleaseInfo `years_ago` years and `days_ago` days before _REF."""
    delta = timedelta(days=years_ago * 365.25 + days_ago)
    return ReleaseInfo(version=version, published_at=_REF - delta)


class TestReleasesInLastNDays:
    def test_empty_list_returns_zero(self):
        assert releases_in_last_n_days([], window_days=365, ref=_REF) == 0

    def test_counts_only_within_window(self):
        releases = [
            _ri(days_ago=10),
            _ri(days_ago=100),
            _ri(days_ago=400),  # outside 365-day window
            _ri(days_ago=730),  # outside
        ]
        assert releases_in_last_n_days(releases, window_days=365, ref=_REF) == 2

    def test_release_exactly_at_window_edge_included(self):
        releases = [_ri(days_ago=365)]
        assert releases_in_last_n_days(releases, window_days=365, ref=_REF) == 1


class TestMedianDaysBetweenReleases:
    def test_zero_releases_returns_none(self):
        assert median_days_between_releases([]) is None

    def test_single_release_returns_none(self):
        assert median_days_between_releases([_ri(days_ago=100)]) is None

    def test_two_releases_returns_gap(self):
        releases = [_ri(days_ago=200), _ri(days_ago=100)]  # 100 days apart
        result = median_days_between_releases(releases)
        assert result is not None
        assert abs(result - 100.0) < 0.01

    def test_median_is_robust_against_outlier(self):
        # Gaps: 10, 10, 10, 1000  -> median 10, mean would be ~257
        releases = [
            _ri(days_ago=1030),
            _ri(days_ago=30),
            _ri(days_ago=20),
            _ri(days_ago=10),
        ]
        result = median_days_between_releases(releases)
        assert result is not None
        assert 9.0 <= result <= 11.0


class TestDaysSinceLatestRelease:
    def test_empty_returns_none(self):
        assert days_since_latest_release([], ref=_REF) is None

    def test_returns_days_since_latest(self):
        releases = [_ri(days_ago=200), _ri(days_ago=42), _ri(days_ago=500)]
        assert days_since_latest_release(releases, ref=_REF) == 42


class TestComputeAdoptionLatencies:
    def test_empty_returns_empty(self):
        result = compute_adoption_latencies({}, [])
        assert result == []

    def test_latency_for_observed_versions(self):
        # pkg-a v1.1.0 published 30 days before _REF; first scan that saw it 5 days before _REF
        # -> adoption latency = 25 days
        history = {
            "pkg-a": [
                ReleaseInfo(version="1.0.0", published_at=_REF - timedelta(days=400)),
                ReleaseInfo(version="1.1.0", published_at=_REF - timedelta(days=30)),
            ],
        }
        observations = [
            ("pkg-a", "1.1.0", _REF - timedelta(days=5)),
        ]
        latencies = compute_adoption_latencies(history, observations)
        assert latencies == [25]

    def test_skips_versions_with_unknown_publish_date(self):
        history = {"pkg-a": []}  # no release info for any version
        observations = [("pkg-a", "1.0.0", _REF)]
        assert compute_adoption_latencies(history, observations) == []


class TestAggregateUpstreamMetrics:
    def test_empty_history_returns_all_none(self):
        result = aggregate_upstream_metrics({}, observations=[], ref=_REF)
        assert result.upstream_releases_last_12m_median is None
        assert result.upstream_days_between_releases_median is None
        assert result.upstream_days_since_latest_release_median is None
        assert result.adoption_latency_days_median is None

    def test_aggregates_across_packages(self):
        # pkg-a: 3 releases in last year, gap median ~60d, last 30 days ago
        # pkg-b: 1 release in last year, no gap median, last 90 days ago
        history = {
            "pkg-a": [
                _ri(days_ago=180),
                _ri(days_ago=120),
                _ri(days_ago=60),
                _ri(days_ago=30),
            ],
            "pkg-b": [
                _ri(days_ago=90),
            ],
        }
        result = aggregate_upstream_metrics(history, observations=[], ref=_REF)

        # 12m: pkg-a has 4, pkg-b has 1. Median = 2.5
        assert result.upstream_releases_last_12m_median is not None
        assert abs(result.upstream_releases_last_12m_median - 2.5) < 0.01

        # days between releases: pkg-a has gaps {60, 60, 30} -> median 60. pkg-b has none.
        # Aggregate median across packages-with-data = 60.
        assert result.upstream_days_between_releases_median is not None
        assert abs(result.upstream_days_between_releases_median - 60.0) < 0.01

        # days since latest: pkg-a=30, pkg-b=90 -> median 60
        assert result.upstream_days_since_latest_release_median is not None
        assert abs(result.upstream_days_since_latest_release_median - 60.0) < 0.01

    def test_releases_count_excludes_prereleases(self):
        # 2 stable + 3 betas in last 12m -> stable-only count is 2.
        history = {
            "pkg": [
                ReleaseInfo(version="1.0.0", published_at=_REF - timedelta(days=300)),
                ReleaseInfo(version="1.0.0-beta1", published_at=_REF - timedelta(days=280)),
                ReleaseInfo(version="1.0.0-rc1", published_at=_REF - timedelta(days=200)),
                ReleaseInfo(version="1.1.0", published_at=_REF - timedelta(days=100)),
                ReleaseInfo(version="2.0.0a1", published_at=_REF - timedelta(days=30)),
            ],
        }
        result = aggregate_upstream_metrics(history, observations=[], ref=_REF)
        # Median across one package = 2 stable releases.
        assert result.upstream_releases_last_12m_median == 2.0

    def test_days_between_excludes_prereleases(self):
        # Stable releases 100 days apart; betas would shrink the gap if counted.
        history = {
            "pkg": [
                ReleaseInfo(version="1.0.0", published_at=_REF - timedelta(days=200)),
                ReleaseInfo(version="1.0.0-beta1", published_at=_REF - timedelta(days=150)),
                ReleaseInfo(version="1.1.0", published_at=_REF - timedelta(days=100)),
            ],
        }
        result = aggregate_upstream_metrics(history, observations=[], ref=_REF)
        # Stable-only gap 200 -> 100 = 100 days. With prereleases it'd be 50.
        assert result.upstream_days_between_releases_median is not None
        assert abs(result.upstream_days_between_releases_median - 100.0) < 1.0

    def test_days_since_latest_excludes_prerelease(self):
        # Latest stable is 200 days old; a beta released yesterday must
        # not pretend the package is "actively maintained".
        history = {
            "pkg": [
                ReleaseInfo(version="1.0.0", published_at=_REF - timedelta(days=200)),
                ReleaseInfo(version="2.0.0-beta1", published_at=_REF - timedelta(days=1)),
            ],
        }
        result = aggregate_upstream_metrics(history, observations=[], ref=_REF)
        assert result.upstream_days_since_latest_release_median == 200

    def test_adoption_latency_includes_prereleases(self):
        # If the team adopted a beta, the adoption_latency must measure
        # the right thing — the upstream publish date of *that* beta,
        # not a hypothetical filtered-out release.
        history = {
            "pkg": [
                ReleaseInfo(version="1.0.0-beta1", published_at=_REF - timedelta(days=20)),
            ],
        }
        observations = [("pkg", "1.0.0-beta1", _REF - timedelta(days=5))]
        result = aggregate_upstream_metrics(history, observations=observations, ref=_REF)
        assert result.adoption_latency_days_median == 15

    def test_parse_deps_dev_skips_versions_without_published_at(self):
        # Real-world deps.dev responses occasionally omit publishedAt.
        # Those entries must be dropped; valid ones kept.
        payload = {
            "versions": [
                {
                    "versionKey": {"version": "1.0.0"},
                    "publishedAt": "2024-06-01T12:34:56Z",
                },
                {
                    "versionKey": {"version": "1.0.1"},
                    # publishedAt missing
                },
                {
                    "versionKey": {"version": "1.0.2"},
                    "publishedAt": "2024-09-15T08:00:00Z",
                },
            ]
        }
        releases = parse_deps_dev_response(payload)
        versions = sorted(r.version for r in releases)
        assert versions == ["1.0.0", "1.0.2"]
        for r in releases:
            assert r.published_at.tzinfo is not None  # must be timezone-aware

    def test_parse_deps_dev_handles_empty_payload(self):
        assert parse_deps_dev_response({}) == []
        assert parse_deps_dev_response({"versions": []}) == []

    def test_deps_dev_fetcher_uses_cache_when_available(self):
        # The fetcher must consult the cache and skip HTTP when a hit exists.
        cache_hits: List[str] = []

        async def fake_get(key: str):  # type: ignore[no-untyped-def]
            cache_hits.append(key)
            # Return cached release list as JSON-serializable list of dicts.
            return [
                {"version": "1.0.0", "published_at": "2025-06-01T00:00:00+00:00"},
            ]

        async def fail_fetch(*_args, **_kwargs):  # type: ignore[no-untyped-def]
            raise AssertionError("HTTP fetch should not be called when cache is warm")

        fetcher = DepsDevReleaseHistoryFetcher(
            cache_get=fake_get,
            cache_set=lambda *a, **k: _async_noop(),
            http_fetch=fail_fetch,
        )

        import asyncio

        result = asyncio.run(fetcher.fetch([("pypi", "pkg-a")]))
        assert "pkg-a" in result
        assert len(result["pkg-a"]) == 1
        assert cache_hits  # cache was consulted

    def test_adoption_latency_uses_observation_input(self):
        history = {
            "pkg-a": [
                ReleaseInfo(version="1.0.0", published_at=_REF - timedelta(days=100)),
                ReleaseInfo(version="1.1.0", published_at=_REF - timedelta(days=20)),
            ],
        }
        observations = [
            ("pkg-a", "1.0.0", _REF - timedelta(days=80)),  # latency 20
            ("pkg-a", "1.1.0", _REF - timedelta(days=5)),   # latency 15
        ]
        result = aggregate_upstream_metrics(history, observations=observations, ref=_REF)
        assert result.adoption_latency_days_median is not None
        assert abs(result.adoption_latency_days_median - 17.5) < 0.01


class TestDepsDevFetcherIntegration:
    """The fetcher's pure helpers (parse, serialize) are well-covered. These
    drive the cache-miss and cache-hit branches end-to-end so a regression
    in the fetcher's orchestration would surface at the unit level rather
    than waiting for a full deps.dev integration test."""

    def test_cache_miss_fetches_parses_and_caches(self):
        import asyncio
        from app.services.release_history import DepsDevReleaseHistoryFetcher

        fetched_urls: List[str] = []
        cache_writes: dict = {}

        async def cache_get(_key):  # noqa: ANN001
            return None  # always cold

        async def cache_set(key, value, ttl_seconds):  # noqa: ANN001
            cache_writes[key] = (value, ttl_seconds)

        async def http_fetch(url):  # noqa: ANN001
            fetched_urls.append(url)
            return {
                "versions": [
                    {"versionKey": {"version": "1.0.0"}, "publishedAt": "2024-06-01T00:00:00Z"},
                    {"versionKey": {"version": "1.1.0"}, "publishedAt": "2024-09-01T00:00:00Z"},
                ]
            }

        fetcher = DepsDevReleaseHistoryFetcher(
            cache_get=cache_get, cache_set=cache_set, http_fetch=http_fetch
        )
        result = asyncio.run(fetcher.fetch([("pypi", "pkg-a")]))

        assert len(result["pkg-a"]) == 2
        assert {r.version for r in result["pkg-a"]} == {"1.0.0", "1.1.0"}
        assert len(fetched_urls) == 1
        assert "pkg-a" in fetched_urls[0]
        assert "releases:pypi:pkg-a" in cache_writes
        # Cached payload must round-trip through the JSON-serializable shape.
        cached_payload, _ = cache_writes["releases:pypi:pkg-a"]
        assert isinstance(cached_payload, list)
        assert all("version" in entry and "published_at" in entry for entry in cached_payload)

    def test_http_failure_returns_empty_for_that_package(self):
        import asyncio
        from app.services.release_history import DepsDevReleaseHistoryFetcher

        async def cache_get(_key):  # noqa: ANN001
            return None

        async def cache_set(*_a, **_k):  # noqa: ANN001
            return None

        async def http_fetch(_url):  # noqa: ANN001
            return None  # simulates timeout / 5xx

        fetcher = DepsDevReleaseHistoryFetcher(
            cache_get=cache_get, cache_set=cache_set, http_fetch=http_fetch
        )
        result = asyncio.run(fetcher.fetch([("pypi", "pkg-broken")]))
        # No history surfaces for the failed package; the orchestrator will
        # treat it as "no upstream data" rather than crash.
        assert "pkg-broken" not in result

    def test_multi_package_fetch_keys_results_by_package_name(self):
        import asyncio
        from app.services.release_history import DepsDevReleaseHistoryFetcher

        cache: dict = {}

        async def cache_get(key):  # noqa: ANN001
            return cache.get(key)

        async def cache_set(key, value, ttl_seconds):  # noqa: ANN001
            cache[key] = value

        responses_by_url: dict = {
            "first": {
                "versions": [{"versionKey": {"version": "1.0"}, "publishedAt": "2024-01-01T00:00:00Z"}]
            },
            "second": {
                "versions": [{"versionKey": {"version": "2.0"}, "publishedAt": "2024-02-01T00:00:00Z"}]
            },
        }
        urls_seen: List[str] = []

        async def http_fetch(url):  # noqa: ANN001
            urls_seen.append(url)
            # Pick payload by ordinal so the assertion is unambiguous.
            return responses_by_url["first" if "first" in url else "second"]

        fetcher = DepsDevReleaseHistoryFetcher(
            cache_get=cache_get, cache_set=cache_set, http_fetch=http_fetch
        )
        result = asyncio.run(fetcher.fetch([("pypi", "first"), ("pypi", "second")]))
        assert "first" in result and "second" in result
        assert {r.version for r in result["first"]} == {"1.0"}
        assert {r.version for r in result["second"]} == {"2.0"}
        assert len(urls_seen) == 2

    def test_cache_hit_skips_http(self):
        import asyncio
        from app.services.release_history import DepsDevReleaseHistoryFetcher

        async def cache_get(_key):  # noqa: ANN001
            return [
                {"version": "5.0.0", "published_at": "2025-01-01T00:00:00+00:00"},
            ]

        async def cache_set(*_a, **_k):  # noqa: ANN001
            raise AssertionError("cache_set must not be called on a cache hit")

        async def http_fetch(_url):  # noqa: ANN001
            raise AssertionError("http_fetch must not be called on a cache hit")

        fetcher = DepsDevReleaseHistoryFetcher(
            cache_get=cache_get, cache_set=cache_set, http_fetch=http_fetch
        )
        result = asyncio.run(fetcher.fetch([("pypi", "warm")]))
        assert len(result["warm"]) == 1
        assert result["warm"][0].version == "5.0.0"
