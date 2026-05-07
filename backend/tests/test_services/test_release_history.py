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
