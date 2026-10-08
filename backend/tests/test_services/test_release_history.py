"""Tests for upstream release-history analytics (release-cadence metrics)."""

import asyncio
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any

import httpx
import pytest

from app.core.cache import CacheKeys, CacheTTL
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


class _Store(dict):
    """cache_service's batch calls over a dict, remembering the TTL each write asked for."""

    async def mget(self, keys: list[str]) -> dict[str, Any]:
        return {key: self.get(key) for key in keys}

    async def mset(self, mapping: dict[str, Any], ttl_seconds: int | None = None) -> bool:
        self.update(mapping)
        self.ttl = ttl_seconds
        return True


@pytest.fixture
def cache(monkeypatch: pytest.MonkeyPatch) -> _Store:
    store = _Store()
    monkeypatch.setattr("app.services.release_history.cache_service", store)
    return store


def _serve(monkeypatch: pytest.MonkeyPatch, answer: Callable[[str], dict[str, Any] | int]) -> list[str]:
    """Answer each deps.dev request with ``answer(url)``: a payload, or a status code to fail with."""
    urls: list[str] = []

    def _handle(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        reply = answer(str(request.url))
        if isinstance(reply, int):
            return httpx.Response(reply, request=request)
        return httpx.Response(200, json=reply, request=request)

    monkeypatch.setattr(httpx, "AsyncClient", partial(httpx.AsyncClient, transport=httpx.MockTransport(_handle)))
    return urls


def _fetch(packages: list[tuple[str, str]]) -> dict[Any, list[ReleaseInfo]]:
    return asyncio.run(DepsDevReleaseHistoryFetcher().fetch(packages))


def _dated(*versions: str) -> dict[str, Any]:
    return {
        "versions": [
            {"versionKey": {"version": version}, "publishedAt": f"2026-0{month}-01T00:00:00Z"}
            for month, version in enumerate(versions, start=1)
        ]
    }


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

    @staticmethod
    def _yearly_releases(system: str, version: str) -> float | None:
        history = {(system, "pkg"): [_ri(days_ago=30, version=version)]}
        return aggregate_upstream_metrics(history, observations=[], ref=_REF).upstream_releases_last_12m_median

    @pytest.mark.parametrize(
        ("system", "version"),
        [
            ("npm", "19.0.0-canary-abc123-20240101"),
            ("npm", "14.2.0-canary.52"),
            ("npm", "1.0.0-next.3"),
            ("npm", "0.0.0-experimental-7f3a1b2-20240501"),
            ("npm", "2.0.0-beta-26f2496093-20240514"),
            ("npm", "1.0.0-alpha1.2"),
            ("npm", "1.0.0-nightly.20240101"),
            ("npm", "0.0.0-insiders.4a3b1c2"),
            ("npm", "5.6.0-insiders.20240601"),
            ("npm", "4.0.0-0"),
            ("npm", "3.0.0-oxide.5"),
            ("npm", "4.0.0-pr.12"),
            ("npm", "1.0.0-unstable.1"),
            ("go", "v0.0.0-20240101123456-abcdef123456"),
            ("go", "v1.2.4-0.20240101123456-abcdef123456"),
            ("cargo", "0.5.0-dev.3"),
            ("cargo", "0.3.0-unstable.2"),
            ("nuget", "9.0.0-preview.1.24080.9"),
            ("nuget", "2.0.0-ci.20240101"),
            ("maven", "5.0.0-M1"),
            ("maven", "5.0.0.M1"),
            ("maven", "1.0.0-SNAPSHOT"),
        ],
    )
    def test_prerelease_versions_are_not_releases(self, system, version):
        assert self._yearly_releases(system, version) is None

    @pytest.mark.parametrize(
        ("system", "version"),
        [
            ("maven", "33.0.0-jre"),
            ("maven", "33.0.0-android"),
            ("maven", "5.4.0.Final"),
            ("maven", "2.7.18.RELEASE"),
            ("npm", "4.17.21"),
            ("npm", "1.0.0+build-5"),
            ("go", "v2.0.0+incompatible"),
        ],
    )
    def test_release_versions_stay_releases(self, system, version):
        assert self._yearly_releases(system, version) == 1

    def test_a_package_with_only_prereleases_leaves_every_cadence_median_alone(self):
        tagged = [_ri(days_ago=5 + 30 * month, version=f"v1.{month}.0") for month in range(6)]
        pseudo = [_ri(days_ago=10 * day, version=f"v0.0.0-2026050{day}000000-abcdef123456") for day in range(9)]
        history = {("go", "tagged-a"): tagged, ("go", "tagged-b"): tagged}
        history |= {("go", f"golang.org/x/exp{index}"): pseudo for index in range(3)}

        result = aggregate_upstream_metrics(history, observations=[], ref=_REF)

        assert (
            result.upstream_releases_last_12m_median,
            result.upstream_days_between_releases_median,
            result.upstream_days_since_latest_release_median,
        ) == (6.0, 30.0, 5.0)

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

    def test_adoption_latency_uses_observation_input(self):
        history = {
            "pkg-a": [
                ReleaseInfo(version="1.0.0", published_at=_REF - timedelta(days=100)),
                ReleaseInfo(version="1.1.0", published_at=_REF - timedelta(days=20)),
            ],
        }
        observations = [
            ("pkg-a", "1.0.0", _REF - timedelta(days=80)),  # latency 20
            ("pkg-a", "1.1.0", _REF - timedelta(days=5)),  # latency 15
        ]
        result = aggregate_upstream_metrics(history, observations=observations, ref=_REF)
        assert result.adoption_latency_days_median is not None
        assert abs(result.adoption_latency_days_median - 17.5) < 0.01


class TestDepsDevFetcher:
    """The fetcher as the update-frequency view runs it: the cache first, deps.dev for the rest."""

    def test_a_cache_miss_is_fetched_parsed_and_cached(self, monkeypatch, cache):
        urls = _serve(monkeypatch, lambda _url: _dated("1.0.0", "1.1.0"))

        result = _fetch([("pypi", "pkg-a")])

        assert {r.version for r in result[("pypi", "pkg-a")]} == {"1.0.0", "1.1.0"}
        assert len(urls) == 1
        assert [entry["version"] for entry in cache[CacheKeys.release_history("pypi", "pkg-a")]] == ["1.0.0", "1.1.0"]
        assert cache.ttl == CacheTTL.RELEASE_HISTORY

    def test_a_cache_hit_skips_deps_dev(self, monkeypatch, cache):
        cache[CacheKeys.release_history("pypi", "warm")] = [
            {"version": "5.0.0", "published_at": "2025-01-01T00:00:00+00:00"}
        ]
        urls = _serve(monkeypatch, lambda _url: _dated("6.0.0"))

        result = _fetch([("pypi", "warm")])

        assert [r.version for r in result[("pypi", "warm")]] == ["5.0.0"]
        assert urls == []

    def test_a_package_deps_dev_does_not_know_is_remembered_as_empty(self, monkeypatch, cache):
        urls = _serve(monkeypatch, lambda _url: 404)

        assert _fetch([("npm", "gone")]) == {}
        assert _fetch([("npm", "gone")]) == {}

        assert len(urls) == 1
        assert cache[CacheKeys.release_history("npm", "gone")] == []

    def test_a_failed_lookup_is_neither_reported_nor_cached(self, monkeypatch, cache):
        _serve(monkeypatch, lambda url: 503 if "broken" in url else _dated("1.0.0"))

        result = _fetch([("pypi", "broken"), ("pypi", "fine")])

        assert list(result) == [("pypi", "fine")]
        assert CacheKeys.release_history("pypi", "broken") not in cache

    def test_a_package_without_dated_releases_leaves_the_release_median_alone(self, monkeypatch, cache):
        _serve(
            monkeypatch,
            lambda url: (
                {"versions": [{"versionKey": {"version": "1.0.0"}}]}
                if "undated" in url
                else _dated("1.0", "1.1", "1.2")
            ),
        )

        history = _fetch([("npm", "dated"), ("npm", "undated")])

        assert aggregate_upstream_metrics(history, observations=[], ref=_REF).upstream_releases_last_12m_median == 3.0

    def test_same_named_packages_of_two_ecosystems_stay_apart(self, monkeypatch, cache):
        _serve(monkeypatch, lambda url: _dated("9.9.9") if "/npm/" in url else _dated("1.0.0"))

        result = _fetch([("npm", "foo"), ("pypi", "foo")])

        assert {r.version for r in result[("npm", "foo")]} == {"9.9.9"}
        assert {r.version for r in result[("pypi", "foo")]} == {"1.0.0"}

    def test_the_url_follows_the_configured_deps_dev_base(self, monkeypatch, cache):
        monkeypatch.setattr("app.services.release_history.DEPS_DEV_API_URL", "https://deps.example/v3")
        urls = _serve(monkeypatch, lambda _url: 404)

        _fetch([("npm", "@babel/core")])

        assert urls == ["https://deps.example/v3/systems/npm/packages/%40babel%2Fcore"]


class TestEcosystemKeyingNoConflation:
    """Keying history/observations by (system, name) keeps same-named packages in different ecosystems separate."""

    def test_aggregate_counts_both_ecosystems_of_same_name(self):
        # Cadence aggregation iterates history values; with (system, name) keys
        # both same-named packages contribute instead of one clobbering the other.
        history = {
            ("npm", "foo"): [_ri(days_ago=30), _ri(days_ago=10)],
            ("pypi", "foo"): [_ri(days_ago=200)],
        }
        result = aggregate_upstream_metrics(history, observations=[], ref=_REF)
        # npm foo: 2 releases in last year; pypi foo: 1. Median across both = 1.5.
        assert result.upstream_releases_last_12m_median is not None
        assert abs(result.upstream_releases_last_12m_median - 1.5) < 0.01

    def test_adoption_latency_disambiguates_by_system(self):
        # Same name+version in two ecosystems, published on different dates.
        # A system-aware (4-tuple) observation must match the RIGHT ecosystem.
        history = {
            ("npm", "foo"): [ReleaseInfo(version="1.0.0", published_at=_REF - timedelta(days=50))],
            ("pypi", "foo"): [ReleaseInfo(version="1.0.0", published_at=_REF - timedelta(days=10))],
        }
        observations = [
            ("npm", "foo", "1.0.0", _REF),  # latency vs npm publish = 50
            ("pypi", "foo", "1.0.0", _REF),  # latency vs pypi publish = 10
        ]
        latencies = compute_adoption_latencies(history, observations)
        assert sorted(latencies) == [10, 50]

    def test_name_only_history_and_observations_still_work(self):
        # Name-keyed history + 3-tuple observations (what update_frequency passes) must resolve.
        history = {
            "pkg-a": [ReleaseInfo(version="1.1.0", published_at=_REF - timedelta(days=30))],
        }
        observations = [("pkg-a", "1.1.0", _REF - timedelta(days=5))]
        assert compute_adoption_latencies(history, observations) == [25]

    def test_system_observation_falls_back_to_name_keyed_history(self):
        # A system-aware observation matches name-keyed history via the name+version fallback.
        history = {
            "pkg-a": [ReleaseInfo(version="1.0.0", published_at=_REF - timedelta(days=40))],
        }
        observations = [("pypi", "pkg-a", "1.0.0", _REF - timedelta(days=10))]
        assert compute_adoption_latencies(history, observations) == [30]
