import asyncio
import contextlib
import hashlib
import time
from unittest.mock import AsyncMock

import fakeredis
import pytest
import redis.asyncio as redis
from prometheus_client import REGISTRY

from app.core import cache as cache_module
from app.core.cache import (
    STAMPEDE_LOCK_TTL_SECONDS,
    STAMPEDE_MAX_WAIT_SECONDS,
    CacheKeys,
    CacheService,
    CacheTTL,
    scope_digest,
    suppress_cache_writes,
)
from app.core.constants import ANALYZER_TIMEOUTS

_TTL = 60


class TestCacheTTLValues:
    def test_popular_packages_is_positive_int(self):
        assert isinstance(CacheTTL.POPULAR_PACKAGES, int)
        assert CacheTTL.POPULAR_PACKAGES > 0

    def test_deps_dev_metadata_is_positive_int(self):
        assert isinstance(CacheTTL.DEPS_DEV_METADATA, int)
        assert CacheTTL.DEPS_DEV_METADATA > 0

    def test_latest_version_is_positive_int(self):
        assert isinstance(CacheTTL.LATEST_VERSION, int)
        assert CacheTTL.LATEST_VERSION > 0

    def test_eol_status_is_positive_int(self):
        assert isinstance(CacheTTL.EOL_STATUS, int)
        assert CacheTTL.EOL_STATUS > 0

    def test_package_hash_is_positive_int(self):
        assert isinstance(CacheTTL.PACKAGE_HASH, int)
        assert CacheTTL.PACKAGE_HASH > 0

    def test_maintainer_info_is_positive_int(self):
        assert isinstance(CacheTTL.MAINTAINER_INFO, int)
        assert CacheTTL.MAINTAINER_INFO > 0

    def test_malware_check_is_positive_int(self):
        assert isinstance(CacheTTL.MALWARE_CHECK, int)
        assert CacheTTL.MALWARE_CHECK > 0


class TestCacheTTLExpectedValues:
    def test_kev_catalog_is_24_hours(self):
        assert CacheTTL.KEV_CATALOG == 86400

    def test_epss_score_is_24_hours(self):
        assert CacheTTL.EPSS_SCORE == 86400

    def test_ghsa_data_is_7_days(self):
        assert CacheTTL.GHSA_DATA == 604800

    def test_osv_vulnerability_is_6_hours(self):
        assert CacheTTL.OSV_VULNERABILITY == 21600

    def test_negative_result_is_1_hour(self):
        assert CacheTTL.NEGATIVE_RESULT == 3600


class TestScopeDigest:
    def test_order_of_the_ids_does_not_matter(self):
        assert scope_digest(["b", "a", "c"]) == scope_digest(["c", "b", "a"])

    def test_different_sets_differ(self):
        assert scope_digest(["a", "b"]) != scope_digest(["a", "c"])

    def test_the_global_scope_is_not_the_empty_scope(self):
        assert scope_digest(None) != scope_digest([])


class TestCacheKeysRecommendations:
    def test_includes_all_components(self):
        key = CacheKeys.recommendations("proj1", "scanA", "2026-09-30T10:00:00", "deadbeef")
        assert "proj1" in key and "scanA" in key and "2026-09-30T10:00:00" in key and "deadbeef" in key

    def test_differs_by_scan(self):
        assert CacheKeys.recommendations("p", "s1", "t", "h") != CacheKeys.recommendations("p", "s2", "t", "h")

    def test_differs_by_analysis(self):
        assert CacheKeys.recommendations("p", "s", "t1", "h") != CacheKeys.recommendations("p", "s", "t2", "h")

    def test_differs_by_scope(self):
        assert CacheKeys.recommendations("p", "s", "t", "h1") != CacheKeys.recommendations("p", "s", "t", "h2")


class TestCacheKeysKevCatalog:
    def test_returns_fixed_string(self):
        assert CacheKeys.kev_catalog() == "kev:catalog"


class TestCacheKeysEpss:
    def test_basic_cve_id(self):
        assert CacheKeys.epss("CVE-2024-001") == "epss:CVE-2024-001"

    def test_another_cve_id(self):
        assert CacheKeys.epss("CVE-2023-44487") == "epss:CVE-2023-44487"

    def test_empty_cve_id(self):
        assert CacheKeys.epss("") == "epss:"


class TestCacheKeysGhsa:
    def test_basic_ghsa_id(self):
        assert CacheKeys.ghsa("GHSA-abcd-1234-efgh") == "ghsa:GHSA-abcd-1234-efgh"

    def test_another_ghsa_id(self):
        assert CacheKeys.ghsa("GHSA-xyzw-9876-ijkl") == "ghsa:GHSA-xyzw-9876-ijkl"


class TestCacheKeysOsv:
    def _expected_osv_key(self, purl: str) -> str:
        purl_hash = hashlib.md5(purl.encode()).hexdigest()[:16]
        return f"osv4:{purl_hash}"

    def test_basic_purl(self):
        purl = "pkg:pypi/requests@2.31.0"
        assert CacheKeys.osv(purl) == self._expected_osv_key(purl)

    def test_deterministic(self):
        purl = "pkg:npm/lodash@4.17.21"
        first = CacheKeys.osv(purl)
        second = CacheKeys.osv(purl)
        assert first == second

    def test_different_purls_differ(self):
        assert CacheKeys.osv("pkg:pypi/flask@2.0") != CacheKeys.osv("pkg:pypi/django@4.0")

    def test_uses_16_char_hex_prefix(self):
        key = CacheKeys.osv("pkg:pypi/test@1.0")
        hash_part = key.split(":", 1)[1]
        assert len(hash_part) == 16
        assert all(c in "0123456789abcdef" for c in hash_part)

    def test_long_purl(self):
        long_purl = "pkg:npm/@very-long-scope/very-long-package-name@99.99.99"
        result = CacheKeys.osv(long_purl)
        assert result.startswith("osv4:")
        assert result == self._expected_osv_key(long_purl)


class TestCacheKeysDepsDev:
    def test_pypi_package(self):
        assert CacheKeys.deps_dev("pypi", "requests", "2.31.0") == "deps:pypi:requests:2.31.0"

    def test_npm_package(self):
        assert CacheKeys.deps_dev("npm", "lodash", "4.17.21") == "deps:npm:lodash:4.17.21"

    def test_maven_package(self):
        assert CacheKeys.deps_dev("maven", "org.apache:commons", "1.0") == "deps:maven:org.apache:commons:1.0"


class TestCacheKeysLatestVersion:
    def test_pypi_package(self):
        assert CacheKeys.latest_version("pypi", "requests") == "latest3:pypi:requests"

    def test_npm_package(self):
        assert CacheKeys.latest_version("npm", "express") == "latest3:npm:express"


class TestCacheKeysEol:
    def test_basic_product(self):
        assert CacheKeys.eol("python") == "eol:python"

    def test_another_product(self):
        assert CacheKeys.eol("nodejs") == "eol:nodejs"


class TestCacheKeysPackageHash:
    def test_basic_package(self):
        assert CacheKeys.package_hash("pypi", "requests", "2.31.0") == "hash:pypi:requests:2.31.0"

    def test_npm_package(self):
        assert CacheKeys.package_hash("npm", "axios", "1.6.0") == "hash:npm:axios:1.6.0"


class TestCacheKeysPopularPackages:
    def test_basic_registry(self):
        assert CacheKeys.popular_packages("pypi") == "popular:pypi"

    def test_npm_registry(self):
        assert CacheKeys.popular_packages("npm") == "popular:npm"


class TestCacheKeysMaintainer:
    def test_basic_maintainer(self):
        assert CacheKeys.maintainer("pypi", "requests") == "maintainer2:pypi:requests"

    def test_npm_maintainer(self):
        assert CacheKeys.maintainer("npm", "express") == "maintainer2:npm:express"

    def test_github_facts_share_one_entry_per_repository_whatever_the_spelling(self):
        assert CacheKeys.maintainer_github("Vercel/Next.js") == "maintainer_gh:vercel/next.js"


class TestCacheKeysMalware:
    def test_basic_malware(self):
        assert CacheKeys.malware("pypi", "requests", "2.31.0") == "malware:pypi:requests:2.31.0"

    def test_npm_malware(self):
        assert CacheKeys.malware("npm", "lodash", "4.17.21") == "malware:npm:lodash:4.17.21"


class TestStampedeLockRelease:
    @pytest.mark.asyncio
    async def test_release_does_not_delete_another_pods_lock(self, fake_cache):
        key = "epss:CVE-2024-0001"
        full_lock_key = fake_cache._make_key(f"lock:{key}")
        other_pod_token = "pod-B-token"

        async def slow_fetch():
            # Simulate our lock TTL expiring mid-fetch and pod B re-acquiring it.
            await fake_cache._client.set(full_lock_key, other_pod_token)
            return {"score": 0.5}

        result = await fake_cache.get_or_fetch_with_lock(key, slow_fetch, ttl_seconds=60)

        assert result == {"score": 0.5}
        assert await fake_cache._client.get(full_lock_key) == other_pod_token

    @pytest.mark.asyncio
    async def test_holder_releases_its_own_lock(self, fake_cache):
        key = "epss:CVE-2024-0002"
        full_lock_key = fake_cache._make_key(f"lock:{key}")

        async def fetch():
            return {"score": 0.9}

        result = await fake_cache.get_or_fetch_with_lock(key, fetch, ttl_seconds=60)

        assert result == {"score": 0.9}
        assert await fake_cache._client.exists(full_lock_key) == 0


class TestStampedeHolderVanishes:
    @pytest.mark.asyncio
    async def test_waiter_takes_over_after_the_holder_is_cancelled(self, fake_cache):
        key = "update_freq_cmp:scope-a:all"
        holder_running = asyncio.Event()

        async def holder_fetch():
            holder_running.set()
            await asyncio.sleep(30)
            return {"unreachable": True}

        async def waiter_fetch():
            return {"value": 42}

        def call(fetch_fn):
            return fake_cache.get_or_fetch_with_lock(
                key, fetch_fn, ttl_seconds=60, lock_ttl_seconds=60, max_wait_seconds=5.0
            )

        holder = asyncio.create_task(call(holder_fetch))
        await holder_running.wait()
        waiter = asyncio.create_task(call(waiter_fetch))
        await asyncio.sleep(0.2)

        holder.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await holder

        assert await waiter == {"value": 42}


class TestStampedeWaitOutlastsTheFetch:
    def test_by_default_a_waiter_outlasts_a_catalog_fetch_and_the_lock_outlasts_the_waiter(self):
        slowest_fetch = max(ANALYZER_TIMEOUTS["kev"], ANALYZER_TIMEOUTS["ghsa"])

        assert slowest_fetch < STAMPEDE_MAX_WAIT_SECONDS < STAMPEDE_LOCK_TTL_SECONDS

    @pytest.mark.asyncio
    async def test_a_value_a_peer_publishes_as_the_wait_ends_is_served_without_a_second_fetch(
        self, fake_cache, monkeypatch
    ):
        key = "kev:catalog"
        await fake_cache._client.set(fake_cache._make_key(f"lock:{key}"), "peer-token")
        fetched = []

        async def peer_publishes_after_the_last_poll(_client, cache_key, _lock_key, deadline):
            await asyncio.sleep(max(0.0, deadline - time.monotonic()))
            await fake_cache.set(cache_key, {"from": "peer"}, _TTL)

        async def fetch():
            fetched.append(key)
            return {"from": "waiter"}

        monkeypatch.setattr(fake_cache, "_wait_for_lock_holder", peer_publishes_after_the_last_poll)

        assert await fake_cache.get_or_fetch_with_lock(key, fetch, _TTL, max_wait_seconds=0.2) == {"from": "peer"}
        assert fetched == []


class TestStampedeNegativeCaching:
    @pytest.mark.asyncio
    async def test_a_failed_fetch_expires_on_the_negative_ttl_not_the_callers(self, fake_cache):
        key = "ghsa:GHSA-xxxx-yyyy-zzzz"
        callers_ttl = CacheTTL.GHSA_DATA

        async def fetch():
            return None

        assert await fake_cache.get_or_fetch_with_lock(key, fetch, ttl_seconds=callers_ttl) is None

        stored_ttl = await fake_cache._client.ttl(fake_cache._make_key(key))
        assert stored_ttl <= CacheTTL.NEGATIVE_RESULT
        assert stored_ttl > CacheTTL.NEGATIVE_RESULT - 60
        assert callers_ttl > CacheTTL.NEGATIVE_RESULT

    @pytest.mark.asyncio
    async def test_an_empty_list_is_cached_as_itself_at_the_callers_ttl(self, fake_cache):
        key = "osv:pypi:acme:1.0.0"
        callers_ttl = CacheTTL.OSV_VULNERABILITY
        fetches = []

        async def fetch():
            fetches.append(key)
            return []

        assert await fake_cache.get_or_fetch_with_lock(key, fetch, ttl_seconds=callers_ttl) == []

        # An empty real answer must not read back as the {} marker that means the fetch failed.
        assert await fake_cache.get_or_fetch_with_lock(key, fetch, ttl_seconds=callers_ttl) == []
        assert fetches == [key]
        assert await fake_cache._client.ttl(fake_cache._make_key(key)) > CacheTTL.NEGATIVE_RESULT


class TestGetManyOrFetch:
    @pytest.mark.asyncio
    async def test_hits_come_from_one_read_and_only_a_miss_is_fetched_and_cached(self, fake_cache, monkeypatch):
        await fake_cache.set("k:hit", {"v": 1}, _TTL)
        reads: list[list[str]] = []
        read_many = fake_cache.mget

        async def _recording_mget(keys):
            reads.append(list(keys))
            return await read_many(keys)

        monkeypatch.setattr(fake_cache, "mget", _recording_mget)
        fetched: list[str] = []

        async def fetch(key):
            fetched.append(key)
            return {"v": key}

        values = await fake_cache.get_many_or_fetch(["k:hit", "k:miss", "k:hit"], fetch, 60, 4)

        assert values == {"k:hit": {"v": 1}, "k:miss": {"v": "k:miss"}}
        assert (reads, fetched) == ([["k:hit", "k:miss"]], ["k:miss"])
        assert 0 < await fake_cache._client.ttl(fake_cache._make_key("k:miss")) <= 60

    @pytest.mark.asyncio
    async def test_a_failed_fetch_leaves_its_exception_and_caches_nothing(self, fake_cache):
        boom = RuntimeError("upstream down")

        async def fetch(_key):
            raise boom

        assert await fake_cache.get_many_or_fetch(["k:down"], fetch, 60, 4) == {"k:down": boom}
        assert await fake_cache.get("k:down") is None

    @pytest.mark.asyncio
    async def test_no_more_than_the_concurrency_fetch_at_once(self, fake_cache):
        in_flight = peak = 0

        async def fetch(key):
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0.01)
            in_flight -= 1
            return key

        values = await fake_cache.get_many_or_fetch([f"k:{i}" for i in range(6)], fetch, 60, 2)

        assert (len(values), peak) == (6, 2)


_SUPPRESSED_KEY = "deps:pypi:acme-private:1.0.0"
_SUPPRESSED_VALUE = {"scorecard": 4.2}
_SEEDED_KEY = "popular:npm"
_SEEDED_VALUE = ["express"]
_UPSTREAM_VALUE = {"published": "2021-12-10"}
_UPSTREAM_ID_KEYS = (
    CacheKeys.osv_vuln("GHSA-jfh8-c2jp-5v3q", "2024-06-01T00:00:00Z"),
    CacheKeys.epss("CVE-2021-44228"),
    CacheKeys.ghsa("GHSA-jfh8-c2jp-5v3q"),
    CacheKeys.kev_catalog(),
)


class TestSuppressCacheWrites:
    @pytest.mark.asyncio
    async def test_set_writes_nothing_and_reports_failure(self, fake_cache):
        with suppress_cache_writes():
            assert await fake_cache.set(_SUPPRESSED_KEY, _SUPPRESSED_VALUE, _TTL) is False

        assert await fake_cache._client.exists(fake_cache._make_key(_SUPPRESSED_KEY)) == 0

    @pytest.mark.asyncio
    async def test_mset_writes_nothing(self, fake_cache):
        with suppress_cache_writes():
            assert await fake_cache.mset({_SUPPRESSED_KEY: _SUPPRESSED_VALUE}, _TTL) is False

        assert await fake_cache._client.exists(fake_cache._make_key(_SUPPRESSED_KEY)) == 0

    @pytest.mark.asyncio
    @pytest.mark.parametrize("key", _UPSTREAM_ID_KEYS)
    async def test_a_key_named_by_a_public_upstream_id_alone_is_still_written(self, fake_cache, key):
        with suppress_cache_writes():
            assert await fake_cache.set(key, _UPSTREAM_VALUE, _TTL) is True

        assert await fake_cache.get(key) == _UPSTREAM_VALUE

    @pytest.mark.asyncio
    async def test_mset_writes_only_the_entries_named_by_upstream_ids(self, fake_cache):
        upstream_key = CacheKeys.epss("CVE-2021-44228")

        with suppress_cache_writes():
            await fake_cache.mset({_SUPPRESSED_KEY: _SUPPRESSED_VALUE, upstream_key: _UPSTREAM_VALUE}, _TTL)

        assert await fake_cache._client.exists(fake_cache._make_key(_SUPPRESSED_KEY)) == 0
        assert await fake_cache.get(upstream_key) == _UPSTREAM_VALUE

    @pytest.mark.asyncio
    async def test_an_upstream_id_fetch_is_cached_behind_the_stampede_lock(self, fake_cache):
        upstream_key = CacheKeys.ghsa("GHSA-jfh8-c2jp-5v3q")
        locks: list[str] = []

        async def fetch():
            locks.extend(await fake_cache._client.keys("*lock*"))
            return _UPSTREAM_VALUE

        with suppress_cache_writes():
            assert await fake_cache.get_or_fetch_with_lock(upstream_key, fetch, _TTL) == _UPSTREAM_VALUE

        assert locks == [fake_cache._make_key(f"lock:{upstream_key}")]
        assert await fake_cache.get(upstream_key) == _UPSTREAM_VALUE

    @pytest.mark.asyncio
    async def test_reads_still_hit_the_shared_cache(self, fake_cache):
        await fake_cache.set(_SEEDED_KEY, _SEEDED_VALUE, _TTL)

        with suppress_cache_writes():
            assert await fake_cache.get(_SEEDED_KEY) == _SEEDED_VALUE
            assert await fake_cache.mget([_SEEDED_KEY]) == {_SEEDED_KEY: _SEEDED_VALUE}

    @pytest.mark.asyncio
    async def test_fetch_still_runs_but_leaves_neither_value_nor_lock(self, fake_cache):
        fetched = []

        async def fetch():
            fetched.append(_SUPPRESSED_KEY)
            # The stampede lock must not be taken either, and only a look from inside the fetch could see it.
            assert await fake_cache._client.keys("*") == []
            return _SUPPRESSED_VALUE

        with suppress_cache_writes():
            result = await fake_cache.get_or_fetch_with_lock(_SUPPRESSED_KEY, fetch, _TTL)

        assert result == _SUPPRESSED_VALUE
        assert fetched == [_SUPPRESSED_KEY]
        assert await fake_cache._client.keys("*") == []

    @pytest.mark.asyncio
    async def test_a_cached_value_is_served_without_refetching(self, fake_cache):
        await fake_cache.set(_SEEDED_KEY, _SEEDED_VALUE, _TTL)
        fetched = []

        async def fetch():
            fetched.append(_SEEDED_KEY)
            return ["other"]

        with suppress_cache_writes():
            result = await fake_cache.get_or_fetch_with_lock(_SEEDED_KEY, fetch, _TTL)

        assert result == _SEEDED_VALUE
        assert fetched == []

    @pytest.mark.asyncio
    async def test_suppression_ends_with_the_block(self, fake_cache):
        with suppress_cache_writes():
            await fake_cache.set(_SUPPRESSED_KEY, _SUPPRESSED_VALUE, _TTL)

        assert await fake_cache.set(_SUPPRESSED_KEY, _SUPPRESSED_VALUE, _TTL) is True
        assert await fake_cache.get(_SUPPRESSED_KEY) == _SUPPRESSED_VALUE

    @pytest.mark.asyncio
    async def test_a_concurrent_task_outside_the_block_still_writes(self, fake_cache):
        started = asyncio.Event()
        release = asyncio.Event()

        async def suppressed():
            with suppress_cache_writes():
                started.set()
                await release.wait()
                await fake_cache.set(_SUPPRESSED_KEY, _SUPPRESSED_VALUE, _TTL)

        task = asyncio.create_task(suppressed())
        await started.wait()
        assert await fake_cache.set(_SEEDED_KEY, _SEEDED_VALUE, _TTL) is True
        release.set()
        await task

        assert await fake_cache.get(_SEEDED_KEY) == _SEEDED_VALUE
        assert await fake_cache._client.exists(fake_cache._make_key(_SUPPRESSED_KEY)) == 0


class TestConnectionPoolBursts:
    @pytest.mark.asyncio
    async def test_more_concurrent_misses_than_pooled_connections_are_all_cached(self, tcp_redis):
        svc = CacheService()
        keys = [f"deps:npm:pkg{i}:1.0.0" for i in range(60)]

        async def fetch():
            return {"ok": True}

        try:
            await asyncio.gather(*(svc.get_or_fetch_with_lock(key, fetch, ttl_seconds=60) for key in keys))

            assert svc._available is True
            assert await svc.mget(keys) == {key: {"ok": True} for key in keys}
        finally:
            await svc._client.aclose(close_connection_pool=True)


async def _hang(*_args, **_kwargs):
    await asyncio.Event().wait()


_BOUND = 0.1
_GUARD = 3


class TestAHangingRedisCannotStallTheLockedPath:
    @pytest.fixture(autouse=True)
    def short_redis_bound(self, monkeypatch):
        monkeypatch.setattr(cache_module, "REDIS_OPERATION_TIMEOUT_SECONDS", _BOUND)

    @staticmethod
    async def _fetch():
        return {"v": 1}

    @pytest.mark.asyncio
    async def test_a_hanging_lock_acquire_pauses_the_cache_and_fetches_directly(self, fake_cache, monkeypatch):
        monkeypatch.setattr(fake_cache._client, "set", _hang)

        result = await asyncio.wait_for(fake_cache.get_or_fetch_with_lock("k", self._fetch, _TTL), _GUARD)

        assert (result, fake_cache._available) == ({"v": 1}, False)

    @pytest.mark.asyncio
    async def test_a_hanging_lock_probe_pauses_the_cache_and_fetches_directly(self, fake_cache, monkeypatch):
        await fake_cache._client.set(fake_cache._make_key("lock:k"), "peer-token")
        monkeypatch.setattr(fake_cache._client, "exists", _hang)

        result = await asyncio.wait_for(fake_cache.get_or_fetch_with_lock("k", self._fetch, _TTL), _GUARD)

        assert (result, fake_cache._available) == ({"v": 1}, False)

    @pytest.mark.asyncio
    async def test_a_hanging_lock_release_still_returns_the_fetched_value(self, fake_cache, monkeypatch):
        monkeypatch.setattr(fake_cache._client, "eval", _hang)

        result = await asyncio.wait_for(fake_cache.get_or_fetch_with_lock("k", self._fetch, _TTL), _GUARD)

        assert result == {"v": 1}

    @pytest.mark.asyncio
    async def test_a_hanging_connection_check_pauses_the_cache_and_fetches_directly(self, tcp_redis, monkeypatch):
        monkeypatch.setattr(redis.Redis, "ping", _hang)
        svc = CacheService()
        try:
            result = await asyncio.wait_for(svc.get_or_fetch_with_lock("k", self._fetch, _TTL), _GUARD)
        finally:
            await svc._client.aclose(close_connection_pool=True)

        assert (result, svc._available) == ({"v": 1}, False)

    @pytest.mark.asyncio
    async def test_a_wait_for_a_pooled_connection_ends_on_the_same_bound(self, tcp_redis):
        svc = CacheService()
        client = await svc.get_client()
        held = [await svc._pool.get_connection() for _ in range(svc._pool.max_connections)]
        try:
            health = await asyncio.wait_for(svc.health_check(), _GUARD)
        finally:
            for connection in held:
                await svc._pool.release(connection)
            await client.aclose(close_connection_pool=True)

        assert health["status"] == "unhealthy"


_BATCH_BOUND = 0.4
_BATCH_KEYS = 2
_BATCH = {f"k{i}": i for i in range(5)}


class TestABatchLargerThanOneRoundTrip:
    @pytest.fixture(autouse=True)
    def small_round_trips(self, monkeypatch):
        monkeypatch.setattr(cache_module, "REDIS_OPERATION_TIMEOUT_SECONDS", _BATCH_BOUND)
        monkeypatch.setattr(cache_module, "_KEYS_PER_ROUND_TRIP", _BATCH_KEYS)

    @pytest.mark.asyncio
    async def test_a_read_slower_than_one_bound_in_total_still_returns_every_key(self, fake_cache, monkeypatch):
        await fake_cache.mset(_BATCH, _TTL)
        real_mget = fake_cache._client.mget

        async def mget_taking_a_quarter_bound_per_key(keys):
            await asyncio.sleep(len(keys) * _BATCH_BOUND / 4)
            return await real_mget(keys)

        monkeypatch.setattr(fake_cache._client, "mget", mget_taking_a_quarter_bound_per_key)

        assert (await fake_cache.mget(list(_BATCH)), fake_cache._available) == (_BATCH, True)

    @pytest.mark.asyncio
    async def test_a_write_goes_out_in_bounded_round_trips_without_a_transaction(self, fake_cache, monkeypatch):
        sent: list[tuple[bool, int]] = []
        real_pipeline = fake_cache._client.pipeline

        def recording_pipeline(*args, **kwargs):
            pipe = real_pipeline(*args, **kwargs)
            real_execute = pipe.execute

            async def execute(*a, **kw):
                sent.append((pipe.is_transaction, len(pipe.command_stack)))
                return await real_execute(*a, **kw)

            pipe.execute = execute
            return pipe

        monkeypatch.setattr(fake_cache._client, "pipeline", recording_pipeline)

        assert await fake_cache.mset(_BATCH, _TTL) is True
        assert sent == [(False, 2), (False, 2), (False, 1)]
        assert await fake_cache.mget(list(_BATCH)) == _BATCH


class TestFetchFailuresReachTheCaller:
    @pytest.mark.asyncio
    async def test_a_redis_failure_on_the_lock_still_raises_the_fetch_error(self, fake_cache, monkeypatch):
        async def lock_refused(*_a, **_kw):
            raise redis.ConnectionError("connection reset")

        monkeypatch.setattr(fake_cache._client, "set", lock_refused)
        calls = []

        async def fetch():
            calls.append("fetch")
            raise RuntimeError("upstream answered 503")

        with pytest.raises(RuntimeError, match="503"):
            await fake_cache.get_or_fetch_with_lock("deps:npm:a:1.0.0", fetch, _TTL, reraise_fetch_errors=True)
        assert calls == ["fetch"]

    @pytest.mark.asyncio
    async def test_a_fetch_after_the_lock_wait_times_out_raises_once(self, fake_cache):
        key = "deps:npm:b:1.0.0"
        await fake_cache._client.set(fake_cache._make_key(f"lock:{key}"), "peer-token")
        calls = []

        async def fetch():
            calls.append("fetch")
            raise RuntimeError("upstream answered 503")

        with pytest.raises(RuntimeError, match="503"):
            await fake_cache.get_or_fetch_with_lock(key, fetch, _TTL, max_wait_seconds=0.3, reraise_fetch_errors=True)
        assert calls == ["fetch"]


class TestAtomicPrimitives:
    @pytest.mark.asyncio
    async def test_incr_counts_inside_the_window_the_first_hit_opened(self, fake_cache):
        full_key = fake_cache._make_key("rate_limit:k")

        assert await fake_cache.incr("rate_limit:k", 60) == 1
        await fake_cache._client.expire(full_key, 5)

        assert await fake_cache.incr("rate_limit:k", 60) == 2
        assert await fake_cache._client.ttl(full_key) <= 5

    @pytest.mark.asyncio
    async def test_incr_continues_a_count_the_json_cache_wrote(self, fake_cache):
        await fake_cache.set("rate_limit:k", 2, ttl_seconds=60)

        assert await fake_cache.incr("rate_limit:k", 60) == 3

    @pytest.mark.asyncio
    async def test_pop_hands_a_value_out_once(self, fake_cache):
        await fake_cache.set("oidc_state:s", True, ttl_seconds=60)

        assert await fake_cache.pop("oidc_state:s") is True
        assert await fake_cache.pop("oidc_state:s") is None

    @pytest.mark.asyncio
    async def test_eval_runs_its_script_over_the_prefixed_key(self, fake_cache):
        script = "redis.call('SET', KEYS[1], ARGV[1]) return redis.call('GET', KEYS[1])"

        assert await fake_cache.eval(script, "chat:rl:u:minute", "v") == "v"
        assert await fake_cache._client.get(fake_cache._make_key("chat:rl:u:minute")) == "v"


_OPERATIONS = {
    "get": (lambda c: c.get("k"), None),
    "set": (lambda c: c.set("k", 1, _TTL), False),
    "mget": (lambda c: c.mget(["k", "j"]), {"k": None, "j": None}),
    "mset": (lambda c: c.mset({"k": 1}, _TTL), False),
    "incr": (lambda c: c.incr("n", 60), None),
    "pop": (lambda c: c.pop("k"), None),
    "eval": (lambda c: c.eval("return 1", "k"), None),
}


def _disconnect(cache, _monkeypatch):
    server = fakeredis.FakeServer()
    server.connected = False
    cache._client = fakeredis.aioredis.FakeRedis(server=server)


def _time_out(cache, monkeypatch):
    monkeypatch.setattr(cache, "get_client", AsyncMock(side_effect=asyncio.TimeoutError))


class TestFailuresFallBackToTheDefault:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation", _OPERATIONS)
    @pytest.mark.parametrize("lose_redis", [_disconnect, _time_out], ids=["unreachable", "timeout"])
    async def test_a_lost_redis_answers_the_default_pauses_the_cache_and_still_times_the_call(
        self, fake_cache, monkeypatch, lose_redis, operation
    ):
        call, default = _OPERATIONS[operation]
        lose_redis(fake_cache, monkeypatch)
        timing = ("cache_operation_duration_seconds_count", {"operation": operation})
        timed = REGISTRY.get_sample_value(*timing) or 0.0

        assert await call(fake_cache) == default
        assert fake_cache._available is False
        assert REGISTRY.get_sample_value(*timing) == timed + 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation", _OPERATIONS)
    async def test_a_cancelled_call_propagates_the_cancellation_and_still_times_the_call(
        self, fake_cache, monkeypatch, operation
    ):
        call, _default = _OPERATIONS[operation]
        monkeypatch.setattr(fake_cache, "get_client", AsyncMock(side_effect=asyncio.CancelledError))
        timing = ("cache_operation_duration_seconds_count", {"operation": operation})
        timed = REGISTRY.get_sample_value(*timing) or 0.0

        with pytest.raises(asyncio.CancelledError):
            await call(fake_cache)
        assert REGISTRY.get_sample_value(*timing) == timed + 1

    @pytest.mark.asyncio
    async def test_a_corrupt_entry_reads_as_absent(self, fake_cache):
        await fake_cache._client.set(fake_cache._make_key("bad"), "{not json")
        await fake_cache.set("good", 1, _TTL)

        assert await fake_cache.get("bad") is None
        assert await fake_cache.mget(["bad", "good"]) == {"bad": None, "good": 1}
        assert await fake_cache.pop("bad") is None
        assert fake_cache._available is True

    @pytest.mark.asyncio
    async def test_an_unserializable_value_is_not_stored_and_keeps_the_cache_up(self, fake_cache):
        circular: list = []
        circular.append(circular)

        assert await fake_cache.set("k", circular, _TTL) is False
        assert await fake_cache.mset({"k": circular}, _TTL) is False
        assert await fake_cache._client.exists(fake_cache._make_key("k")) == 0
        assert fake_cache._available is True


@pytest.mark.asyncio
async def test_a_failed_stats_read_reaches_the_housekeeping_loop(fake_cache, monkeypatch):
    fake_cache._client = AsyncMock(info=AsyncMock(side_effect=redis.ConnectionError("reset")))
    monkeypatch.setattr(cache_module, "cache_service", fake_cache)

    with pytest.raises(redis.ConnectionError):
        await cache_module.update_cache_stats()
