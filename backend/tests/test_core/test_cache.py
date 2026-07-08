"""Tests for cache key builders and TTL constants."""

import hashlib

import fakeredis.aioredis
import pytest

from app.core.cache import CacheKeys, CacheService, CacheTTL


class TestCacheTTLValues:
    """All TTL constants must be positive integers."""

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


class TestCacheKeysRecommendations:
    """Recommendations key isolates by scan and caller scope to prevent cross-project cache sharing."""

    def test_includes_all_components(self):
        key = CacheKeys.recommendations("proj1", "scanA", "deadbeef")
        assert "proj1" in key and "scanA" in key and "deadbeef" in key

    def test_differs_by_scan(self):
        assert CacheKeys.recommendations("p", "s1", "h") != CacheKeys.recommendations("p", "s2", "h")

    def test_differs_by_scope(self):
        assert CacheKeys.recommendations("p", "s", "h1") != CacheKeys.recommendations("p", "s", "h2")


class TestCacheKeysKevCatalog:
    def test_returns_fixed_string(self):
        assert CacheKeys.kev_catalog() == "kev:catalog"

    def test_returns_string_type(self):
        assert isinstance(CacheKeys.kev_catalog(), str)


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
        return f"osv:{purl_hash}"

    def test_basic_purl(self):
        purl = "pkg:pypi/requests@2.31.0"
        assert CacheKeys.osv(purl) == self._expected_osv_key(purl)

    def test_deterministic(self):
        purl = "pkg:npm/lodash@4.17.21"
        assert CacheKeys.osv(purl) == CacheKeys.osv(purl)

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
        assert result.startswith("osv:")
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
        assert CacheKeys.latest_version("pypi", "requests") == "latest:pypi:requests"

    def test_npm_package(self):
        assert CacheKeys.latest_version("npm", "express") == "latest:npm:express"


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
        assert CacheKeys.maintainer("pypi", "requests") == "maintainer:pypi:requests"

    def test_npm_maintainer(self):
        assert CacheKeys.maintainer("npm", "express") == "maintainer:npm:express"


class TestCacheKeysMalware:
    def test_basic_malware(self):
        assert CacheKeys.malware("pypi", "requests", "2.31.0") == "malware:pypi:requests:2.31.0"

    def test_npm_malware(self):
        assert CacheKeys.malware("npm", "lodash", "4.17.21") == "malware:npm:lodash:4.17.21"


@pytest.fixture
def fake_cache():
    """A CacheService backed by an in-memory fakeredis async client."""
    svc = CacheService()
    svc._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    svc._pool = object()  # non-None so get_client() short-circuits to the fake
    svc._available = True
    return svc


class TestStampedeLockRelease:
    """get_or_fetch_with_lock must only release a lock it still owns."""

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
        # Pod B's lock must survive: the slow holder only deletes locks it owns.
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
