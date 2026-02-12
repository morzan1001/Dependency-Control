"""Tests for cache key builders and TTL constants."""

import hashlib

from app.core.cache import CacheKeys, CacheTTL


class TestCacheTTLValues:
    """All TTL constants must be positive integers."""

    def test_lock_default_is_positive_int(self):
        """LOCK_DEFAULT should be a positive integer."""
        assert isinstance(CacheTTL.LOCK_DEFAULT, int)
        assert CacheTTL.LOCK_DEFAULT > 0

    def test_kev_catalog_is_positive_int(self):
        """KEV_CATALOG should be a positive integer."""
        assert isinstance(CacheTTL.KEV_CATALOG, int)
        assert CacheTTL.KEV_CATALOG > 0

    def test_popular_packages_is_positive_int(self):
        """POPULAR_PACKAGES should be a positive integer."""
        assert isinstance(CacheTTL.POPULAR_PACKAGES, int)
        assert CacheTTL.POPULAR_PACKAGES > 0

    def test_epss_score_is_positive_int(self):
        """EPSS_SCORE should be a positive integer."""
        assert isinstance(CacheTTL.EPSS_SCORE, int)
        assert CacheTTL.EPSS_SCORE > 0

    def test_ghsa_data_is_positive_int(self):
        """GHSA_DATA should be a positive integer."""
        assert isinstance(CacheTTL.GHSA_DATA, int)
        assert CacheTTL.GHSA_DATA > 0

    def test_osv_vulnerability_is_positive_int(self):
        """OSV_VULNERABILITY should be a positive integer."""
        assert isinstance(CacheTTL.OSV_VULNERABILITY, int)
        assert CacheTTL.OSV_VULNERABILITY > 0

    def test_deps_dev_metadata_is_positive_int(self):
        """DEPS_DEV_METADATA should be a positive integer."""
        assert isinstance(CacheTTL.DEPS_DEV_METADATA, int)
        assert CacheTTL.DEPS_DEV_METADATA > 0

    def test_deps_dev_scorecard_is_positive_int(self):
        """DEPS_DEV_SCORECARD should be a positive integer."""
        assert isinstance(CacheTTL.DEPS_DEV_SCORECARD, int)
        assert CacheTTL.DEPS_DEV_SCORECARD > 0

    def test_latest_version_is_positive_int(self):
        """LATEST_VERSION should be a positive integer."""
        assert isinstance(CacheTTL.LATEST_VERSION, int)
        assert CacheTTL.LATEST_VERSION > 0

    def test_eol_status_is_positive_int(self):
        """EOL_STATUS should be a positive integer."""
        assert isinstance(CacheTTL.EOL_STATUS, int)
        assert CacheTTL.EOL_STATUS > 0

    def test_package_hash_is_positive_int(self):
        """PACKAGE_HASH should be a positive integer."""
        assert isinstance(CacheTTL.PACKAGE_HASH, int)
        assert CacheTTL.PACKAGE_HASH > 0

    def test_maintainer_info_is_positive_int(self):
        """MAINTAINER_INFO should be a positive integer."""
        assert isinstance(CacheTTL.MAINTAINER_INFO, int)
        assert CacheTTL.MAINTAINER_INFO > 0

    def test_malware_check_is_positive_int(self):
        """MALWARE_CHECK should be a positive integer."""
        assert isinstance(CacheTTL.MALWARE_CHECK, int)
        assert CacheTTL.MALWARE_CHECK > 0

    def test_negative_result_is_positive_int(self):
        """NEGATIVE_RESULT should be a positive integer."""
        assert isinstance(CacheTTL.NEGATIVE_RESULT, int)
        assert CacheTTL.NEGATIVE_RESULT > 0


class TestCacheTTLExpectedValues:
    """TTL constants should have the documented expected values."""

    def test_lock_default_is_30_seconds(self):
        """LOCK_DEFAULT should be 30 seconds."""
        assert CacheTTL.LOCK_DEFAULT == 30

    def test_kev_catalog_is_24_hours(self):
        """KEV_CATALOG should be 24 hours."""
        assert CacheTTL.KEV_CATALOG == 86400

    def test_epss_score_is_24_hours(self):
        """EPSS_SCORE should be 24 hours."""
        assert CacheTTL.EPSS_SCORE == 86400

    def test_ghsa_data_is_7_days(self):
        """GHSA_DATA should be 7 days."""
        assert CacheTTL.GHSA_DATA == 604800

    def test_osv_vulnerability_is_6_hours(self):
        """OSV_VULNERABILITY should be 6 hours."""
        assert CacheTTL.OSV_VULNERABILITY == 21600

    def test_negative_result_is_1_hour(self):
        """NEGATIVE_RESULT should be 1 hour."""
        assert CacheTTL.NEGATIVE_RESULT == 3600


class TestCacheKeysKevCatalog:
    """Tests for CacheKeys.kev_catalog static method."""

    def test_returns_fixed_string(self):
        """kev_catalog should return the static key."""
        assert CacheKeys.kev_catalog() == "kev:catalog"

    def test_returns_string_type(self):
        """kev_catalog should return a string."""
        assert isinstance(CacheKeys.kev_catalog(), str)


class TestCacheKeysEpss:
    """Tests for CacheKeys.epss static method."""

    def test_basic_cve_id(self):
        """epss should format with 'epss:' prefix."""
        assert CacheKeys.epss("CVE-2024-001") == "epss:CVE-2024-001"

    def test_another_cve_id(self):
        """epss should work with different CVE IDs."""
        assert CacheKeys.epss("CVE-2023-44487") == "epss:CVE-2023-44487"

    def test_empty_cve_id(self):
        """epss should handle empty string input."""
        assert CacheKeys.epss("") == "epss:"


class TestCacheKeysGhsa:
    """Tests for CacheKeys.ghsa static method."""

    def test_basic_ghsa_id(self):
        """ghsa should format with 'ghsa:' prefix."""
        assert CacheKeys.ghsa("GHSA-abcd-1234-efgh") == "ghsa:GHSA-abcd-1234-efgh"

    def test_another_ghsa_id(self):
        """ghsa should work with different GHSA IDs."""
        assert CacheKeys.ghsa("GHSA-xyzw-9876-ijkl") == "ghsa:GHSA-xyzw-9876-ijkl"


class TestCacheKeysOsv:
    """Tests for CacheKeys.osv static method."""

    def _expected_osv_key(self, purl: str) -> str:
        """Build expected osv key from a PURL."""
        purl_hash = hashlib.md5(purl.encode()).hexdigest()[:16]
        return f"osv:{purl_hash}"

    def test_basic_purl(self):
        """osv should use MD5 hash prefix of the PURL."""
        purl = "pkg:pypi/requests@2.31.0"
        assert CacheKeys.osv(purl) == self._expected_osv_key(purl)

    def test_deterministic(self):
        """osv should return the same key for the same PURL."""
        purl = "pkg:npm/lodash@4.17.21"
        assert CacheKeys.osv(purl) == CacheKeys.osv(purl)

    def test_different_purls_differ(self):
        """osv should return different keys for different PURLs."""
        assert CacheKeys.osv("pkg:pypi/flask@2.0") != CacheKeys.osv("pkg:pypi/django@4.0")

    def test_uses_16_char_hex_prefix(self):
        """osv key should contain a 16-character hex hash."""
        key = CacheKeys.osv("pkg:pypi/test@1.0")
        hash_part = key.split(":", 1)[1]
        assert len(hash_part) == 16
        assert all(c in "0123456789abcdef" for c in hash_part)

    def test_long_purl(self):
        """osv should handle very long PURLs via hashing."""
        long_purl = "pkg:npm/@very-long-scope/very-long-package-name@99.99.99"
        result = CacheKeys.osv(long_purl)
        assert result.startswith("osv:")
        assert result == self._expected_osv_key(long_purl)


class TestCacheKeysDepsDev:
    """Tests for CacheKeys.deps_dev static method."""

    def test_pypi_package(self):
        """deps_dev should format system, package, and version."""
        assert CacheKeys.deps_dev("pypi", "requests", "2.31.0") == "deps:pypi:requests:2.31.0"

    def test_npm_package(self):
        """deps_dev should work with npm packages."""
        assert CacheKeys.deps_dev("npm", "lodash", "4.17.21") == "deps:npm:lodash:4.17.21"

    def test_maven_package(self):
        """deps_dev should work with maven packages."""
        assert CacheKeys.deps_dev("maven", "org.apache:commons", "1.0") == "deps:maven:org.apache:commons:1.0"


class TestCacheKeysDevsDevScorecard:
    """Tests for CacheKeys.deps_dev_scorecard static method."""

    def test_basic_project_id(self):
        """deps_dev_scorecard should format with 'scorecard:' prefix."""
        assert CacheKeys.deps_dev_scorecard("github.com/org/repo") == "scorecard:github.com/org/repo"

    def test_different_project(self):
        """deps_dev_scorecard should work with different project IDs."""
        assert CacheKeys.deps_dev_scorecard("gitlab.com/group/proj") == "scorecard:gitlab.com/group/proj"


class TestCacheKeysLatestVersion:
    """Tests for CacheKeys.latest_version static method."""

    def test_pypi_package(self):
        """latest_version should format system and package."""
        assert CacheKeys.latest_version("pypi", "requests") == "latest:pypi:requests"

    def test_npm_package(self):
        """latest_version should work with npm packages."""
        assert CacheKeys.latest_version("npm", "express") == "latest:npm:express"


class TestCacheKeysEol:
    """Tests for CacheKeys.eol static method."""

    def test_basic_product(self):
        """eol should format with 'eol:' prefix."""
        assert CacheKeys.eol("python") == "eol:python"

    def test_another_product(self):
        """eol should work with different products."""
        assert CacheKeys.eol("nodejs") == "eol:nodejs"


class TestCacheKeysPackageHash:
    """Tests for CacheKeys.package_hash static method."""

    def test_basic_package(self):
        """package_hash should format system, package, and version."""
        assert CacheKeys.package_hash("pypi", "requests", "2.31.0") == "hash:pypi:requests:2.31.0"

    def test_npm_package(self):
        """package_hash should work with npm packages."""
        assert CacheKeys.package_hash("npm", "axios", "1.6.0") == "hash:npm:axios:1.6.0"


class TestCacheKeysPopularPackages:
    """Tests for CacheKeys.popular_packages static method."""

    def test_basic_registry(self):
        """popular_packages should format with 'popular:' prefix."""
        assert CacheKeys.popular_packages("pypi") == "popular:pypi"

    def test_npm_registry(self):
        """popular_packages should work with npm registry."""
        assert CacheKeys.popular_packages("npm") == "popular:npm"


class TestCacheKeysMaintainer:
    """Tests for CacheKeys.maintainer static method."""

    def test_basic_maintainer(self):
        """maintainer should format system and package."""
        assert CacheKeys.maintainer("pypi", "requests") == "maintainer:pypi:requests"

    def test_npm_maintainer(self):
        """maintainer should work with npm packages."""
        assert CacheKeys.maintainer("npm", "express") == "maintainer:npm:express"


class TestCacheKeysMalware:
    """Tests for CacheKeys.malware static method."""

    def test_basic_malware(self):
        """malware should format registry, package, and version."""
        assert CacheKeys.malware("pypi", "requests", "2.31.0") == "malware:pypi:requests:2.31.0"

    def test_npm_malware(self):
        """malware should work with npm packages."""
        assert CacheKeys.malware("npm", "lodash", "4.17.21") == "malware:npm:lodash:4.17.21"
