"""Tests for PURL parsing and utility functions."""

from app.services.analyzers.purl_utils import (
    ParsedPURL,
    parse_purl,
    get_purl_type,
    is_purl_type,
    is_pypi,
    is_npm,
    is_maven,
    is_go,
    is_cargo,
    is_nuget,
    normalize_hash_algorithm,
    MAX_PURL_LENGTH,
    MAX_NAME_LENGTH,
    MAX_VERSION_LENGTH,
    MAX_NAMESPACE_LENGTH,
)


class TestParsePurl:
    def test_parse_simple_pypi(self, sample_purls):
        result = parse_purl(sample_purls["pypi"])
        assert result is not None
        assert result.type == "pypi"
        assert result.name == "requests"
        assert result.version == "2.31.0"
        assert result.namespace is None

    def test_parse_npm(self, sample_purls):
        result = parse_purl(sample_purls["npm"])
        assert result is not None
        assert result.type == "npm"
        assert result.name == "express"
        assert result.version == "4.18.2"

    def test_parse_npm_scoped(self, sample_purls):
        result = parse_purl(sample_purls["npm_scoped"])
        assert result is not None
        assert result.type == "npm"
        assert result.namespace == "@angular"
        assert result.name == "core"
        assert result.version == "16.0.0"

    def test_parse_maven_with_namespace(self, sample_purls):
        result = parse_purl(sample_purls["maven"])
        assert result is not None
        assert result.type == "maven"
        assert result.namespace == "org.apache.commons"
        assert result.name == "commons-lang3"
        assert result.version == "3.12.0"

    def test_parse_go_purl(self, sample_purls):
        result = parse_purl(sample_purls["go"])
        assert result is not None
        assert result.type == "golang"
        assert result.namespace == "github.com"
        assert "gin" in result.name
        assert result.version == "1.9.1"

    def test_parse_cargo(self, sample_purls):
        result = parse_purl(sample_purls["cargo"])
        assert result is not None
        assert result.type == "cargo"
        assert result.name == "serde"
        assert result.version == "1.0.188"

    def test_parse_nuget(self, sample_purls):
        result = parse_purl(sample_purls["nuget"])
        assert result is not None
        assert result.type == "nuget"
        assert result.name == "Newtonsoft.Json"
        assert result.version == "13.0.3"

    def test_parse_with_qualifiers(self, sample_purls):
        result = parse_purl(sample_purls["with_qualifiers"])
        assert result is not None
        assert result.qualifiers == {"repository_url": "https://pypi.org"}
        assert result.version == "2.31.0"

    def test_parse_with_subpath(self, sample_purls):
        result = parse_purl(sample_purls["with_subpath"])
        assert result is not None
        assert result.subpath == "dist/lodash.min.js"

    def test_parse_returns_none_for_empty_string(self):
        assert parse_purl("") is None

    def test_parse_returns_none_for_none(self):
        assert parse_purl(None) is None

    def test_parse_returns_none_for_non_pkg_prefix(self):
        assert parse_purl("http://example.com") is None

    def test_parse_returns_none_for_no_slash(self):
        assert parse_purl("pkg:pypi") is None

    def test_parse_returns_none_for_exceeding_max_length(self):
        long_purl = "pkg:pypi/" + "a" * (MAX_PURL_LENGTH + 1)
        assert parse_purl(long_purl) is None

    def test_parse_returns_none_for_name_exceeding_max(self):
        long_name = "a" * (MAX_NAME_LENGTH + 1)
        assert parse_purl(f"pkg:pypi/{long_name}@1.0.0") is None

    def test_parse_returns_none_for_version_exceeding_max(self):
        long_version = "1." * (MAX_VERSION_LENGTH + 1)
        assert parse_purl(f"pkg:pypi/requests@{long_version}") is None

    def test_parse_type_normalized_to_lowercase(self):
        result = parse_purl("pkg:PyPI/requests@2.31.0")
        assert result is not None
        assert result.type == "pypi"

    def test_parse_no_version(self):
        result = parse_purl("pkg:pypi/requests")
        assert result is not None
        assert result.name == "requests"
        assert result.version is None

    def test_parse_with_qualifiers_and_subpath(self):
        result = parse_purl("pkg:pypi/requests@2.31.0?vcs_url=https://github.com#src")
        assert result is not None
        assert result.qualifiers == {"vcs_url": "https://github.com"}
        assert result.subpath == "src"


class TestParsedPURLProperties:
    def test_full_name_with_namespace(self):
        result = parse_purl("pkg:maven/org.apache/commons@1.0")
        assert result is not None
        assert result.full_name == "org.apache/commons"

    def test_full_name_without_namespace(self):
        result = parse_purl("pkg:pypi/requests@1.0")
        assert result is not None
        assert result.full_name == "requests"

    def test_registry_system_pypi(self):
        result = parse_purl("pkg:pypi/requests@1.0")
        assert result.registry_system == "pypi"

    def test_registry_system_golang(self):
        result = parse_purl("pkg:golang/github.com/gin-gonic/gin@1.0")
        assert result.registry_system == "go"

    def test_registry_system_gem(self):
        result = parse_purl("pkg:gem/rails@7.0")
        assert result.registry_system == "rubygems"

    def test_registry_system_unknown_type(self):
        result = parse_purl("pkg:unknown/package@1.0")
        assert result is not None
        assert result.registry_system is None

    def test_deps_dev_name_maven(self):
        result = parse_purl("pkg:maven/org.apache/commons@1.0")
        assert result.deps_dev_name == "org.apache:commons"

    def test_deps_dev_name_npm_scoped(self):
        result = parse_purl("pkg:npm/%40angular/core@16.0.0")
        assert result.deps_dev_name == "@angular/core"

    def test_deps_dev_name_simple(self):
        result = parse_purl("pkg:pypi/requests@1.0")
        assert result.deps_dev_name == "requests"

    def test_deps_dev_name_go_no_doubling(self):
        """Go module names must not double the domain prefix."""
        result = parse_purl("pkg:golang/github.com/gin-gonic/gin@1.9.1")
        assert result.deps_dev_name == "github.com/gin-gonic/gin"

    def test_deps_dev_name_go_nested(self):
        result = parse_purl("pkg:golang/github.com/cespare/xxhash/v2@v2.3.0")
        assert result.deps_dev_name == "github.com/cespare/xxhash/v2"


class TestGetPurlType:
    def test_extracts_pypi(self):
        assert get_purl_type("pkg:pypi/requests@2.31.0") == "pypi"

    def test_extracts_npm(self):
        assert get_purl_type("pkg:npm/express@4.0.0") == "npm"

    def test_returns_none_for_empty(self):
        assert get_purl_type("") is None

    def test_returns_none_for_none(self):
        assert get_purl_type(None) is None

    def test_returns_none_for_non_pkg(self):
        assert get_purl_type("http://example.com") is None

    def test_normalizes_case(self):
        assert get_purl_type("pkg:NPM/express@1.0") == "npm"


class TestIsPurlType:
    def test_single_match(self):
        assert is_purl_type("pkg:pypi/requests@1.0", "pypi") is True

    def test_single_mismatch(self):
        assert is_purl_type("pkg:pypi/requests@1.0", "npm") is False

    def test_tuple_match(self):
        assert is_purl_type("pkg:golang/gin@1.0", ("go", "golang")) is True

    def test_tuple_no_match(self):
        assert is_purl_type("pkg:pypi/requests@1.0", ("npm", "maven")) is False


class TestConvenienceFunctions:
    def test_is_pypi(self):
        assert is_pypi("pkg:pypi/requests@2.31.0") is True
        assert is_pypi("pkg:npm/express@4.0.0") is False

    def test_is_npm(self):
        assert is_npm("pkg:npm/express@4.0.0") is True
        assert is_npm("pkg:pypi/requests@1.0") is False

    def test_is_maven(self):
        assert is_maven("pkg:maven/org.apache/commons@1.0") is True
        assert is_maven("pkg:pypi/requests@1.0") is False

    def test_is_go_golang(self):
        assert is_go("pkg:golang/gin@1.0") is True

    def test_is_go_go(self):
        assert is_go("pkg:go/gin@1.0") is True

    def test_is_go_not_go(self):
        assert is_go("pkg:pypi/requests@1.0") is False

    def test_is_cargo(self):
        assert is_cargo("pkg:cargo/serde@1.0") is True
        assert is_cargo("pkg:npm/express@1.0") is False

    def test_is_nuget(self):
        assert is_nuget("pkg:nuget/Newtonsoft.Json@13.0") is True
        assert is_nuget("pkg:pypi/requests@1.0") is False


class TestNormalizeHashAlgorithm:
    def test_sha256_uppercase_with_hyphen(self):
        assert normalize_hash_algorithm("SHA-256") == "sha256"

    def test_sha512_lowercase_no_hyphen(self):
        assert normalize_hash_algorithm("sha512") == "sha512"

    def test_md5(self):
        assert normalize_hash_algorithm("MD5") == "md5"

    def test_sha1_with_hyphen(self):
        assert normalize_hash_algorithm("SHA-1") == "sha1"

    def test_empty_string(self):
        assert normalize_hash_algorithm("") == ""

    def test_none(self):
        assert normalize_hash_algorithm(None) == ""
