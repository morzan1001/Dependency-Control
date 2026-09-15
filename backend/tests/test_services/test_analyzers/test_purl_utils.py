"""Tests for PURL parsing and utility functions."""

import pytest

from app.services.analyzers.purl_utils import (
    MAX_NAME_LENGTH,
    MAX_PURL_LENGTH,
    MAX_VERSION_LENGTH,
    get_purl_type,
    is_cargo,
    is_go,
    is_maven,
    is_npm,
    is_nuget,
    is_purl_type,
    is_pypi,
    normalize_hash_algorithm,
    parse_purl,
)


class TestParsePurl:
    @pytest.mark.parametrize(
        ("purl_key", "expected_fields"),
        [
            pytest.param(
                "pypi",
                {"type": "pypi", "name": "requests", "version": "2.31.0", "namespace": None},
                id="simple_pypi",
            ),
            pytest.param("npm", {"type": "npm", "name": "express", "version": "4.18.2"}, id="npm"),
            pytest.param(
                "npm_scoped",
                {"type": "npm", "namespace": "@angular", "name": "core", "version": "16.0.0"},
                id="npm_scoped",
            ),
            pytest.param(
                "maven",
                {"type": "maven", "namespace": "org.apache.commons", "name": "commons-lang3", "version": "3.12.0"},
                id="maven_with_namespace",
            ),
            pytest.param("cargo", {"type": "cargo", "name": "serde", "version": "1.0.188"}, id="cargo"),
            pytest.param("nuget", {"type": "nuget", "name": "Newtonsoft.Json", "version": "13.0.3"}, id="nuget"),
            pytest.param(
                "with_qualifiers",
                {"qualifiers": {"repository_url": "https://pypi.org"}, "version": "2.31.0"},
                id="with_qualifiers",
            ),
            pytest.param("with_subpath", {"subpath": "dist/lodash.min.js"}, id="with_subpath"),
        ],
    )
    def test_parse_reads_the_coordinates_of(self, sample_purls, purl_key, expected_fields):
        result = parse_purl(sample_purls[purl_key])
        assert result is not None
        for field, expected in expected_fields.items():
            assert getattr(result, field) == expected

    def test_parse_go_purl(self, sample_purls):
        result = parse_purl(sample_purls["go"])
        assert result is not None
        assert result.type == "golang"
        assert result.namespace == "github.com"
        assert "gin" in result.name
        assert result.version == "1.9.1"

    @pytest.mark.parametrize(
        "malformed",
        [
            pytest.param("", id="empty_string"),
            pytest.param(None, id="none"),
            pytest.param("http://example.com", id="non_pkg_prefix"),
            pytest.param("pkg:pypi", id="no_slash"),
            pytest.param("pkg:pypi/" + "a" * (MAX_PURL_LENGTH + 1), id="exceeding_max_length"),
            pytest.param(f"pkg:pypi/{'a' * (MAX_NAME_LENGTH + 1)}@1.0.0", id="name_exceeding_max"),
            pytest.param(f"pkg:pypi/requests@{'1.' * (MAX_VERSION_LENGTH + 1)}", id="version_exceeding_max"),
        ],
    )
    def test_parse_returns_none_for(self, malformed):
        assert parse_purl(malformed) is None

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
    @pytest.mark.parametrize(
        ("purl", "expected"),
        [
            pytest.param("pkg:maven/org.apache/commons@1.0", "org.apache/commons", id="with_namespace"),
            pytest.param("pkg:pypi/requests@1.0", "requests", id="without_namespace"),
        ],
    )
    def test_full_name(self, purl, expected):
        result = parse_purl(purl)
        assert result is not None
        assert result.full_name == expected

    @pytest.mark.parametrize(
        ("purl", "expected"),
        [
            pytest.param("pkg:pypi/requests@1.0", "pypi", id="pypi"),
            pytest.param("pkg:golang/github.com/gin-gonic/gin@1.0", "go", id="golang"),
            pytest.param("pkg:gem/rails@7.0", "rubygems", id="gem"),
            pytest.param("pkg:unknown/package@1.0", None, id="unknown_type"),
        ],
    )
    def test_registry_system(self, purl, expected):
        result = parse_purl(purl)
        assert result is not None
        assert result.registry_system == expected

    @pytest.mark.parametrize(
        ("purl", "expected"),
        [
            pytest.param("pkg:maven/org.apache/commons@1.0", "org.apache:commons", id="maven"),
            pytest.param("pkg:npm/%40angular/core@16.0.0", "@angular/core", id="npm_scoped"),
            pytest.param("pkg:pypi/requests@1.0", "requests", id="simple"),
            # deps.dev serves PyPI packages under their PEP 503 name; unnormalized
            # purls (underscores, dots, mixed case) 404 otherwise.
            pytest.param("pkg:pypi/My_Package.Name@1.0", "my-package-name", id="pypi_pep503_normalized"),
            # A Go module name must not double the domain prefix.
            pytest.param("pkg:golang/github.com/gin-gonic/gin@1.9.1", "github.com/gin-gonic/gin", id="go_no_doubling"),
            pytest.param(
                "pkg:golang/github.com/cespare/xxhash/v2@v2.3.0", "github.com/cespare/xxhash/v2", id="go_nested"
            ),
        ],
    )
    def test_deps_dev_name(self, purl, expected):
        result = parse_purl(purl)
        assert result.deps_dev_name == expected


class TestGetPurlType:
    @pytest.mark.parametrize(
        ("purl", "expected"),
        [
            pytest.param("pkg:pypi/requests@2.31.0", "pypi", id="extracts_pypi"),
            pytest.param("pkg:npm/express@4.0.0", "npm", id="extracts_npm"),
            pytest.param("pkg:NPM/express@1.0", "npm", id="normalizes_case"),
        ],
    )
    def test_extracts_the_type(self, purl, expected):
        assert get_purl_type(purl) == expected

    @pytest.mark.parametrize(
        "malformed",
        [
            pytest.param("", id="empty"),
            pytest.param(None, id="none"),
            pytest.param("http://example.com", id="non_pkg"),
        ],
    )
    def test_returns_none_for(self, malformed):
        assert get_purl_type(malformed) is None


class TestIsPurlType:
    @pytest.mark.parametrize(
        ("purl", "wanted", "expected"),
        [
            pytest.param("pkg:pypi/requests@1.0", "pypi", True, id="single_match"),
            pytest.param("pkg:pypi/requests@1.0", "npm", False, id="single_mismatch"),
            pytest.param("pkg:golang/gin@1.0", ("go", "golang"), True, id="tuple_match"),
            pytest.param("pkg:pypi/requests@1.0", ("npm", "maven"), False, id="tuple_no_match"),
        ],
    )
    def test_is_purl_type(self, purl, wanted, expected):
        assert is_purl_type(purl, wanted) is expected


class TestConvenienceFunctions:
    @pytest.mark.parametrize(
        ("predicate", "own_type_purl", "foreign_purl"),
        [
            pytest.param(is_pypi, "pkg:pypi/requests@2.31.0", "pkg:npm/express@4.0.0", id="is_pypi"),
            pytest.param(is_npm, "pkg:npm/express@4.0.0", "pkg:pypi/requests@1.0", id="is_npm"),
            pytest.param(is_maven, "pkg:maven/org.apache/commons@1.0", "pkg:pypi/requests@1.0", id="is_maven"),
            pytest.param(is_cargo, "pkg:cargo/serde@1.0", "pkg:npm/express@1.0", id="is_cargo"),
            pytest.param(is_nuget, "pkg:nuget/Newtonsoft.Json@13.0", "pkg:pypi/requests@1.0", id="is_nuget"),
        ],
    )
    def test_accepts_its_own_type_and_rejects_a_foreign_one(self, predicate, own_type_purl, foreign_purl):
        assert predicate(own_type_purl) is True
        assert predicate(foreign_purl) is False

    @pytest.mark.parametrize(
        ("purl", "expected"),
        [
            pytest.param("pkg:golang/gin@1.0", True, id="golang"),
            pytest.param("pkg:go/gin@1.0", True, id="go"),
            pytest.param("pkg:pypi/requests@1.0", False, id="not_go"),
        ],
    )
    def test_is_go_accepts_both_spellings_of_the_type(self, purl, expected):
        assert is_go(purl) is expected


class TestNormalizeHashAlgorithm:
    @pytest.mark.parametrize(
        ("algorithm", "expected"),
        [
            pytest.param("SHA-256", "sha256", id="sha256_uppercase_with_hyphen"),
            pytest.param("sha512", "sha512", id="sha512_lowercase_no_hyphen"),
            pytest.param("MD5", "md5", id="md5"),
            pytest.param("SHA-1", "sha1", id="sha1_with_hyphen"),
            pytest.param("", "", id="empty_string"),
            pytest.param(None, "", id="none"),
        ],
    )
    def test_normalize_hash_algorithm(self, algorithm, expected):
        assert normalize_hash_algorithm(algorithm) == expected
