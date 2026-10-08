"""What OSV is asked for each component, and whose name a cached answer carries."""

import json
from typing import Any

import httpx
import pytest

from app.core.cache import CacheKeys
from app.services.analyzers import osv
from app.services.analyzers.osv import OSVAnalyzer
from tests.helpers.osv import batch_queries, osv_cache, serve_osv

_SBOM: dict[str, Any] = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}


def _querybatch(rejected: frozenset[str] = frozenset(), names_index: bool = True):
    """Answers every query clean; like OSV, a ``rejected`` purl fails the batch with 400 naming its index."""

    def handle(request: httpx.Request) -> httpx.Response:
        queries = json.loads(request.content)["queries"]
        purls = [query["package"].get("purl") for query in queries]
        bad = next((index for index, purl in enumerate(purls) if purl in rejected), None)
        if bad is None:
            return httpx.Response(200, json={"results": [{} for _ in queries]})
        message = f"error in query at index {bad}: invalid qualifiers" if names_index else "Bad Request"
        return httpx.Response(400, text=f'{{"code":3,"message":"{message}"}}')

    return handle


@pytest.fixture
def cache(monkeypatch):
    return osv_cache(monkeypatch)


async def _queries(monkeypatch, components: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    seen = serve_osv(monkeypatch, _querybatch())
    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=components)
    return batch_queries(seen), result


def _npm(name: str, qualifiers: str = "") -> dict[str, Any]:
    return {"name": name, "version": "1.0.0", "purl": f"pkg:npm/{name}@1.0.0{qualifiers}"}


class TestVersionlessPurls:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("version", ["unknown", "", None])
    async def test_an_unpinned_component_is_never_a_package_wide_query(self, cache, monkeypatch, version):
        queries, result = await _queries(
            monkeypatch, [{"name": "requests", "version": version, "purl": "pkg:pypi/requests"}]
        )

        assert queries == []
        assert "partial_components_skipped" not in result

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("purl", "versioned"),
        [
            pytest.param(
                "pkg:npm/lodash?repository_url=https://r",
                "pkg:npm/lodash@4.17.21?repository_url=https://r",
                id="before_qualifiers",
            ),
            pytest.param("pkg:npm/lodash@", "pkg:npm/lodash@4.17.21", id="empty_version"),
        ],
    )
    async def test_a_versionless_purl_is_asked_at_the_component_version(self, cache, monkeypatch, purl, versioned):
        queries, _ = await _queries(monkeypatch, [{"name": "lodash", "version": "4.17.21", "purl": purl}])

        assert queries == [{"package": {"purl": versioned}}]
        assert CacheKeys.osv(versioned) in cache


class TestOperatingSystemPackages:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("component", "expected"),
        [
            pytest.param(
                {
                    "name": "libc6",
                    "version": "2.36-9",
                    "purl": "pkg:deb/debian/libc6@2.36-9?arch=amd64&upstream=glibc&distro=debian-12",
                },
                {"package": {"ecosystem": "Debian:12", "name": "glibc"}, "version": "2.36-9"},
                id="syft_debian_binary",
            ),
            pytest.param(
                {
                    "name": "libc6",
                    "version": "2.36-9+b1",
                    "purl": "pkg:deb/debian/libc6@2.36-9+b1?upstream=glibc%402.36-9&distro=debian-12",
                },
                {"package": {"ecosystem": "Debian:12", "name": "glibc"}, "version": "2.36-9"},
                id="syft_debian_source_version",
            ),
            pytest.param(
                {
                    "name": "libssl1.1",
                    "version": "1.1.1n-0+deb11u4",
                    "purl": "pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u4?arch=amd64&distro=debian-11.6",
                    "properties": {
                        "aquasecurity:trivy:SrcName": "openssl",
                        "aquasecurity:trivy:SrcVersion": "1.1.1n",
                        "aquasecurity:trivy:SrcRelease": "0+deb11u4",
                    },
                },
                {"package": {"ecosystem": "Debian:11", "name": "openssl"}, "version": "1.1.1n-0+deb11u4"},
                id="trivy_debian",
            ),
            pytest.param(
                {
                    "name": "login",
                    "version": "1:4.13+dfsg1-1+b1",
                    "purl": "pkg:deb/debian/login@4.13%2Bdfsg1-1%2Bb1?arch=amd64&distro=debian-12.5&epoch=1",
                    "properties": {
                        "aquasecurity:trivy:SrcName": "shadow",
                        "aquasecurity:trivy:SrcVersion": "4.13+dfsg1",
                        "aquasecurity:trivy:SrcRelease": "1",
                        "aquasecurity:trivy:SrcEpoch": "1",
                    },
                },
                {"package": {"ecosystem": "Debian:12", "name": "shadow"}, "version": "1:4.13+dfsg1-1"},
                id="trivy_debian_epoch",
            ),
            pytest.param(
                {
                    "name": "bash",
                    "version": "5.2.15-2+b2",
                    "purl": "pkg:deb/debian/bash@5.2.15-2+b2?arch=amd64&distro=debian-12",
                    "found_by": "dpkg-db-cataloger",
                },
                {"package": {"ecosystem": "Debian:12", "name": "bash"}, "version": "5.2.15-2+b2"},
                id="syft_debian_source_is_the_binary",
            ),
            pytest.param(
                {
                    "name": "bash",
                    "version": "5.2.15-2+b2",
                    "purl": "pkg:deb/Debian/bash@5.2.15-2+b2?arch=amd64&distro=debian-12",
                    "found_by": "dpkg-db-cataloger",
                },
                {"package": {"ecosystem": "Debian:12", "name": "bash"}, "version": "5.2.15-2+b2"},
                id="namespace_case",
            ),
            pytest.param(
                {
                    "name": "libssl3",
                    "version": "3.0.8-r0",
                    "purl": "pkg:apk/alpine/libssl3@3.0.8-r0?arch=x86_64&upstream=openssl&distro=alpine-3.17.2",
                },
                {"package": {"ecosystem": "Alpine:v3.17", "name": "openssl"}, "version": "3.0.8-r0"},
                id="syft_alpine",
            ),
            pytest.param(
                {
                    "name": "libssl3",
                    "version": "3.0.8-r0",
                    "purl": "pkg:apk/alpine/libssl3@3.0.8-r0?arch=x86_64&distro=3.17.2",
                    "properties": {"aquasecurity:trivy:SrcName": "openssl"},
                },
                {"package": {"ecosystem": "Alpine:v3.17", "name": "openssl"}, "version": "3.0.8-r0"},
                id="trivy_alpine",
            ),
            pytest.param(
                {"name": "openssl", "version": "3.0.2", "purl": "pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-22.04"},
                {"package": {"purl": "pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-22.04"}},
                id="ubuntu_resolves_by_purl",
            ),
            pytest.param(
                {
                    "name": "libssl3",
                    "version": "3.0.2-0ubuntu1.10",
                    "purl": "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04&upstream=openssl",
                },
                {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "openssl"}, "version": "3.0.2-0ubuntu1.10"},
                id="syft_ubuntu_lts",
            ),
            pytest.param(
                {
                    "name": "zlib1g",
                    "version": "1:1.2.13.dfsg-1ubuntu4",
                    "purl": "pkg:deb/ubuntu/zlib1g@1.2.13.dfsg-1ubuntu4?arch=amd64&distro=ubuntu-23.04&epoch=1",
                    "properties": {
                        "aquasecurity:trivy:SrcName": "zlib",
                        "aquasecurity:trivy:SrcVersion": "1.2.13.dfsg",
                        "aquasecurity:trivy:SrcRelease": "1ubuntu4",
                        "aquasecurity:trivy:SrcEpoch": "1",
                    },
                },
                {"package": {"ecosystem": "Ubuntu:23.04", "name": "zlib"}, "version": "1:1.2.13.dfsg-1ubuntu4"},
                id="trivy_ubuntu_interim",
            ),
        ],
    )
    async def test_the_package_is_asked_for_in_its_release_ecosystem(self, cache, monkeypatch, component, expected):
        queries, _ = await _queries(monkeypatch, [component])

        assert queries == [expected]
        assert CacheKeys.osv(component["purl"]) in cache

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "purl",
        [
            pytest.param("pkg:deb/debian/zlib1g@1.2.13?arch=amd64", id="no_release"),
            pytest.param("pkg:deb/debian/zlib1g@1.2.13?arch=amd64&distro=debian-12", id="no_known_source"),
        ],
    )
    async def test_an_os_package_osv_cannot_resolve_is_reported_unscanned(self, cache, monkeypatch, purl):
        component = {"name": "zlib1g", "version": "1.2.13", "purl": purl}

        queries, result = await _queries(monkeypatch, [component])

        assert queries == []
        assert result["partial_components_skipped"] == 1
        assert cache == {}


class TestMalformedPurls:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "purl",
        [
            "pkg:npm/foo%zz@1",
            "pkg:npm/foo@1.0%",
            "pkg:npm/",
            "pkg:nuget/Foo@1.0.0?repository_url=https://x/%zz",
            "pkg:/foo@1",
            "pkg:1bad/foo@1",
            "pkg:a_b/foo@1",
        ],
    )
    async def test_a_purl_osv_rejects_is_left_out_so_the_batch_survives(self, cache, monkeypatch, purl):
        good = {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}

        queries, result = await _queries(monkeypatch, [{"name": "foo", "version": "1", "purl": purl}, good])

        assert queries == [{"package": {"purl": "pkg:npm/lodash@4.17.21"}}]
        assert result["partial_components_skipped"] == 1


class TestRejectedQueries:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("names_index", [True, False], ids=["index_named", "bisected"])
    async def test_a_query_osv_rejects_costs_only_its_own_component(self, cache, monkeypatch, names_index):
        bad = _npm("foo", "?1a=b")
        components = [_npm(f"good-{i}") for i in range(5)]
        components.insert(3, bad)
        seen = serve_osv(monkeypatch, _querybatch(rejected=frozenset({bad["purl"]}), names_index=names_index))

        result = await OSVAnalyzer().analyze(_SBOM, parsed_components=components)

        assert result["partial_components_skipped"] == 1
        assert set(cache) == {CacheKeys.osv(c["purl"]) for c in components if c is not bad}
        if names_index:
            assert len(seen) == 2

    @pytest.mark.asyncio
    async def test_resends_stop_after_the_cap(self, cache, monkeypatch):
        rejected = [_npm(f"bad-{i}", "?1a=b") for i in range(osv._MAX_REJECTION_RESENDS + 1)]
        components = [*rejected, _npm("good")]
        seen = serve_osv(monkeypatch, _querybatch(rejected=frozenset(c["purl"] for c in rejected)))

        result = await OSVAnalyzer().analyze(_SBOM, parsed_components=components)

        assert len(seen) == 1 + osv._MAX_REJECTION_RESENDS
        assert result["partial_components_skipped"] == len(components)
        assert cache == {}


class TestCachedIdentity:
    @pytest.mark.asyncio
    async def test_a_cached_answer_is_named_after_the_scanning_component(self, cache, monkeypatch):
        purl = "pkg:npm/%40angular/core@17.0.0"
        cache[CacheKeys.osv(purl)] = [{"id": "GHSA-x", "modified": "m"}]
        cache[CacheKeys.osv_vuln("GHSA-x", "m")] = {"id": "GHSA-x", "summary": "s"}
        component = {"name": "@angular/core", "version": "17.0.0", "purl": purl}

        queries, result = await _queries(monkeypatch, [component])

        assert queries == []
        [entry] = result["osv_vulnerabilities"]
        assert (entry["component"], entry["version"], entry["purl"]) == ("@angular/core", "17.0.0", purl)
