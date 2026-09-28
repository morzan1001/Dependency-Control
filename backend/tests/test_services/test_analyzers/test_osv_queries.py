"""What OSV is asked for each component, and whose name a cached answer carries."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.cache import CacheKeys
from app.services.analyzers.osv import OSVAnalyzer

_SBOM: dict[str, Any] = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}


def _client(results_for: Any = None) -> MagicMock:
    """A querybatch stub answering every query with no vulnerabilities, recording the payloads."""
    client = MagicMock()
    client.payloads = []

    async def _post(url: str, json: dict[str, Any]) -> MagicMock:
        client.payloads.append(json)
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"results": [{} for _ in json["queries"]]}
        return response

    client.post = AsyncMock(side_effect=_post)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


@pytest.fixture
def cache(monkeypatch):
    store: dict[str, Any] = {}

    async def _mget(keys):
        return {key: store.get(key) for key in keys}

    async def _mset(mapping, ttl=None):
        store.update(mapping)
        return True

    monkeypatch.setattr("app.services.analyzers.osv.cache_service.mget", _mget)
    monkeypatch.setattr("app.services.analyzers.osv.cache_service.mset", _mset)
    return store


async def _queries(monkeypatch, components: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    client = _client()
    monkeypatch.setattr("app.services.analyzers.osv.InstrumentedAsyncClient", lambda *a, **k: client)
    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=components)
    return [query for payload in client.payloads for query in payload["queries"]], result


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
                        "aquasecurity:trivy:SrcVersion": "1.1.1n-0+deb11u4",
                    },
                },
                {"package": {"ecosystem": "Debian:11", "name": "openssl"}, "version": "1.1.1n-0+deb11u4"},
                id="trivy_debian",
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
        ],
    )
    async def test_the_package_is_asked_for_in_its_release_ecosystem(self, cache, monkeypatch, component, expected):
        queries, _ = await _queries(monkeypatch, [component])

        assert queries == [expected]
        assert CacheKeys.osv(component["purl"]) in cache

    @pytest.mark.asyncio
    async def test_an_os_package_without_its_release_is_reported_unscanned(self, cache, monkeypatch):
        component = {"name": "zlib1g", "version": "1.2.13", "purl": "pkg:deb/debian/zlib1g@1.2.13?arch=amd64"}

        queries, result = await _queries(monkeypatch, [component])

        assert queries == []
        assert result["partial_components_skipped"] == 1
        assert cache == {}


class TestMalformedPurls:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "purl",
        ["pkg:npm/foo%zz@1", "pkg:npm/foo@1.0%", "pkg:npm/", "pkg:nuget/Foo@1.0.0?repository_url=https://x/%zz"],
    )
    async def test_a_purl_osv_rejects_is_left_out_so_the_batch_survives(self, cache, monkeypatch, purl):
        good = {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}

        queries, result = await _queries(monkeypatch, [{"name": "foo", "version": "1", "purl": purl}, good])

        assert queries == [{"package": {"purl": "pkg:npm/lodash@4.17.21"}}]
        assert result["partial_components_skipped"] == 1


class TestCachedIdentity:
    @pytest.mark.asyncio
    async def test_a_cached_answer_is_named_after_the_scanning_component(self, cache, monkeypatch):
        purl = "pkg:npm/%40angular/core@17.0.0"
        vulnerability = {"id": "GHSA-x", "severity": "HIGH", "summary": "s"}
        cache[CacheKeys.osv(purl)] = {"component": "core", "version": "17.0.0", "vulnerabilities": [vulnerability]}
        component = {"name": "@angular/core", "version": "17.0.0", "purl": purl}

        _, result = await _queries(monkeypatch, [component])

        [entry] = result["osv_vulnerabilities"]
        assert (entry["component"], entry["version"], entry["purl"]) == ("@angular/core", "17.0.0", purl)
        assert entry["message"].startswith("@angular/core@17.0.0 has 1 known vulnerability")
