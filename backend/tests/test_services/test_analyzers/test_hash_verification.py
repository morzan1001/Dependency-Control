"""Hash verification compares the parser's component hashes with the registry's digests for that exact version."""

import asyncio
from typing import Any, Self

import httpx
import pytest

from app.core.cache import CacheKeys
from app.core.constants import ANALYZER_BATCH_SIZES, NPM_REGISTRY_URL
from app.core.http_utils import InstrumentedAsyncClient
from app.models.finding import Severity
from app.services.aggregation import ResultAggregator
from app.services.analyzers import hash_verification
from app.services.analyzers.hash_verification import HashVerificationAnalyzer, normalize_hash_algorithm
from tests.helpers.analyzers import analyze_cyclonedx


class _FakeClient:
    def __init__(self, payload: dict[str, Any], status_code: int = 200):
        self._payload = payload
        self._status_code = status_code
        self.urls: list[str] = []

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def get(self, url: str, **_kwargs: Any) -> httpx.Response:
        self.urls.append(url)
        return httpx.Response(self._status_code, json=self._payload, request=httpx.Request("GET", url))


class _MemoryCache:
    """Mirrors cache_service: a batched read, and a locked fetch that stores what the fetch returned."""

    def __init__(self, entries: dict[str, Any] | None = None):
        self.entries = dict(entries or {})
        self.mget_calls: list[list[str]] = []

    async def mget(self, keys: list[str]) -> dict[str, Any]:
        self.mget_calls.append(list(keys))
        return {key: self.entries.get(key) for key in keys}

    async def get_or_fetch_with_lock(
        self, key: str, fetch_fn, ttl_seconds: int | None = None, reraise_fetch_errors: bool = False
    ) -> Any:
        if self.entries.get(key) is not None:
            return self.entries[key]
        value = await fetch_fn()
        self.entries[key] = {} if value is None else value
        return value


# sha256 digests for three released files of the same version.
_MAC_WHEEL_SHA256 = "a" * 64
_MANYLINUX_WHEEL_SHA256 = "b" * 64
_SDIST_SHA256 = "c" * 64

_PYPI_PAYLOAD = {
    "urls": [
        {"digests": {"sha256": _MAC_WHEEL_SHA256}},
        {"digests": {"sha256": _MANYLINUX_WHEEL_SHA256}},
        {"digests": {"sha256": _SDIST_SHA256}},
    ]
}


def _numpy(*hashes: tuple[str, str], version: str | None = "1.26.4") -> dict[str, Any]:
    component: dict[str, Any] = {"type": "library", "name": "numpy", "purl": "pkg:pypi/numpy"}
    if version:
        component |= {"version": version, "purl": f"pkg:pypi/numpy@{version}"}
    component["hashes"] = [{"alg": alg, "content": content} for alg, content in hashes]
    return component


def _left_pad(*hashes: tuple[str, str]) -> dict[str, Any]:
    return {
        "type": "library",
        "name": "left-pad",
        "version": "1.0.0",
        "purl": "pkg:npm/left-pad@1.0.0",
        "hashes": [{"alg": alg, "content": content} for alg, content in hashes],
    }


async def _verify(
    monkeypatch, components: list[dict[str, Any]], client: Any, cache: _MemoryCache | None = None
) -> dict[str, Any]:
    monkeypatch.setattr(hash_verification, "InstrumentedAsyncClient", lambda *_a, **_k: client)
    monkeypatch.setattr(hash_verification, "cache_service", cache or _MemoryCache())
    return await analyze_cyclonedx(HashVerificationAnalyzer(), components)


@pytest.mark.asyncio
async def test_fetch_pypi_collects_all_file_digests():
    result = await HashVerificationAnalyzer()._fetch_registry_hashes(
        _FakeClient(_PYPI_PAYLOAD), "pypi", "numpy", "1.26.4"
    )

    assert set(result["sha256"]) == {_MAC_WHEEL_SHA256, _MANYLINUX_WHEEL_SHA256, _SDIST_SHA256}


@pytest.mark.asyncio
async def test_non_first_wheel_hash_is_verified_not_flagged(monkeypatch):
    result = await _verify(monkeypatch, [_numpy(("SHA-256", _MANYLINUX_WHEEL_SHA256))], _FakeClient(_PYPI_PAYLOAD))

    assert result["hash_issues"] == []
    assert result["summary"] == {"verified_count": 1, "unverifiable_count": 0, "mismatch_count": 0}


@pytest.mark.asyncio
async def test_genuinely_wrong_hash_is_a_critical_finding(monkeypatch):
    result = await _verify(monkeypatch, [_numpy(("SHA-256", "d" * 64))], _FakeClient(_PYPI_PAYLOAD))
    aggregator = ResultAggregator()
    aggregator.aggregate("hash_verification", result)

    [issue] = result["hash_issues"]
    assert set(issue["expected_hashes"]) == {_MAC_WHEEL_SHA256, _MANYLINUX_WHEEL_SHA256, _SDIST_SHA256}
    assert [finding.severity for finding in aggregator.get_findings()] == [Severity.CRITICAL]


@pytest.mark.asyncio
async def test_the_finding_takes_the_severity_the_analyzer_gave(monkeypatch):
    result = await _verify(monkeypatch, [_numpy(("SHA-256", "d" * 64))], _FakeClient(_PYPI_PAYLOAD))
    result["hash_issues"][0]["severity"] = Severity.HIGH.value
    aggregator = ResultAggregator()

    aggregator.aggregate("hash_verification", result)

    assert [finding.severity for finding in aggregator.get_findings()] == [Severity.HIGH]


@pytest.mark.asyncio
async def test_uppercase_registry_digest_verifies_against_the_sbom_hash(monkeypatch):
    client = _FakeClient({"urls": [{"digests": {"sha256": _SDIST_SHA256.upper()}}]})

    result = await _verify(monkeypatch, [_numpy(("SHA-256", _SDIST_SHA256))], client)

    assert result["summary"]["verified_count"] == 1


@pytest.mark.asyncio
async def test_a_404_from_pypi_is_a_negative_result_not_a_transient_error():
    """{} is cached as the release being absent; a transient failure raises and is cached nowhere."""
    result = await HashVerificationAnalyzer()._fetch_registry_hashes(
        _FakeClient({}, status_code=404), "pypi", "nonexistent-pkg", "1.0.0"
    )

    assert result == {}


@pytest.mark.parametrize("status", [429, 503])
@pytest.mark.asyncio
async def test_a_registry_outage_skips_the_component_and_is_asked_again_next_scan(fake_cache, monkeypatch, status):
    answers = [httpx.Response(status), httpx.Response(200, json={"dist": {"shasum": "e" * 40}})]
    transport = httpx.MockTransport(lambda _request: answers.pop(0))
    monkeypatch.setattr(
        hash_verification,
        "InstrumentedAsyncClient",
        lambda service, **kwargs: InstrumentedAsyncClient(service, transport=transport, **kwargs),
    )
    monkeypatch.setattr(hash_verification, "cache_service", fake_cache)
    component = _left_pad(("SHA-1", "f" * 40))

    outage = await analyze_cyclonedx(HashVerificationAnalyzer(), [component])
    cached = await fake_cache.get(CacheKeys.package_hash("npm", "left-pad", "1.0.0"))
    recovered = await analyze_cyclonedx(HashVerificationAnalyzer(), [component])

    assert outage["partial_components_skipped"] == 1
    assert cached is None
    assert [issue["severity"] for issue in recovered["hash_issues"]] == [Severity.CRITICAL.value]


@pytest.mark.asyncio
async def test_a_scoped_npm_package_is_requested_with_an_escaped_slash():
    client = _FakeClient({"dist": {"shasum": "e" * 40}})

    await HashVerificationAnalyzer()._fetch_registry_hashes(client, "npm", "@babel/core", "7.24.0")

    assert client.urls == [f"{NPM_REGISTRY_URL}/@babel%2Fcore/7.24.0"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sbom_sha1", "verified", "mismatches"),
    [
        pytest.param("E" * 40, 1, 0, id="same_digest_other_case"),
        pytest.param("f" * 40, 0, 1, id="other_digest"),
    ],
)
async def test_npm_single_digest_per_algorithm_is_compared(monkeypatch, sbom_sha1, verified, mismatches):
    client = _FakeClient({"dist": {"shasum": "e" * 40}})

    result = await _verify(monkeypatch, [_left_pad(("SHA-1", sbom_sha1))], client)

    assert result["summary"]["verified_count"] == verified
    assert result["summary"]["mismatch_count"] == mismatches


@pytest.mark.asyncio
async def test_a_component_without_a_hash_makes_no_registry_request(monkeypatch):
    client = _FakeClient(_PYPI_PAYLOAD)

    result = await _verify(monkeypatch, [_numpy()], client)

    assert client.urls == []
    assert result == {
        "hash_issues": [],
        "summary": {"verified_count": 0, "unverifiable_count": 1, "mismatch_count": 0},
    }


@pytest.mark.asyncio
async def test_a_component_without_a_version_makes_no_registry_request(monkeypatch):
    client = _FakeClient(_PYPI_PAYLOAD)

    result = await _verify(monkeypatch, [_numpy(("SHA-256", _SDIST_SHA256), version=None)], client)

    assert client.urls == []
    assert result["summary"]["unverifiable_count"] == 1


@pytest.mark.asyncio
async def test_all_registry_hashes_are_read_from_the_cache_in_one_batch(monkeypatch):
    numpy_key = CacheKeys.package_hash("pypi", "numpy", "1.26.4")
    left_pad_key = CacheKeys.package_hash("npm", "left-pad", "1.0.0")
    cache = _MemoryCache({numpy_key: {"sha256": [_SDIST_SHA256]}, left_pad_key: {"sha1": "e" * 40}})
    client = _FakeClient({})
    components = [_numpy(("SHA-256", _SDIST_SHA256)), _left_pad(("SHA-1", "e" * 40))]

    result = await _verify(monkeypatch, components, client, cache)

    assert [sorted(keys) for keys in cache.mget_calls] == [sorted([numpy_key, left_pad_key])]
    assert client.urls == []
    assert result["summary"]["verified_count"] == 2


class _ConcurrencyProbe:
    """Stands in for the registry client and records how many requests are in flight at once."""

    def __init__(self) -> None:
        self.live = 0
        self.peak = 0

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def get(self, _url: str, **_kwargs: Any) -> httpx.Response:
        self.live += 1
        self.peak = max(self.peak, self.live)
        await asyncio.sleep(0)
        self.live -= 1
        return httpx.Response(404)


@pytest.mark.asyncio
async def test_registry_fan_out_is_bounded(monkeypatch):
    """One outbound request per component, so an unbounded gather turns an SBOM into a fan-out amplifier."""
    probe = _ConcurrencyProbe()
    components = [
        {
            "type": "library",
            "name": f"pkg{i}",
            "version": "1.0.0",
            "purl": f"pkg:npm/pkg{i}@1.0.0",
            "hashes": [{"alg": "SHA-1", "content": "0" * 40}],
        }
        for i in range(200)
    ]

    await _verify(monkeypatch, components, probe)

    assert probe.peak == ANALYZER_BATCH_SIZES["hash_verification"]
    assert probe.live == 0


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
def test_normalize_hash_algorithm(algorithm, expected):
    assert normalize_hash_algorithm(algorithm) == expected
