"""Tests that the PyPI hash verifier collects every file's digest per algorithm, not just the first."""

import asyncio
from typing import Any

import pytest

from app.models.finding import Severity
from app.services.analyzers import hash_verification
from app.services.analyzers.hash_verification import HashVerificationAnalyzer


class _FakeResponse:
    def __init__(self, payload: dict[str, Any], status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeClient:
    def __init__(self, payload: dict[str, Any], status_code: int = 200):
        self._payload = payload
        self._status_code = status_code

    async def get(self, url: str) -> _FakeResponse:
        return _FakeResponse(self._payload, self._status_code)


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


@pytest.mark.asyncio
async def test_fetch_pypi_collects_all_file_digests():
    analyzer = HashVerificationAnalyzer()
    client = _FakeClient(_PYPI_PAYLOAD)

    result = await analyzer._fetch_pypi_registry_hashes(client, "numpy", "1.26.4")

    assert set(result["sha256"]) == {
        _MAC_WHEEL_SHA256,
        _MANYLINUX_WHEEL_SHA256,
        _SDIST_SHA256,
    }


@pytest.mark.asyncio
async def test_non_first_wheel_hash_is_verified_not_flagged():
    """The manylinux wheel hash (2nd urls entry) must verify, not be flagged."""
    analyzer = HashVerificationAnalyzer()
    client = _FakeClient(_PYPI_PAYLOAD)

    registry_hashes_flat = await analyzer._fetch_pypi_registry_hashes(client, "numpy", "1.26.4")

    sbom_hashes = {"sha256": _MANYLINUX_WHEEL_SHA256}
    result = analyzer._evaluate_registry_hashes(registry_hashes_flat, sbom_hashes, "numpy", "1.26.4", "pypi")

    assert result == {"verified": True}


@pytest.mark.asyncio
async def test_genuinely_wrong_hash_still_flagged():
    """A hash matching none of the files is still a CRITICAL mismatch."""
    analyzer = HashVerificationAnalyzer()
    client = _FakeClient(_PYPI_PAYLOAD)

    registry_hashes_flat = await analyzer._fetch_pypi_registry_hashes(client, "numpy", "1.26.4")

    sbom_hashes = {"sha256": "d" * 64}
    result = analyzer._evaluate_registry_hashes(registry_hashes_flat, sbom_hashes, "numpy", "1.26.4", "pypi")

    assert result is not None
    assert result["mismatch"] is True
    assert result["severity"] == Severity.CRITICAL.value
    assert set(result["expected_hashes"]) == {
        _MAC_WHEEL_SHA256,
        _MANYLINUX_WHEEL_SHA256,
        _SDIST_SHA256,
    }


class _ConcurrencyProbe:
    """Stands in for the registry client and records how many requests are in flight at once."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.live = 0
        self.peak = 0

    async def __aenter__(self) -> "_ConcurrencyProbe":
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def get(self, _url: str) -> _FakeResponse:
        self.live += 1
        self.peak = max(self.peak, self.live)
        await asyncio.sleep(0)
        self.live -= 1
        return _FakeResponse({}, status_code=404)


_FAN_OUT_COMPONENTS = 200


@pytest.mark.asyncio
async def test_registry_fan_out_is_bounded(monkeypatch):
    """One outbound request per component, so an unbounded gather turns an SBOM into a fan-out amplifier."""
    probe = _ConcurrencyProbe()
    monkeypatch.setattr(hash_verification, "InstrumentedAsyncClient", lambda *a, **k: probe)

    async def _fetch_directly(key, fetch_fn, ttl_seconds=None):
        return await fetch_fn()

    monkeypatch.setattr(hash_verification.cache_service, "get_or_fetch_with_lock", _fetch_directly)

    components = [
        {"name": f"pkg{i}", "version": "1.0.0", "purl": f"pkg:npm/pkg{i}@1.0.0"} for i in range(_FAN_OUT_COMPONENTS)
    ]
    await HashVerificationAnalyzer().analyze({}, parsed_components=components)

    assert probe.peak == HashVerificationAnalyzer.MAX_CONCURRENT
    assert probe.live == 0


def test_evaluate_still_handles_scalar_npm_style_dict():
    """npm supplies one digest per algorithm as a plain str; keep it working."""
    analyzer = HashVerificationAnalyzer()
    registry_hashes_flat = {"sha1": "e" * 40}

    verified = analyzer._evaluate_registry_hashes(registry_hashes_flat, {"sha1": "E" * 40}, "left-pad", "1.0.0", "npm")
    assert verified == {"verified": True}

    mismatch = analyzer._evaluate_registry_hashes(registry_hashes_flat, {"sha1": "f" * 40}, "left-pad", "1.0.0", "npm")
    assert mismatch is not None and mismatch["mismatch"] is True
