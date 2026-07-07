"""Tests for the hash verification analyzer.

Regression coverage for the PyPI multi-file hash bug: a released package
ships one entry per file in ``data['urls']`` (sdist + one wheel per
platform), each with its own sha256. The verifier must collect EVERY
file's digest per algorithm, otherwise an SBOM built on a platform whose
wheel is not the first ``urls`` entry gets a false CRITICAL "tampering"
finding.
"""

from typing import Any, Dict

import pytest

from app.models.finding import Severity
from app.services.analyzers.hash_verification import HashVerificationAnalyzer


class _FakeResponse:
    def __init__(self, payload: Dict[str, Any], status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def json(self) -> Dict[str, Any]:
        return self._payload


class _FakeClient:
    def __init__(self, payload: Dict[str, Any], status_code: int = 200):
        self._payload = payload
        self._status_code = status_code

    async def get(self, url: str) -> _FakeResponse:
        return _FakeResponse(self._payload, self._status_code)


# sha256 digests for three different released files of the same version.
_MAC_WHEEL_SHA256 = "a" * 64
_MANYLINUX_WHEEL_SHA256 = "b" * 64
_SDIST_SHA256 = "c" * 64

_PYPI_PAYLOAD = {
    "urls": [
        {"digests": {"sha256": _MAC_WHEEL_SHA256}},        # macOS wheel (first)
        {"digests": {"sha256": _MANYLINUX_WHEEL_SHA256}},  # manylinux wheel
        {"digests": {"sha256": _SDIST_SHA256}},            # sdist
    ]
}


@pytest.mark.asyncio
async def test_fetch_pypi_collects_all_file_digests():
    analyzer = HashVerificationAnalyzer()
    client = _FakeClient(_PYPI_PAYLOAD)

    result = await analyzer._fetch_pypi_registry_hashes(client, "numpy", "1.26.4")

    # Every released file's sha256 must be retained, not just the first.
    assert set(result["sha256"]) == {
        _MAC_WHEEL_SHA256,
        _MANYLINUX_WHEEL_SHA256,
        _SDIST_SHA256,
    }


@pytest.mark.asyncio
async def test_non_first_wheel_hash_is_verified_not_flagged():
    """SBOM carries the manylinux wheel hash (2nd urls entry) -> must verify."""
    analyzer = HashVerificationAnalyzer()
    client = _FakeClient(_PYPI_PAYLOAD)

    registry_hashes_flat = await analyzer._fetch_pypi_registry_hashes(
        client, "numpy", "1.26.4"
    )

    sbom_hashes = {"sha256": _MANYLINUX_WHEEL_SHA256}
    result = analyzer._evaluate_registry_hashes(
        registry_hashes_flat, sbom_hashes, "numpy", "1.26.4", "pypi"
    )

    assert result == {"verified": True}


@pytest.mark.asyncio
async def test_genuinely_wrong_hash_still_flagged():
    """A hash matching none of the files is still a CRITICAL mismatch."""
    analyzer = HashVerificationAnalyzer()
    client = _FakeClient(_PYPI_PAYLOAD)

    registry_hashes_flat = await analyzer._fetch_pypi_registry_hashes(
        client, "numpy", "1.26.4"
    )

    sbom_hashes = {"sha256": "d" * 64}
    result = analyzer._evaluate_registry_hashes(
        registry_hashes_flat, sbom_hashes, "numpy", "1.26.4", "pypi"
    )

    assert result is not None
    assert result["mismatch"] is True
    assert result["severity"] == Severity.CRITICAL.value
    assert set(result["expected_hashes"]) == {
        _MAC_WHEEL_SHA256,
        _MANYLINUX_WHEEL_SHA256,
        _SDIST_SHA256,
    }


def test_evaluate_still_handles_scalar_npm_style_dict():
    """npm supplies one digest per algorithm as a plain str; keep it working."""
    analyzer = HashVerificationAnalyzer()
    registry_hashes_flat = {"sha1": "e" * 40}

    verified = analyzer._evaluate_registry_hashes(
        registry_hashes_flat, {"sha1": "E" * 40}, "left-pad", "1.0.0", "npm"
    )
    assert verified == {"verified": True}

    mismatch = analyzer._evaluate_registry_hashes(
        registry_hashes_flat, {"sha1": "f" * 40}, "left-pad", "1.0.0", "npm"
    )
    assert mismatch is not None and mismatch["mismatch"] is True
