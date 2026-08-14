"""Embedded CBOM in a CycloneDX SBOM: _process_sbom persists both dependency and CryptoAsset records."""

import json
from pathlib import Path

import pytest

from app.repositories.crypto_asset import CryptoAssetRepository
from app.services.analysis.engine import _process_sbom

FIXTURES = Path(__file__).parent.parent / "fixtures" / "cbom"


def _load(name):
    with open(FIXTURES / name) as f:
        return json.load(f)


class _MinimalAggregator:
    """Stub aggregator that discards results — the test only checks DB side-effects."""

    def aggregate(self, *args, **kwargs):
        pass

    def get_findings(self):
        return []

    def get_dependency_enrichments(self):
        return []


@pytest.mark.asyncio
async def test_cyclonedx_sbom_with_crypto_persists_crypto_assets(db):
    """_process_sbom on a CycloneDX 1.6 SBOM containing a cryptographic-asset component stores a CryptoAsset."""
    sbom = _load("cyclonedx_1_6_with_crypto_assets.json")
    project_id = "test-project-id"
    scan_id = "scan-embedded-cbom-001"
    aggregator = _MinimalAggregator()

    await _process_sbom(
        index=0,
        current_sbom=sbom,
        scan_id=scan_id,
        db=db,
        aggregator=aggregator,
        active_analyzers=[],
        system_settings=None,
        project_id=project_id,
    )

    count = await CryptoAssetRepository(db).count_by_scan(project_id, scan_id)
    assert count == 1, f"Expected 1 CryptoAsset (SHA-1) from embedded CBOM, got {count}"


@pytest.mark.asyncio
async def test_sbom_without_crypto_components_persists_no_crypto_assets(db):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg-requests",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
            }
        ],
    }
    project_id = "test-project-id"
    scan_id = "scan-no-crypto-001"

    await _process_sbom(
        index=0,
        current_sbom=sbom,
        scan_id=scan_id,
        db=db,
        aggregator=_MinimalAggregator(),
        active_analyzers=[],
        system_settings=None,
        project_id=project_id,
    )

    count = await CryptoAssetRepository(db).count_by_scan(project_id, scan_id)
    assert count == 0, f"Expected 0 CryptoAssets for a plain SBOM, got {count}"
