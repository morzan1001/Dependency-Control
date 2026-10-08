"""Embedded CBOM in a CycloneDX SBOM: _process_sbom persists the CryptoAsset records and the scan evaluates them once."""

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.core.init_db import create_indexes
from app.models.crypto_policy import CryptoPolicy
from app.models.project import Scan
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.services.analysis import engine
from app.services.analysis.registry import CRYPTO_ANALYZERS
from app.services.crypto_policy.seeder import load_seed_rules
from tests.helpers.analyzers import bundled_iana_catalog, process_sbom_document
from tests.helpers.cbom import content_ref, fixture_component
from tests.helpers.sboms import store_sbom

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

    await process_sbom_document(0, sbom, scan_id, db, aggregator, [], None, project_id=project_id)

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

    await process_sbom_document(0, sbom, scan_id, db, _MinimalAggregator(), [], None, project_id=project_id)

    count = await CryptoAssetRepository(db).count_by_scan(project_id, scan_id)
    assert count == 0, f"Expected 0 CryptoAssets for a plain SBOM, got {count}"


@pytest.mark.asyncio
async def test_a_json_number_in_a_crypto_text_field_keeps_every_asset_of_the_sbom(db):
    rsa = {"assetType": "algorithm", "algorithmProperties": {"primitive": "pke", "parameterSetIdentifier": 2048}}
    tls = {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": 1.2}}
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"type": "cryptographic-asset", "bom-ref": "algo-rsa", "name": "RSA", "cryptoProperties": rsa},
            {"type": "cryptographic-asset", "bom-ref": "proto-tls", "name": "TLS", "cryptoProperties": tls},
        ],
    }
    scan_id = "scan-numeric-crypto-fields"

    await process_sbom_document(0, sbom, scan_id, db, _MinimalAggregator(), [], None, project_id="test-project-id")

    stored = await db.crypto_assets.find({"scan_id": scan_id}).to_list(None)
    assert sorted((a["name"], a["parameter_set_identifier"], a["version"]) for a in stored) == [
        ("RSA", "2048", None),
        ("TLS", None, "1.2"),
    ]


_PROJECT_ID = "embedded-cbom-project"
_WORKER = "pod-a/worker-0"


def _sbom_embedding(fixture: str, app_name: str) -> dict:
    cbom = _load(fixture)
    return {**cbom, "metadata": {"component": {"type": "application", "name": app_name}}}


@pytest.fixture
def catalog_loader(monkeypatch) -> AsyncMock:
    loader = AsyncMock(return_value=bundled_iana_catalog())
    monkeypatch.setattr(engine, "load_iana_catalog", loader)
    return loader


async def _analyze(db, sboms: list[dict]) -> tuple[str, str | None]:
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", rules=list(load_seed_rules()), version=1)
    )
    refs = [await store_sbom(db, sbom) for sbom in sboms]
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=refs, status="processing", worker_id=_WORKER)
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    return scan.id, await engine.run_analysis(scan.id, refs, [], db, worker_id=_WORKER)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_scan_of_several_sboms_evaluates_its_crypto_assets_once(db, catalog_loader):
    await create_indexes(db)
    sboms = [_sbom_embedding("legacy_crypto_mixed.json", f"app-{n}") for n in (1, 2, 3)]

    scan_id, status = await _analyze(db, sboms)

    assert status == SCAN_STATUS_COMPLETED
    rows = await db.analysis_results.find({"scan_id": scan_id}).to_list(None)
    assert sorted(row["analyzer_name"] for row in rows) == sorted(CRYPTO_ANALYZERS)
    findings = await db.findings.find({"scan_id": scan_id}).to_list(None)
    rsa, md5, tls = (
        content_ref(fixture_component("legacy_crypto_mixed.json", ref))
        for ref in ("algo-rsa1024", "algo-md5", "proto-tls10")
    )
    assert sorted((f["type"], f["component"]) for f in findings) == [
        ("crypto_quantum_vulnerable", f"RSA [bom-ref:{rsa}]"),
        ("crypto_weak_algorithm", f"MD5 [bom-ref:{md5}]"),
        ("crypto_weak_algorithm", f"TLS [bom-ref:{tls}]"),
        ("crypto_weak_key", f"RSA [bom-ref:{rsa}]"),
        ("crypto_weak_protocol", f"tls 1.0 [bom-ref:{tls}]"),
    ]
    assert all(f["found_in"] == ["CBOM"] for f in findings)
    catalog_loader.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_scan_without_protocol_assets_never_loads_the_cipher_catalog(db, catalog_loader):
    await create_indexes(db)
    scan_id, status = await _analyze(db, [_sbom_embedding("cyclonedx_1_6_with_crypto_assets.json", "app")])

    assert status == SCAN_STATUS_COMPLETED
    assert [f["type"] for f in await db.findings.find({"scan_id": scan_id}).to_list(None)] == ["crypto_weak_algorithm"]
    catalog_loader.assert_not_awaited()
