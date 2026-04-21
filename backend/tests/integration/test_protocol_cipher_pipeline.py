"""
Integration: registry-resolved ProtocolCipherSuiteAnalyzer produces findings.
"""
import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.crypto_policy import CryptoPolicy
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.cbom import CryptoAssetType
from app.services.analysis.registry import analyzers


@pytest.mark.asyncio
async def test_protocol_cipher_registered_and_runs(db):
    analyzer = analyzers["crypto_protocol_cipher"]
    await CryptoAssetRepository(db).bulk_upsert("p", "s", [
        CryptoAsset(
            project_id="p", scan_id="s", bom_ref="proto",
            name="TLS", asset_type=CryptoAssetType.PROTOCOL,
            protocol_type="tls", version="1.2",
            cipher_suites=[
                "TLS_RSA_WITH_RC4_128_SHA",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ],
        ),
    ])
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[])
    )
    result = await analyzer.analyze(
        sbom={}, project_id="p", scan_id="s", db=db,
    )
    findings = result["findings"]
    assert any("RC4_128_SHA" in f["details"]["cipher_suite"] for f in findings)
    assert not any("AES_256_GCM_SHA384" in f["details"]["cipher_suite"] for f in findings)
