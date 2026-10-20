import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.crypto_policy import CryptoPolicy
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.cbom import CryptoAssetType
from tests.helpers.analyzers import evaluate_crypto
from tests.helpers.cbom import store_assets


@pytest.mark.asyncio
async def test_protocol_cipher_registered_and_runs(db):
    await store_assets(
        db,
        "p",
        "s",
        [
            CryptoAsset(
                project_id="p",
                scan_id="s",
                bom_ref="proto",
                name="TLS",
                asset_type=CryptoAssetType.PROTOCOL,
                protocol_type="tls",
                version="1.2",
                cipher_suites=[
                    "TLS_RSA_WITH_RC4_128_SHA",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                ],
            ),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=1, rules=[]))
    result = await evaluate_crypto("crypto_protocol_cipher", db)
    findings = result["findings"]
    assert any("RC4_128_SHA" in f["details"]["cipher_suite"] for f in findings)
    assert not any("AES_256_GCM_SHA384" in f["details"]["cipher_suite"] for f in findings)
