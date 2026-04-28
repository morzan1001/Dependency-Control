from datetime import datetime, timezone

from app.schemas.cbom import (
    CryptoAssetType,
    CryptoPrimitive,
    ParsedCryptoAsset,
    ParsedCBOM,
)


def test_parsed_crypto_asset_minimal():
    asset = ParsedCryptoAsset(bom_ref="crypto-1", name="SHA-1", asset_type=CryptoAssetType.ALGORITHM)
    assert asset.bom_ref == "crypto-1"
    assert asset.primitive is None
    assert asset.key_size_bits is None
    assert asset.occurrence_locations == []


def test_parsed_crypto_asset_algorithm_full():
    asset = ParsedCryptoAsset(
        bom_ref="c1",
        name="RSA",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.PKE,
        variant="RSA-2048",
        key_size_bits=2048,
        padding="OAEP",
    )
    assert asset.primitive == CryptoPrimitive.PKE
    assert asset.key_size_bits == 2048


def test_parsed_crypto_asset_certificate():
    asset = ParsedCryptoAsset(
        bom_ref="cert1",
        name="CN=example.com",
        asset_type=CryptoAssetType.CERTIFICATE,
        subject_name="CN=example.com",
        issuer_name="CN=Example CA",
        not_valid_after=datetime(2025, 6, 1, tzinfo=timezone.utc),
    )
    assert asset.subject_name == "CN=example.com"


def test_parsed_cbom_empty_defaults():
    cbom = ParsedCBOM()
    assert cbom.assets == []
    assert cbom.parsed_components == 0
    assert cbom.skipped_components == 0


def test_parsed_cbom_with_assets():
    cbom = ParsedCBOM(
        assets=[ParsedCryptoAsset(bom_ref="a", name="MD5", asset_type=CryptoAssetType.ALGORITHM)],
        parsed_components=1,
    )
    assert len(cbom.assets) == 1
