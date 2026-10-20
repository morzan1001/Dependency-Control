from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.cbom import CBOMIngest, CryptoAssetType, CryptoPrimitive, ParsedCryptoAsset
from app.schemas.opengrep import OpenGrepIngest


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


def test_a_cbom_upload_needs_no_pipeline_data_while_a_scanner_upload_does():
    manual = CBOMIngest.model_validate({"cbom": {}})
    assert (manual.pipeline_id, manual.commit_hash, manual.branch) == (None, None, None)
    with pytest.raises(ValidationError) as exc:
        OpenGrepIngest.model_validate({"findings": []})
    assert {error["loc"][0] for error in exc.value.errors()} == {"pipeline_id", "commit_hash", "branch"}
