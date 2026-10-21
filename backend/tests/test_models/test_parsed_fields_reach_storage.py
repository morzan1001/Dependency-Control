import inspect

import pytest

from app.models.crypto_asset import CryptoAsset, CryptoAssetType
from app.models.dependency import Dependency
from app.schemas.cbom import ParsedCryptoAsset
from app.schemas.sbom import ParsedDependency


@pytest.mark.parametrize(("parsed", "stored"), [(ParsedDependency, Dependency), (ParsedCryptoAsset, CryptoAsset)])
def test_every_parsed_field_is_a_stored_field(parsed, stored):
    assert parsed.model_fields.keys() <= stored.model_fields.keys()


@pytest.mark.parametrize(("parsed", "stored"), [(ParsedDependency, Dependency), (ParsedCryptoAsset, CryptoAsset)])
def test_parsed_and_stored_declare_each_shared_field_once(parsed, stored):
    shared = parsed.model_fields.keys() & stored.model_fields.keys()
    redeclared = shared & inspect.get_annotations(parsed).keys() & inspect.get_annotations(stored).keys()
    assert redeclared == set()


def test_an_undeclared_license_parses_empty_and_loads_as_none_from_storage():
    assert ParsedDependency(name="a", version="1").license == ""
    assert Dependency(project_id="p", scan_id="s", name="a", version="1").license is None


def test_a_parsed_crypto_asset_still_coerces_numbers_and_validates_assignment():
    asset = ParsedCryptoAsset(bom_ref="c1", name="AES", asset_type=CryptoAssetType.ALGORITHM, version=3)
    assert asset.version == "3"
    with pytest.raises(ValueError):
        asset.key_size_bits = "not-a-number"
