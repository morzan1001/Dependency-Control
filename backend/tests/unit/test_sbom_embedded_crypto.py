import json
from pathlib import Path

from app.services.sbom_parser import parse_sbom

FIXTURES = Path(__file__).parent.parent / "fixtures" / "cbom"


def test_cyclonedx_with_crypto_assets_extracted():
    with open(FIXTURES / "cyclonedx_1_6_with_crypto_assets.json") as f:
        raw = json.load(f)
    parsed = parse_sbom(raw)
    names = {d.name for d in parsed.dependencies}
    assert "openssl" in names
    assert len(parsed.crypto_assets) == 1
    assert parsed.crypto_assets[0].name == "SHA-1"


def test_cyclonedx_without_crypto_assets_has_empty_list():
    raw = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [{"type": "library", "name": "a", "version": "1.0"}],
    }
    parsed = parse_sbom(raw)
    assert parsed.crypto_assets == []
