import copy
import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.services.cbom_parser import parse_cbom, parse_crypto_components

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "cbom"

OLD_ASSET_CAP = 50_000


def load_cbom(name: str) -> dict[str, Any]:
    return json.loads((_FIXTURES / name).read_text())


def fixture_component(fixture: str, bom_ref: str) -> dict[str, Any]:
    return copy.deepcopy(next(c for c in load_cbom(fixture)["components"] if c["bom-ref"] == bom_ref))


def filler_components(indices: Iterable[int]) -> list[dict[str, Any]]:
    """Hash components no crypto rule flags, named and referenced to sort before every fixture asset."""
    template = fixture_component("legacy_crypto_mixed.json", "algo-md5")
    del template["cryptoProperties"]["oid"]
    template["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] = "512"
    return [{**template, "bom-ref": f"hash-{i:06d}", "name": f"BLAKE2b-{i:06d}"} for i in indices]


def content_ref(component: dict[str, Any]) -> str:
    [asset] = parse_crypto_components([component])
    return asset.bom_ref


def cbom_of(components: list[dict[str, Any]]) -> dict[str, Any]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}


async def store_cbom(db: Any, project_id: str, scan_id: str, cbom: dict[str, Any]) -> None:
    await CryptoAssetRepository(db).store_parsed(
        project_id, scan_id, parse_cbom(cbom), cbom_upload=False, created_at=datetime.now(timezone.utc)
    )


async def store_assets(db: Any, project_id: str, scan_id: str, assets: Iterable[CryptoAsset]) -> None:
    await CryptoAssetRepository(db).bulk_upsert(project_id, scan_id, [a.model_dump(by_alias=True) for a in assets])
