"""Large CBOMs inflated from a fixture component, for size proofs."""

import copy
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.services.cbom_parser import parse_cbom

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


def cbom_of(components: list[dict[str, Any]]) -> dict[str, Any]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}


async def store_cbom(db: Any, project_id: str, scan_id: str, cbom: dict[str, Any]) -> None:
    """Store the parsed assets the way the engine persists an embedded CBOM."""
    assets = parse_cbom(cbom)
    await CryptoAssetRepository(db).bulk_upsert(
        project_id, scan_id, [CryptoAsset(project_id=project_id, scan_id=scan_id, **a.model_dump()) for a in assets]
    )
