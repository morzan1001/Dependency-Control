from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.analytics.scopes import ResolvedScope
from app.services.pqc_migration.generator import PQCMigrationPlanGenerator


def _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=2048, bom_ref="r"):
    return CryptoAsset(
        project_id="p1", scan_id="s1", bom_ref=bom_ref,
        name=name, asset_type=CryptoAssetType.ALGORITHM,
        primitive=primitive, key_size_bits=key_size_bits,
    )


@pytest.mark.asyncio
async def test_generate_empty_when_no_vulnerable_assets():
    db = MagicMock()
    gen = PQCMigrationPlanGenerator(db)
    with patch.object(gen, "_list_vulnerable_assets", new=AsyncMock(return_value=[])):
        resp = await gen.generate(
            resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["p1"]),
        )
    assert resp.items == []
    assert resp.summary.total_items == 0
    assert resp.mappings_version == 1


@pytest.mark.asyncio
async def test_generate_maps_rsa_pke_to_ml_kem():
    db = MagicMock()
    gen = PQCMigrationPlanGenerator(db)
    with patch.object(
        gen, "_list_vulnerable_assets",
        new=AsyncMock(return_value=[_asset(name="RSA", primitive=CryptoPrimitive.PKE)]),
    ):
        resp = await gen.generate(
            resolved=ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"]),
        )
    assert len(resp.items) == 1
    item = resp.items[0]
    assert item.source_family == "RSA"
    assert item.recommended_pqc == "ML-KEM-768"
    assert item.recommended_standard == "FIPS 203"


@pytest.mark.asyncio
async def test_generate_sorts_items_descending_priority():
    db = MagicMock()
    gen = PQCMigrationPlanGenerator(db)
    weak = _asset(key_size_bits=1024, bom_ref="r1")
    strong = _asset(key_size_bits=4096, bom_ref="r2")
    with patch.object(
        gen, "_list_vulnerable_assets",
        new=AsyncMock(return_value=[strong, weak]),
    ):
        resp = await gen.generate(
            resolved=ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"]),
        )
    assert resp.items[0].asset_bom_ref == "r1"


@pytest.mark.asyncio
async def test_generate_alias_resolution():
    db = MagicMock()
    gen = PQCMigrationPlanGenerator(db)
    with patch.object(
        gen, "_list_vulnerable_assets",
        new=AsyncMock(return_value=[_asset(name="Diffie-Hellman", primitive=CryptoPrimitive.KEM)]),
    ):
        resp = await gen.generate(
            resolved=ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"]),
        )
    assert len(resp.items) == 1
    assert resp.items[0].source_family == "DH"
    assert resp.items[0].recommended_pqc == "ML-KEM-768"
