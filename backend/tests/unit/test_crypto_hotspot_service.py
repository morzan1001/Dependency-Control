from datetime import datetime, timezone

import pytest

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.analytics.crypto_hotspots import CryptoHotspotService
from app.services.analytics.scopes import ResolvedScope


def _asset(bom_ref, name, primitive=None, asset_type=CryptoAssetType.ALGORITHM, project_id="p1", scan_id="s1"):
    return CryptoAsset(
        project_id=project_id,
        scan_id=scan_id,
        bom_ref=bom_ref,
        name=name,
        asset_type=asset_type,
        primitive=primitive,
    )


@pytest.mark.asyncio
async def test_hotspots_group_by_name(db):
    await CryptoAssetRepository(db).bulk_upsert(
        "p1",
        "s1",
        [
            _asset("a1", "MD5", CryptoPrimitive.HASH),
            _asset("a2", "MD5", CryptoPrimitive.HASH),
            _asset("a3", "SHA-256", CryptoPrimitive.HASH),
        ],
    )
    await db.scans.insert_one(
        {
            "_id": "s1",
            "project_id": "p1",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )

    resolved = ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"])
    service = CryptoHotspotService(db)
    result = await service.hotspots(resolved=resolved, group_by="name", limit=10)

    keys = {e.key for e in result.items}
    assert "MD5" in " ".join(keys)
    assert result.scope == "project"
    assert result.grouping_dimension == "name"


@pytest.mark.asyncio
async def test_hotspots_respects_limit(db):
    assets = [_asset(f"a{i}", f"algo-{i}", project_id="p2", scan_id="s2") for i in range(20)]
    await CryptoAssetRepository(db).bulk_upsert("p2", "s2", assets)
    await db.scans.insert_one(
        {
            "_id": "s2",
            "project_id": "p2",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )

    resolved = ResolvedScope(scope="project", scope_id="p2", project_ids=["p2"])
    result = await CryptoHotspotService(db).hotspots(
        resolved=resolved,
        group_by="name",
        limit=5,
    )
    assert len(result.items) <= 5


@pytest.mark.asyncio
async def test_hotspots_group_by_primitive(db):
    await CryptoAssetRepository(db).bulk_upsert(
        "p3",
        "s3",
        [
            _asset("a1", "MD5", CryptoPrimitive.HASH, project_id="p3", scan_id="s3"),
            _asset("a2", "SHA-1", CryptoPrimitive.HASH, project_id="p3", scan_id="s3"),
            _asset("a3", "AES", CryptoPrimitive.BLOCK_CIPHER, project_id="p3", scan_id="s3"),
        ],
    )
    await db.scans.insert_one(
        {
            "_id": "s3",
            "project_id": "p3",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )

    resolved = ResolvedScope(scope="project", scope_id="p3", project_ids=["p3"])
    result = await CryptoHotspotService(db).hotspots(
        resolved=resolved,
        group_by="primitive",
        limit=10,
    )
    keys = {e.key for e in result.items}
    assert "hash" in keys


def _variant_asset(bom_ref, name, variant, *, project_id, scan_id, locations=None):
    return CryptoAsset(
        project_id=project_id,
        scan_id=scan_id,
        bom_ref=bom_ref,
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.PKE,
        variant=variant,
        occurrence_locations=locations or [],
    )


def _crypto_finding(_id, *, asset_name, project_id, scan_id, severity="HIGH", waived=False):
    return {
        "_id": _id,
        "finding_id": _id,
        "type": "crypto_weak_key",
        "project_id": project_id,
        "scan_id": scan_id,
        "severity": severity,
        "waived": waived,
        "details": {"asset_name": asset_name},
    }


@pytest.mark.asyncio
async def test_group_by_name_enrichment_joins_on_bare_name_despite_variants(db):
    """Hotspot rows must key on the bare asset name so findings enrichment joins on details.asset_name."""
    await CryptoAssetRepository(db).bulk_upsert(
        "pv",
        "sv",
        [
            _variant_asset("a1", "RSA", "RSA-OAEP", project_id="pv", scan_id="sv"),
            _variant_asset("a2", "RSA", "RSA-PSS", project_id="pv", scan_id="sv"),
        ],
    )
    await db.scans.insert_one(
        {"_id": "sv", "project_id": "pv", "status": "completed", "created_at": datetime.now(timezone.utc)}
    )
    for f in [
        _crypto_finding("f1", asset_name="RSA", project_id="pv", scan_id="sv"),
        _crypto_finding("f2", asset_name="RSA", project_id="pv", scan_id="sv", severity="MEDIUM"),
    ]:
        await db.findings.insert_one(f)

    resolved = ResolvedScope(scope="project", scope_id="pv", project_ids=["pv"])
    result = await CryptoHotspotService(db).hotspots(resolved=resolved, group_by="name", limit=10)

    entries = [e for e in result.items if e.key == "RSA"]
    assert len(entries) == 1, f"expected a single bare-name 'RSA' row, got keys {[e.key for e in result.items]}"
    entry = entries[0]
    assert entry.asset_count == 2
    assert entry.finding_count == 2
    assert entry.severity_mix == {"HIGH": 1, "MEDIUM": 1}


@pytest.mark.asyncio
async def test_group_by_name_enrichment_excludes_waived_findings(db):
    """Waived crypto findings must not inflate finding_count or severity_mix."""
    await CryptoAssetRepository(db).bulk_upsert(
        "pw",
        "sw",
        [_variant_asset("a1", "MD5", None, project_id="pw", scan_id="sw")],
    )
    await db.scans.insert_one(
        {"_id": "sw", "project_id": "pw", "status": "completed", "created_at": datetime.now(timezone.utc)}
    )
    for f in [
        _crypto_finding("f1", asset_name="MD5", project_id="pw", scan_id="sw"),
        _crypto_finding("f2", asset_name="MD5", project_id="pw", scan_id="sw", waived=True),
        _crypto_finding("f3", asset_name="MD5", project_id="pw", scan_id="sw", waived=True),
    ]:
        await db.findings.insert_one(f)

    resolved = ResolvedScope(scope="project", scope_id="pw", project_ids=["pw"])
    result = await CryptoHotspotService(db).hotspots(resolved=resolved, group_by="name", limit=10)

    entry = next(e for e in result.items if e.key == "MD5")
    assert entry.finding_count == 1
    assert entry.severity_mix == {"HIGH": 1}


@pytest.mark.asyncio
async def test_group_by_severity_excludes_waived_findings(db):
    for f in [
        _crypto_finding("f1", asset_name="MD5", project_id="ps", scan_id="ss", severity="HIGH"),
        _crypto_finding("f2", asset_name="MD5", project_id="ps", scan_id="ss", severity="HIGH", waived=True),
        _crypto_finding("f3", asset_name="MD5", project_id="ps", scan_id="ss", severity="LOW"),
    ]:
        await db.findings.insert_one(f)
    await db.scans.insert_one(
        {"_id": "ss", "project_id": "ps", "status": "completed", "created_at": datetime.now(timezone.utc)}
    )
    # Seed a completed scan so _pick_scan_ids selects "ss".
    resolved = ResolvedScope(scope="project", scope_id="ps", project_ids=["ps"])
    result = await CryptoHotspotService(db).hotspots(resolved=resolved, group_by="severity", limit=10)

    by_key = {e.key: e for e in result.items}
    assert by_key["HIGH"].finding_count == 1
    assert by_key["LOW"].finding_count == 1


@pytest.mark.asyncio
async def test_no_completed_scans_returns_empty_not_all_history(db):
    """With no completed/partial scan the aggregation must match nothing, not fall back to every scan."""
    await CryptoAssetRepository(db).bulk_upsert(
        "pn",
        "srun",
        [_variant_asset("a1", "AES", "AES-256", project_id="pn", scan_id="srun")],
    )
    # Only scan is still running → not eligible for _pick_scan_ids.
    await db.scans.insert_one(
        {"_id": "srun", "project_id": "pn", "status": "running", "created_at": datetime.now(timezone.utc)}
    )

    resolved = ResolvedScope(scope="project", scope_id="pn", project_ids=["pn"])
    result = await CryptoHotspotService(db).hotspots(resolved=resolved, group_by="name", limit=10)

    assert result.items == []
    assert result.total == 0
