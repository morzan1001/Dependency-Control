from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.analytics.scopes import ResolvedScope
from app.services.pqc_migration.generator import PQCMigrationPlanGenerator
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
_DEFAULT_BRANCH = "main"
_DELETED_BRANCH = "feature/gone"


def _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=2048, bom_ref="r"):
    return CryptoAsset(
        project_id="p1",
        scan_id="s1",
        bom_ref=bom_ref,
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=primitive,
        key_size_bits=key_size_bits,
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
        gen,
        "_list_vulnerable_assets",
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
        gen,
        "_list_vulnerable_assets",
        new=AsyncMock(return_value=[strong, weak]),
    ):
        resp = await gen.generate(
            resolved=ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"]),
        )
    assert resp.items[0].asset_bom_ref == "r1"


def _vulnerable_asset_repo():
    repo = MagicMock()
    repo.list_by_scan = AsyncMock(return_value=[_asset(name="RSA", primitive=CryptoPrimitive.PKE)])
    return repo


def _scanned_project(db, project_id, scans):
    """A project plus the scans it holds; each scan is (id, branch, status, age_days)."""
    db.projects._docs[project_id] = {
        "_id": project_id,
        "name": project_id,
        "default_branch": _DEFAULT_BRANCH,
        "deleted_branches": [_DELETED_BRANCH],
        "latest_scan_id": None,
    }
    for scan_id, branch, status, age_days in scans:
        db.scans._docs[scan_id] = {
            "_id": scan_id,
            "project_id": project_id,
            "branch": branch,
            "status": status,
            "created_at": _NOW - timedelta(days=age_days),
        }


@pytest.mark.asyncio
async def test_list_vulnerable_assets_global_scope_enumerates_all_projects():
    # global scope has project_ids=None ("all projects"); it must not be coerced to [] (empty plan) — enumerate every project with a usable scan.
    db = FakeDatabase()
    for pid in ("p1", "p2"):
        _scanned_project(db, pid, [(f"scan-{pid}", _DEFAULT_BRANCH, SCAN_STATUS_COMPLETED, 1)])
    gen = PQCMigrationPlanGenerator(db)
    repo = _vulnerable_asset_repo()

    with patch("app.services.pqc_migration.generator.CryptoAssetRepository", return_value=repo):
        assets = await gen._list_vulnerable_assets(ResolvedScope(scope="global", scope_id=None, project_ids=None))

    assert {call.args[1] for call in repo.list_by_scan.await_args_list} == {"scan-p1", "scan-p2"}
    assert len(assets) == 2  # one vulnerable RSA asset per enumerated project


@pytest.mark.asyncio
async def test_list_vulnerable_assets_empty_project_ids_stays_empty():
    # an explicit empty list means "no projects" and must not fall through to enumerating everything.
    db = FakeDatabase()
    _scanned_project(db, "p1", [("scan-p1", _DEFAULT_BRANCH, SCAN_STATUS_COMPLETED, 1)])
    gen = PQCMigrationPlanGenerator(db)
    repo = _vulnerable_asset_repo()

    with patch("app.services.pqc_migration.generator.CryptoAssetRepository", return_value=repo):
        assets = await gen._list_vulnerable_assets(ResolvedScope(scope="team", scope_id="t1", project_ids=[]))

    repo.list_by_scan.assert_not_awaited()
    assert assets == []


@pytest.mark.asyncio
async def test_list_vulnerable_assets_reads_the_head_build_not_a_deleted_branch():
    """The newest scan sits on a branch the VCS no longer has, so a plan built from it would name
    crypto that shipped nowhere."""
    db = FakeDatabase()
    _scanned_project(
        db,
        "p1",
        [
            ("scan-head", _DEFAULT_BRANCH, SCAN_STATUS_COMPLETED, 5),
            ("scan-gone", _DELETED_BRANCH, SCAN_STATUS_COMPLETED, 1),
        ],
    )
    gen = PQCMigrationPlanGenerator(db)
    repo = _vulnerable_asset_repo()

    with patch("app.services.pqc_migration.generator.CryptoAssetRepository", return_value=repo):
        await gen._list_vulnerable_assets(ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"]))

    assert [call.args[1] for call in repo.list_by_scan.await_args_list] == ["scan-head"]


@pytest.mark.asyncio
async def test_generate_alias_resolution():
    db = MagicMock()
    gen = PQCMigrationPlanGenerator(db)
    with patch.object(
        gen,
        "_list_vulnerable_assets",
        new=AsyncMock(return_value=[_asset(name="Diffie-Hellman", primitive=CryptoPrimitive.KEM)]),
    ):
        resp = await gen.generate(
            resolved=ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"]),
        )
    assert len(resp.items) == 1
    assert resp.items[0].source_family == "DH"
    assert resp.items[0].recommended_pqc == "ML-KEM-768"


_GROUPS_BEYOND_LIMIT = 12
_PLAN_LIMIT = 5


@pytest.mark.asyncio
async def test_the_summary_counts_every_migratable_group_not_the_page_it_returns():
    """A migration plan that under-counts the work is a planning document wrong in the direction
    that matters."""
    db = MagicMock()
    gen = PQCMigrationPlanGenerator(db)
    assets = [_asset(bom_ref=f"r{index}") for index in range(_GROUPS_BEYOND_LIMIT)]
    with patch.object(gen, "_list_vulnerable_assets", new=AsyncMock(return_value=assets)):
        resp = await gen.generate(
            resolved=ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"]),
            limit=_PLAN_LIMIT,
        )

    assert len(resp.items) == _PLAN_LIMIT
    assert resp.summary.items_returned == _PLAN_LIMIT
    assert resp.summary.total_items == _GROUPS_BEYOND_LIMIT
    assert sum(resp.summary.status_counts.values()) == _GROUPS_BEYOND_LIMIT
