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


def _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=2048, bom_ref="r", variant=None):
    return CryptoAsset(
        project_id="p1",
        scan_id="s1",
        bom_ref=bom_ref,
        name=name,
        variant=variant,
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


async def _plan_for(assets):
    """The plan for one project whose head scan holds these assets, through the vulnerability filter."""
    db = FakeDatabase()
    _scanned_project(db, "p1", [("scan-head", _DEFAULT_BRANCH, SCAN_STATUS_COMPLETED, 1)])
    repo = MagicMock()
    repo.list_by_scan = AsyncMock(return_value=assets)
    with patch("app.services.pqc_migration.generator.CryptoAssetRepository", return_value=repo):
        resp = await PQCMigrationPlanGenerator(db).generate(
            resolved=ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"]),
        )
    return {item.asset_bom_ref: item for item in resp.items}


@pytest.mark.asyncio
async def test_an_eddsa_signature_enters_the_plan_under_the_eddsa_family():
    items = await _plan_for(
        [
            _asset(name="Ed25519", primitive=CryptoPrimitive.SIGNATURE, key_size_bits=256, bom_ref="ed25519"),
            _asset(name="Ed448", primitive=CryptoPrimitive.SIGNATURE, key_size_bits=456, bom_ref="ed448"),
        ]
    )

    assert set(items) == {"ed25519", "ed448"}
    for item in items.values():
        assert item.source_family == "EdDSA"
        assert item.recommended_pqc == "ML-DSA-65"
        assert item.recommended_deadline == "2030-01-01T00:00:00+00:00"


@pytest.mark.asyncio
async def test_dhe_and_ffdh_key_agreement_enter_the_plan_as_dh():
    items = await _plan_for(
        [
            _asset(name="DHE", primitive=CryptoPrimitive.KEY_AGREE, bom_ref="dhe"),
            _asset(name="FFDH", primitive=CryptoPrimitive.KEY_AGREE, bom_ref="ffdh"),
        ]
    )

    assert {ref: item.source_family for ref, item in items.items()} == {"dhe": "DH", "ffdh": "DH"}
    assert {item.recommended_pqc for item in items.values()} == {"ML-KEM-768"}


@pytest.mark.asyncio
async def test_an_asset_whose_name_is_no_family_resolves_it_from_the_variant():
    """The policy matcher flags this asset through its variant, so the plan must list it too."""
    items = await _plan_for(
        [_asset(name="sha256WithRSAEncryption", variant="RSA", primitive=CryptoPrimitive.SIGNATURE, bom_ref="sig")]
    )

    item = items["sig"]
    assert item.source_family == "RSA"
    assert item.asset_name == "sha256WithRSAEncryption"
    assert item.use_case == "digital-signature"
