"""A rescan must keep the crypto assets its lineage already established.

Assets posted to /ingest/cbom are stored under the ingested scan id with no SBOM in GridFS, so a
rescan cannot re-derive them; without the carry-over the rescan reports zero crypto assets and the
crypto delta reads that as risk having disappeared.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.v1.helpers.ingest import process_findings_ingest
from app.core.constants import SCAN_STATUS_COMPLETED
from app.core.init_db import create_indexes
from app.models.crypto_asset import CryptoAsset
from app.models.project import Project, Scan
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.trufflehog import TruffleHogIngest
from app.services.analysis import engine
from app.services.analysis.engine import run_analysis
from app.services.analysis.registry import CRYPTO_ANALYZERS
from app.services.crypto_policy.seeder import seed_crypto_policies
from app.services.rescan import RESCAN_SOURCE_PROJECTION, build_rescan
from app.services.scan_manager import ScanManager
from tests.helpers.cbom import OLD_ASSET_CAP, cbom_of, filler_components, store_cbom

_PROJECT_ID = "cbom-rescan-project"
_WORKER = "pod-a/worker-0"
_FILE_ID = "69d5332257c8763c8d8c82d7"
_ASSET_LIMIT = 100
_NO_ANALYZERS: list[str] = []

_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/requests@2.31.0",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        }
    ],
}

_INGESTED_ASSETS = [
    ("crypto/algo/md5", "MD5", CryptoPrimitive.HASH),
    ("crypto/algo/rsa-1024", "RSA-1024", CryptoPrimitive.PKE),
]


def _gridfs_ref() -> dict:
    return {"storage": "gridfs", "file_id": _FILE_ID, "type": "gridfs_reference", "gridfs_id": _FILE_ID}


@pytest.fixture
def _gridfs_patched(monkeypatch):
    fs = MagicMock()

    async def _open(_object_id):
        stream = MagicMock()
        stream.read = AsyncMock(return_value=json.dumps(_SBOM).encode())
        return stream

    fs.open_download_stream = AsyncMock(side_effect=_open)
    monkeypatch.setattr("app.services.analysis.engine.AsyncIOMotorGridFSBucket", lambda _db: fs)
    return fs


async def _ingest_assets(db, scan_id: str) -> None:
    await CryptoAssetRepository(db).bulk_upsert(
        _PROJECT_ID,
        scan_id,
        [
            CryptoAsset(
                project_id=_PROJECT_ID,
                scan_id=scan_id,
                bom_ref=bom_ref,
                name=name,
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=primitive,
            )
            for bom_ref, name, primitive in _INGESTED_ASSETS
        ],
    )


async def _seed_lineage(db) -> tuple[str, str]:
    """An ingested-CBOM scan and a pending rescan of it, both carrying the same SBOM ref."""
    await db.projects.insert_one(Project(id=_PROJECT_ID, name="cbom-rescan").model_dump(by_alias=True))
    original = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=[_gridfs_ref()], status="completed")
    await db.scans.insert_one(original.model_dump(by_alias=True))
    rescan = Scan(
        project_id=_PROJECT_ID,
        branch="main",
        sbom_refs=[_gridfs_ref()],
        status="processing",
        worker_id=_WORKER,
        is_rescan=True,
        original_scan_id=original.id,
    )
    await db.scans.insert_one(rescan.model_dump(by_alias=True))

    await _ingest_assets(db, original.id)
    return original.id, rescan.id


async def _rescan_and_list(db) -> list[str]:
    original_id, rescan_id = await _seed_lineage(db)
    assert await run_analysis(rescan_id, [_gridfs_ref()], _NO_ANALYZERS, db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    repo = CryptoAssetRepository(db)
    assert await repo.count_by_scan(_PROJECT_ID, original_id) == len(_INGESTED_ASSETS)
    return sorted(a.name for a in await repo.list_by_scan(_PROJECT_ID, rescan_id, limit=_ASSET_LIMIT))


@pytest.mark.asyncio
async def test_rescan_keeps_the_ingested_crypto_assets(db, _gridfs_patched):
    assert await _rescan_and_list(db) == ["MD5", "RSA-1024"]


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_rescan_keeps_the_ingested_crypto_assets_on_a_real_server(db, _gridfs_patched):
    assert await _rescan_and_list(db) == ["MD5", "RSA-1024"]


async def _rescan_an_analysed_cbom_scan(db, monkeypatch) -> tuple[list[str], list[str]]:
    """The rescan's analysis_results rows and announced analyzers after the original ran its crypto analyzers."""
    announced: list[list[str]] = []

    async def _capture(project_id, scan_id, scan_doc, stats, status, error, failed, findings, analyzer_outcomes, db):
        announced.append(sorted(analyzer_outcomes))

    monkeypatch.setattr(engine, "_send_integrations_and_notifications", _capture)
    await seed_crypto_policies(db)
    project = Project(id=_PROJECT_ID, name="cbom-rescan")
    await db.projects.insert_one(project.model_dump(by_alias=True))
    manager = ScanManager(db, project)
    trufflehog = TruffleHogIngest(pipeline_id=7001, commit_hash="c" * 40, branch="main", findings=[])
    original = Scan(
        id=manager.run_scan_id(trufflehog),
        project_id=_PROJECT_ID,
        branch="main",
        scan_type="cbom",
        status="processing",
        worker_id=_WORKER,
    )
    await db.scans.insert_one(original.model_dump(by_alias=True))
    await _ingest_assets(db, original.id)
    await process_findings_ingest(manager, "trufflehog", trufflehog)
    assert await run_analysis(original.id, [], _NO_ANALYZERS, db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    source = await db.scans.find_one({"_id": original.id}, RESCAN_SOURCE_PROJECTION)
    rescan = build_rescan(source).model_copy(update={"status": "processing", "worker_id": _WORKER})
    await db.scans.insert_one(rescan.model_dump(by_alias=True))
    assert await run_analysis(rescan.id, [], _NO_ANALYZERS, db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    rows = await db.analysis_results.find({"scan_id": rescan.id}).to_list(None)
    return sorted(row["analyzer_name"] for row in rows), announced[-1]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_rescan_reruns_the_crypto_analyzers_instead_of_carrying_their_rows_over(
    db, monkeypatch, _gridfs_patched
):
    await create_indexes(db)
    expected = sorted([*CRYPTO_ANALYZERS, "trufflehog"])

    assert await _rescan_an_analysed_cbom_scan(db, monkeypatch) == (expected, expected)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_carry_over_past_the_old_asset_cap_copies_every_asset_once(db):
    await create_indexes(db)
    await store_cbom(db, _PROJECT_ID, "scan-original", cbom_of(filler_components(range(OLD_ASSET_CAP + 1))))
    source_ids = await db.crypto_assets.distinct("_id", {"scan_id": "scan-original"})
    repo = CryptoAssetRepository(db)

    await repo.carry_over_to_scan(_PROJECT_ID, "scan-original", "scan-rescan")
    carried = await db.crypto_assets.find({"scan_id": "scan-rescan"}).sort("_id").to_list(None)
    await repo.carry_over_to_scan(_PROJECT_ID, "scan-original", "scan-rescan")

    assert [a["_id"] for a in carried] == sorted(f"scan-rescan:{i}" for i in source_ids)
    assert await db.crypto_assets.find({"scan_id": "scan-rescan"}).sort("_id").to_list(None) == carried
    first = carried[0]
    embedded = CryptoAsset.model_validate({**first, "_id": "embedded", "name": "SHA-512"})
    await repo.bulk_upsert(_PROJECT_ID, "scan-rescan", [embedded])
    assert await db.crypto_assets.count_documents({"scan_id": "scan-rescan"}) == OLD_ASSET_CAP + 1
    assert (await db.crypto_assets.find_one({"_id": first["_id"]}))["name"] == "SHA-512"
