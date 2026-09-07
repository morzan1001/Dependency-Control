"""A rescan must keep the crypto assets its lineage already established.

Assets posted to /ingest/cbom are stored under the ingested scan id with no SBOM in GridFS, so a
rescan cannot re-derive them; without the carry-over the rescan reports zero crypto assets and the
crypto delta reads that as risk having disappeared.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.project import Project, Scan
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.analysis.engine import run_analysis

_PROJECT_ID = "cbom-rescan-project"
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
    monkeypatch.setattr("app.services.analysis.engine.primary_gridfs_bucket", lambda _db: fs)
    return fs


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
        is_rescan=True,
        original_scan_id=original.id,
    )
    await db.scans.insert_one(rescan.model_dump(by_alias=True))

    await CryptoAssetRepository(db).bulk_upsert(
        _PROJECT_ID,
        original.id,
        [
            CryptoAsset(
                project_id=_PROJECT_ID,
                scan_id=original.id,
                bom_ref=bom_ref,
                name=name,
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=primitive,
            )
            for bom_ref, name, primitive in _INGESTED_ASSETS
        ],
    )
    return original.id, rescan.id


async def _rescan_and_list(db) -> list[str]:
    original_id, rescan_id = await _seed_lineage(db)
    assert await run_analysis(rescan_id, [_gridfs_ref()], _NO_ANALYZERS, db) is True

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
