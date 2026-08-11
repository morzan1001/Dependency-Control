"""Row builder for the crypto asset inventory."""

from collections.abc import AsyncIterator
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.inventory import CryptoItem

CRYPTO_COLUMNS = ["name", "asset_type", "primitive", "variant", "key_size_bits", "location_count", "locations"]

_EXPORT_PROJECTION = {
    "name": 1, "asset_type": 1, "primitive": 1, "variant": 1,
    "key_size_bits": 1, "occurrence_locations": 1,
}


def _to_item(doc: dict[str, Any]) -> CryptoItem:
    locations = doc.get("occurrence_locations") or []
    return CryptoItem(
        name=doc.get("name", ""),
        asset_type=doc.get("asset_type", ""),
        primitive=doc.get("primitive"),
        variant=doc.get("variant"),
        key_size_bits=doc.get("key_size_bits"),
        location_count=len(locations),
        locations=locations,
    )


async def get_crypto_page(
    db: AsyncIOMotorDatabase,
    project_id: str,
    scan_id: str,
    *,
    page: int,
    page_size: int,
    search: str | None,
) -> tuple[list[CryptoItem], int]:
    repo = CryptoAssetRepository(db)
    assets = await repo.list_by_scan(
        project_id, scan_id, limit=page_size, skip=(page - 1) * page_size, name_search=search
    )
    total = await repo.count_by_scan(project_id, scan_id, name_search=search)
    return [_to_item(a.model_dump()) for a in assets], total


async def iter_crypto_rows(
    db: AsyncIOMotorDatabase, project_id: str, scan_id: str
) -> AsyncIterator[dict[str, Any]]:
    # Direct cursor instead of list_by_scan: the export must not be capped by the list limit.
    cursor = CryptoAssetRepository(db).collection.find(
        {"project_id": project_id, "scan_id": scan_id}, _EXPORT_PROJECTION
    ).sort("name", 1)
    async for doc in cursor:
        yield _to_item(doc).model_dump()
