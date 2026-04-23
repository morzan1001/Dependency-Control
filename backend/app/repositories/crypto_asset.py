"""
CryptoAssetRepository — MongoDB access for the `crypto_assets` collection.
"""

from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import UpdateOne

from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive

_DEFAULT_CHUNK_SIZE = 500
_MAX_LIST_LIMIT = 10000


class CryptoAssetRepository:
    COLLECTION = "crypto_assets"

    def __init__(self, db: AsyncIOMotorDatabase):
        self._col = db[self.COLLECTION]

    async def ensure_indexes(self) -> None:
        await self._col.create_index([("project_id", 1), ("scan_id", 1)])
        await self._col.create_index([("project_id", 1), ("asset_type", 1)])
        await self._col.create_index([("project_id", 1), ("name", 1)])
        await self._col.create_index([("project_id", 1), ("primitive", 1)])
        await self._col.create_index([("project_id", 1), ("scan_id", 1), ("bom_ref", 1)], unique=True)
        await self._col.create_index([("project_id", 1), ("asset_type", 1), ("primitive", 1)])

    async def bulk_upsert(
        self,
        project_id: str,
        scan_id: str,
        assets: List[CryptoAsset],
        chunk_size: int = _DEFAULT_CHUNK_SIZE,
    ) -> int:
        if not assets:
            return 0
        total = 0
        for start in range(0, len(assets), chunk_size):
            chunk = assets[start : start + chunk_size]
            ops = [
                UpdateOne(
                    {
                        "project_id": project_id,
                        "scan_id": scan_id,
                        "bom_ref": a.bom_ref,
                    },
                    {"$set": a.model_dump(by_alias=True, exclude={"id"})},
                    upsert=True,
                )
                for a in chunk
            ]
            await self._col.bulk_write(ops, ordered=False)
            total += len(ops)
        return total

    async def list_by_scan(
        self,
        project_id: str,
        scan_id: str,
        limit: int,
        skip: int = 0,
        asset_type: Optional[CryptoAssetType] = None,
        primitive: Optional[CryptoPrimitive] = None,
        name_search: Optional[str] = None,
    ) -> List[CryptoAsset]:
        limit = min(limit, _MAX_LIST_LIMIT)
        query: Dict[str, Any] = {"project_id": project_id, "scan_id": scan_id}
        if asset_type is not None:
            query["asset_type"] = asset_type.value if hasattr(asset_type, "value") else asset_type
        if primitive is not None:
            query["primitive"] = primitive.value if hasattr(primitive, "value") else primitive
        if name_search:
            query["name"] = {"$regex": name_search, "$options": "i"}
        cursor = self._col.find(query).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [CryptoAsset.model_validate(d) for d in docs]

    async def get(self, project_id: str, asset_id: str) -> Optional[CryptoAsset]:
        doc = await self._col.find_one({"project_id": project_id, "_id": asset_id})
        return CryptoAsset.model_validate(doc) if doc else None

    async def count_by_scan(self, project_id: str, scan_id: str) -> int:
        return await self._col.count_documents({"project_id": project_id, "scan_id": scan_id})

    async def summary_for_scan(self, project_id: str, scan_id: str) -> Dict[str, Any]:
        pipeline = [
            {"$match": {"project_id": project_id, "scan_id": scan_id}},
            {"$group": {"_id": "$asset_type", "count": {"$sum": 1}}},
        ]
        by_type: Dict[str, int] = {}
        total = 0
        async for row in self._col.aggregate(pipeline):
            by_type[row["_id"]] = row["count"]
            total += row["count"]
        return {"total": total, "by_type": by_type}
