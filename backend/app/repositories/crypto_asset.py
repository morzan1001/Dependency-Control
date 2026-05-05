"""
CryptoAssetRepository — MongoDB access for the `crypto_assets` collection.
"""

from typing import Any, Dict, List, Optional

from pymongo import UpdateOne

from app.core.constants import CRYPTO_ASSET_BULK_CHUNK_SIZE, CRYPTO_ASSET_MAX_LIST_LIMIT
from app.core.metrics import track_db_operation
from app.models.crypto_asset import CryptoAsset
from app.repositories.base import BaseRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive


class CryptoAssetRepository(BaseRepository[CryptoAsset]):
    collection_name = "crypto_assets"
    model_class = CryptoAsset

    async def bulk_upsert(
        self,
        project_id: str,
        scan_id: str,
        assets: List[CryptoAsset],
        chunk_size: int = CRYPTO_ASSET_BULK_CHUNK_SIZE,
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
            with track_db_operation(self.collection_name, "bulk_write"):
                await self.collection.bulk_write(ops, ordered=False)
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
        limit = min(limit, CRYPTO_ASSET_MAX_LIST_LIMIT)
        query: Dict[str, Any] = {"project_id": project_id, "scan_id": scan_id}
        if asset_type is not None:
            query["asset_type"] = asset_type.value if hasattr(asset_type, "value") else asset_type
        if primitive is not None:
            query["primitive"] = primitive.value if hasattr(primitive, "value") else primitive
        if name_search:
            query["name"] = {"$regex": name_search, "$options": "i"}
        with track_db_operation(self.collection_name, "find"):
            cursor = self.collection.find(query).skip(skip).limit(limit)
            docs = await cursor.to_list(length=limit)
        return [CryptoAsset.model_validate(d) for d in docs]

    async def get(self, project_id: str, asset_id: str) -> Optional[CryptoAsset]:
        with track_db_operation(self.collection_name, "find_one"):
            doc = await self.collection.find_one({"project_id": project_id, "_id": asset_id})
        return CryptoAsset.model_validate(doc) if doc else None

    async def count_by_scan(self, project_id: str, scan_id: str) -> int:
        with track_db_operation(self.collection_name, "count"):
            return await self.collection.count_documents({"project_id": project_id, "scan_id": scan_id})

    async def summary_for_scan(self, project_id: str, scan_id: str) -> Dict[str, Any]:
        pipeline: List[Dict[str, Any]] = [
            {"$match": {"project_id": project_id, "scan_id": scan_id}},
            {"$group": {"_id": "$asset_type", "count": {"$sum": 1}}},
        ]
        by_type: Dict[str, int] = {}
        total = 0
        with track_db_operation(self.collection_name, "aggregate"):
            async for row in self.collection.aggregate(pipeline):
                by_type[row["_id"]] = row["count"]
                total += row["count"]
        return {"total": total, "by_type": by_type}
