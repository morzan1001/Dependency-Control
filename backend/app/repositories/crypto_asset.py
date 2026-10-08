"""MongoDB access for the crypto_assets collection."""

import itertools
import re
from collections.abc import Iterable
from typing import Any

from pymongo import UpdateOne

from app.core.constants import CRYPTO_ASSET_BULK_CHUNK_SIZE
from app.models.crypto_asset import CryptoAsset
from app.repositories.base import BaseRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive


def scan_query(
    project_id: str,
    scan_id: str,
    asset_type: CryptoAssetType | None = None,
    primitive: CryptoPrimitive | None = None,
    name_search: str | None = None,
) -> dict[str, Any]:
    query: dict[str, Any] = {"project_id": project_id, "scan_id": scan_id}
    if asset_type is not None:
        query["asset_type"] = asset_type
    if primitive is not None:
        query["primitive"] = primitive
    if name_search:
        query["name"] = {"$regex": re.escape(name_search), "$options": "i"}
    return query


class CryptoAssetRepository(BaseRepository[CryptoAsset]):
    collection_name = "crypto_assets"
    model_class = CryptoAsset

    async def bulk_upsert(
        self,
        project_id: str,
        scan_id: str,
        assets: Iterable[CryptoAsset],
        chunk_size: int = CRYPTO_ASSET_BULK_CHUNK_SIZE,
    ) -> int:
        total = 0
        for chunk in itertools.batched(assets, chunk_size, strict=False):
            ops = [
                UpdateOne(
                    {
                        "project_id": project_id,
                        "scan_id": scan_id,
                        "bom_ref": a.bom_ref,
                    },
                    # $max: an overlapping earlier upload must not age the rows a later one's cleanup keeps.
                    {
                        "$set": a.model_dump(by_alias=True, exclude={"id", "created_at"}),
                        "$max": {"created_at": a.created_at},
                        "$setOnInsert": {"_id": a.id},
                    },
                    upsert=True,
                )
                for a in chunk
            ]
            await self.collection.bulk_write(ops, ordered=False)
            total += len(ops)
        return total

    async def carry_over_to_scan(self, project_id: str, from_scan_id: str, to_scan_id: str) -> None:
        """Copy a scan's assets onto a rescan server-side, since /ingest/cbom assets have no SBOM to
        re-derive them from; joining on the unique bom_ref key keeps any row the rescan already holds."""
        await self.aggregate(
            [
                {"$match": {"project_id": project_id, "scan_id": from_scan_id}},
                {"$set": {"_id": {"$concat": [to_scan_id, ":", {"$toString": "$_id"}]}, "scan_id": to_scan_id}},
                {
                    "$merge": {
                        "into": self.collection_name,
                        "on": ["project_id", "scan_id", "bom_ref"],
                        "whenMatched": "keepExisting",
                    }
                },
            ]
        )

    async def list_by_scan(
        self,
        project_id: str,
        scan_id: str,
        limit: int,
        skip: int = 0,
        asset_type: CryptoAssetType | None = None,
        primitive: CryptoPrimitive | None = None,
        name_search: str | None = None,
    ) -> list[CryptoAsset]:
        """A scan's assets, name-ascending. ``limit`` is the caller's own budget and is applied
        as given, so a short list means the scan is short and a caller can say so."""
        query = scan_query(project_id, scan_id, asset_type, primitive, name_search)
        cursor = self.collection.find(query).sort([("name", 1), ("bom_ref", 1)]).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [CryptoAsset.model_validate(d) for d in docs]

    async def get(self, project_id: str, asset_id: str) -> CryptoAsset | None:
        doc = await self.collection.find_one({"project_id": project_id, "_id": asset_id})
        return CryptoAsset.model_validate(doc) if doc else None

    async def count_by_scan(
        self,
        project_id: str,
        scan_id: str,
        asset_type: CryptoAssetType | None = None,
        primitive: CryptoPrimitive | None = None,
        name_search: str | None = None,
    ) -> int:
        query = scan_query(project_id, scan_id, asset_type, primitive, name_search)
        return await self.collection.count_documents(query)

    async def summary_for_scan(self, project_id: str, scan_id: str) -> dict[str, Any]:
        pipeline: list[dict[str, Any]] = [
            {"$match": {"project_id": project_id, "scan_id": scan_id}},
            {"$group": {"_id": "$asset_type", "count": {"$sum": 1}}},
        ]
        by_type: dict[str, int] = {}
        total = 0
        async for row in self.collection.aggregate(pipeline):
            by_type[row["_id"]] = row["count"]
            total += row["count"]
        return {"total": total, "by_type": by_type}
