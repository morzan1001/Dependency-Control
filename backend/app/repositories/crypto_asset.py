import asyncio
import itertools
import re
import uuid
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from pymongo import UpdateOne

from app.api.v1.helpers.sorting import case_insensitive_sort
from app.core.constants import CRYPTO_ASSET_BULK_CHUNK_SIZE
from app.models.crypto_asset import CryptoAsset
from app.repositories.base import BaseRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive, ParsedCryptoAsset


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


SCAN_ORDER = case_insensitive_sort([("name", 1), ("bom_ref", 1)], {"name"})


def _documents(
    project_id: str, scan_id: str, assets: Sequence[ParsedCryptoAsset], fields: dict[str, Any]
) -> list[dict[str, Any]]:
    return [
        {**a.model_dump(), "_id": str(uuid.uuid4()), "project_id": project_id, "scan_id": scan_id, **fields}
        for a in assets
    ]


class CryptoAssetRepository(BaseRepository[CryptoAsset]):
    collection_name = "crypto_assets"
    model_class = CryptoAsset

    async def store_parsed(
        self,
        project_id: str,
        scan_id: str,
        assets: Iterable[ParsedCryptoAsset],
        *,
        cbom_upload: bool,
        created_at: datetime,
        cbom_source: str | None = None,
    ) -> dict[str, Any]:
        """Stores one asset per bom_ref, the last given; returns how many, in total and per asset type."""
        unique = list({a.bom_ref: a for a in assets}.values())
        fields = {"cbom_upload": cbom_upload, "cbom_source": cbom_source, "created_at": created_at}
        # Built off the event loop, as a CBOM may carry any number of assets.
        documents = await asyncio.to_thread(_documents, project_id, scan_id, unique, fields)
        await self.bulk_upsert(project_id, scan_id, documents)
        return {"total": len(unique), "by_type": dict(Counter(a.asset_type.value for a in unique))}

    async def bulk_upsert(
        self,
        project_id: str,
        scan_id: str,
        documents: Iterable[dict[str, Any]],
        chunk_size: int = CRYPTO_ASSET_BULK_CHUNK_SIZE,
    ) -> None:
        for chunk in itertools.batched(documents, chunk_size, strict=False):
            ops = [
                UpdateOne(
                    {"project_id": project_id, "scan_id": scan_id, "bom_ref": doc["bom_ref"]},
                    # $max: an overlapping earlier upload must not age the rows a later one's cleanup keeps.
                    {
                        "$set": {k: v for k, v in doc.items() if k not in ("_id", "created_at")},
                        "$max": {"created_at": doc["created_at"]},
                        "$setOnInsert": {"_id": doc["_id"]},
                    },
                    upsert=True,
                )
                for doc in chunk
            ]
            await self.collection.bulk_write(ops, ordered=False)

    async def carry_over_to_scan(
        self, project_id: str, from_scan_id: str, to_scan_id: str, created_at: datetime
    ) -> None:
        """Copied, as /ingest/cbom assets have no SBOM to re-derive them from; rows the rescan already holds stay."""
        await self.aggregate(
            [
                {"$match": {"project_id": project_id, "scan_id": from_scan_id}},
                {
                    "$set": {
                        "_id": {"$concat": [to_scan_id, ":", {"$toString": "$_id"}]},
                        "scan_id": to_scan_id,
                        "created_at": created_at,
                    }
                },
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
        """``limit`` applies as given, so a short list means the scan itself is short."""
        query = scan_query(project_id, scan_id, asset_type, primitive, name_search)
        docs = await self.aggregate([{"$match": query}, *SCAN_ORDER, {"$skip": skip}, {"$limit": limit}])
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

    async def evaluated_scan_ids(self, project_ids: list[str], scan_ids: list[str]) -> set[str]:
        """A posted CBOM that listed no asset found its scan free of cryptography."""
        with_assets = await self.collection.distinct(
            "scan_id", {"project_id": {"$in": project_ids}, "scan_id": {"$in": scan_ids}}
        )
        with_cbom = await self.db.scans.distinct("_id", {"_id": {"$in": scan_ids}, "scan_type": "cbom"})
        return {*with_assets, *with_cbom}

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
