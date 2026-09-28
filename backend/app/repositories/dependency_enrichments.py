"""Dependency enrichment data from external sources (deps.dev, license compliance)."""

import logging
from itertools import batched
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import UpdateOne

from app.services.analyzers.purl_utils import canonical_purl

logger = logging.getLogger(__name__)

_UPSERT_CHUNK_SIZE = 500


class DependencyEnrichmentRepository:
    collection_name = "dependency_enrichments"

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection: AsyncIOMotorCollection = db[self.collection_name]

    async def upsert_many(self, entries: list[dict[str, Any]]) -> int:
        """Upsert each entry with a purl and data under its canonical purl; the number persisted.

        A failed chunk is logged and skipped: enrichment is advisory and must not fail the analysis.
        """
        ops = [
            UpdateOne(
                {"purl": canonical_purl(entry["purl"])},
                {
                    "$set": {
                        **entry["data"],
                        "purl": canonical_purl(entry["purl"]),
                        "name": entry["name"],
                        "version": entry["version"],
                    }
                },
                upsert=True,
            )
            for entry in entries
            if entry["purl"] and entry["data"]
        ]
        persisted = 0
        for chunk in batched(ops, _UPSERT_CHUNK_SIZE, strict=False):
            try:
                await self.collection.bulk_write(list(chunk), ordered=False)
                persisted += len(chunk)
            except Exception as e:
                logger.exception("Failed to bulk upsert dependency enrichments: %s", e)
        return persisted

    async def get_by_purl(self, purl: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"purl": canonical_purl(purl)})

    async def get_many_by_purls(self, purls: list[str]) -> dict[str, dict[str, Any]]:
        """Docs are keyed by canonical purl; the result is keyed by the purls the caller asked for."""
        if not purls:
            return {}

        canonical_by_requested = {purl: canonical_purl(purl) for purl in purls}
        canonical_purls = list(set(canonical_by_requested.values()))
        cursor = self.collection.find({"purl": {"$in": canonical_purls}})
        docs = await cursor.to_list(length=len(canonical_purls))

        by_canonical = {doc["purl"]: doc for doc in docs if doc.get("purl")}
        return {
            requested: by_canonical[canonical]
            for requested, canonical in canonical_by_requested.items()
            if canonical in by_canonical
        }
