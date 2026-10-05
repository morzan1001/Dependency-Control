"""Dependency enrichment data from external sources (deps.dev, license compliance)."""

import logging
from itertools import batched
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import UpdateOne

from app.core.purl import canonical_purl

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
        ops = []
        for entry in entries:
            if not (entry["purl"] and entry["data"]):
                continue
            purl = canonical_purl(entry["purl"])
            data = dict(entry["data"])
            # The document merges every scan's findings, so the list of who supplied them accumulates too.
            sources = data.pop("enrichment_sources", [])
            update: dict[str, Any] = {
                "$set": {**data, "purl": purl, "name": entry["name"], "version": entry["version"]}
            }
            if sources:
                update["$addToSet"] = {"enrichment_sources": {"$each": sources}}
            ops.append(UpdateOne({"purl": purl}, update, upsert=True))
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
