"""Dependency enrichment data from external sources (deps.dev, license compliance)."""

from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase

from app.services.analyzers.purl_utils import canonical_purl


class DependencyEnrichmentRepository:
    collection_name = "dependency_enrichments"

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection: AsyncIOMotorCollection = db[self.collection_name]

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
