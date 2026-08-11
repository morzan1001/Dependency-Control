"""Dependency enrichment data from external sources (deps.dev, license compliance)."""

from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase


class DependencyEnrichmentRepository:
    collection_name = "dependency_enrichments"

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection: AsyncIOMotorCollection = db[self.collection_name]

    async def get_by_purl(self, purl: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"purl": purl})

    async def get_many_by_purls(self, purls: list[str]) -> dict[str, dict[str, Any]]:
        if not purls:
            return {}

        cursor = self.collection.find({"purl": {"$in": purls}})
        docs = await cursor.to_list(length=len(purls))

        return {doc["purl"]: doc for doc in docs if doc.get("purl")}
