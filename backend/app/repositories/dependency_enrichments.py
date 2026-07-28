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

    async def upsert(self, purl: str, data: dict[str, Any]) -> None:
        await self.collection.update_one(
            {"purl": purl},
            {"$set": {**data, "purl": purl}},
            upsert=True,
        )

    async def update_deps_dev(self, purl: str, deps_dev_data: dict[str, Any]) -> None:
        await self.collection.update_one(
            {"purl": purl},
            {"$set": {"deps_dev": deps_dev_data, "purl": purl}},
            upsert=True,
        )

    async def update_license_compliance(self, purl: str, license_data: dict[str, Any]) -> None:
        await self.collection.update_one(
            {"purl": purl},
            {"$set": {"license_compliance": license_data, "purl": purl}},
            upsert=True,
        )

    async def delete_by_purl(self, purl: str) -> bool:
        result = await self.collection.delete_one({"purl": purl})
        return result.deleted_count > 0

    async def count(self, query: dict[str, Any] | None = None) -> int:
        return await self.collection.count_documents(query or {})

    async def find_many(
        self,
        query: dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        projection: dict[str, int] | None = None,
    ) -> list[dict[str, Any]]:
        cursor = self.collection.find(query, projection)
        cursor = cursor.skip(skip).limit(limit)
        return await cursor.to_list(limit)
