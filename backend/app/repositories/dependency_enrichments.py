"""
Dependency Enrichment Repository

Repository for accessing dependency enrichment data from external sources
like deps.dev, license compliance databases, etc.
"""

from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase


class DependencyEnrichmentRepository:
    """
    Repository for dependency enrichment data.

    This collection stores enrichment data for dependencies:
    - deps_dev: Data from deps.dev API (versions, advisories, etc.)
    - license_compliance: License analysis data (category, risks, obligations)
    - Other enrichment sources as needed
    """

    collection_name = "dependency_enrichments"

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection: AsyncIOMotorCollection = db[self.collection_name]

    async def get_by_purl(self, purl: str) -> Optional[Dict[str, Any]]:
        """
        Get enrichment data by Package URL (purl).

        Args:
            purl: The Package URL identifier (e.g., 'pkg:npm/lodash@4.17.21')

        Returns:
            Enrichment document or None if not found
        """
        return await self.collection.find_one({"purl": purl})

    async def get_many_by_purls(self, purls: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Get enrichment data for multiple PURLs.

        Args:
            purls: List of Package URLs

        Returns:
            Dict mapping purl to enrichment document
        """
        if not purls:
            return {}

        cursor = self.collection.find({"purl": {"$in": purls}})
        docs = await cursor.to_list(length=len(purls))

        return {doc["purl"]: doc for doc in docs if doc.get("purl")}

    async def upsert(self, purl: str, data: Dict[str, Any]) -> None:
        """
        Insert or update enrichment data for a purl.

        Args:
            purl: The Package URL identifier
            data: Enrichment data to store
        """
        await self.collection.update_one(
            {"purl": purl},
            {"$set": {**data, "purl": purl}},
            upsert=True,
        )

    async def update_deps_dev(self, purl: str, deps_dev_data: Dict[str, Any]) -> None:
        """
        Update deps.dev enrichment data for a purl.

        Args:
            purl: The Package URL identifier
            deps_dev_data: Data from deps.dev API
        """
        await self.collection.update_one(
            {"purl": purl},
            {"$set": {"deps_dev": deps_dev_data, "purl": purl}},
            upsert=True,
        )

    async def update_license_compliance(
        self, purl: str, license_data: Dict[str, Any]
    ) -> None:
        """
        Update license compliance data for a purl.

        Args:
            purl: The Package URL identifier
            license_data: License compliance analysis data
        """
        await self.collection.update_one(
            {"purl": purl},
            {"$set": {"license_compliance": license_data, "purl": purl}},
            upsert=True,
        )

    async def delete_by_purl(self, purl: str) -> bool:
        """
        Delete enrichment data for a purl.

        Args:
            purl: The Package URL identifier

        Returns:
            True if document was deleted, False otherwise
        """
        result = await self.collection.delete_one({"purl": purl})
        return result.deleted_count > 0

    async def count(self, query: Optional[Dict[str, Any]] = None) -> int:
        """Count documents matching query."""
        return await self.collection.count_documents(query or {})

    async def find_many(
        self,
        query: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        projection: Optional[Dict[str, int]] = None,
    ) -> List[Dict[str, Any]]:
        """Find multiple documents matching query."""
        cursor = self.collection.find(query, projection)
        cursor = cursor.skip(skip).limit(limit)
        return await cursor.to_list(limit)
