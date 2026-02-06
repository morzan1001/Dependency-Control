"""
Project Repository

Centralizes all database operations for projects.
"""

from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.project import Project
from app.schemas.projections import ProjectIdOnly, ProjectMinimal, ProjectWithScanId


class ProjectRepository:
    """Repository for project database operations."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.projects

    async def get_by_id(self, project_id: str) -> Optional[Project]:
        """Get project by ID."""
        data = await self.collection.find_one({"_id": project_id})
        if data:
            return Project(**data)
        return None

    async def get_raw_by_id(self, project_id: str) -> Optional[Dict[str, Any]]:
        """Get raw project document by ID."""
        return await self.collection.find_one({"_id": project_id})

    async def get_by_gitlab_id(self, gitlab_project_id: int) -> Optional[Project]:
        """Get project by GitLab project ID."""
        data = await self.collection.find_one({"gitlab_project_id": gitlab_project_id})
        if data:
            return Project(**data)
        return None

    async def get_raw_by_gitlab_id(
        self, gitlab_project_id: int
    ) -> Optional[Dict[str, Any]]:
        """Get raw project document by GitLab project ID."""
        return await self.collection.find_one({"gitlab_project_id": gitlab_project_id})

    async def create(self, project: Project) -> Project:
        """Create a new project."""
        await self.collection.insert_one(project.model_dump(by_alias=True))
        return project

    async def create_raw(self, project_data: Dict[str, Any]) -> None:
        """Create a new project from raw data."""
        await self.collection.insert_one(project_data)

    async def update(
        self, project_id: str, update_data: Dict[str, Any]
    ) -> Optional[Project]:
        """Update project by ID."""
        if update_data:
            await self.collection.update_one({"_id": project_id}, {"$set": update_data})
        return await self.get_by_id(project_id)

    async def update_raw(self, project_id: str, update_ops: Dict[str, Any]) -> None:
        """Update project with raw MongoDB operations."""
        await self.collection.update_one({"_id": project_id}, update_ops)

    async def delete(self, project_id: str) -> bool:
        """Delete project by ID."""
        result = await self.collection.delete_one({"_id": project_id})
        return result.deleted_count > 0

    async def find_many(
        self,
        query: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "name",
        sort_order: int = 1,
        projection: Optional[Dict[str, int]] = None,
    ) -> List[Project]:
        """Find multiple projects with pagination. Returns Pydantic models."""
        cursor = (
            self.collection.find(query, projection)
            .sort(sort_by, sort_order)
            .skip(skip)
            .limit(limit)
        )
        docs = await cursor.to_list(limit)
        return [Project(**doc) for doc in docs]

    async def find_many_ids(
        self,
        query: Dict[str, Any],
        limit: int = 1000,
    ) -> List[ProjectIdOnly]:
        """Find project IDs matching query. Returns minimal Pydantic models."""
        cursor = self.collection.find(query, {"_id": 1}).limit(limit)
        docs = await cursor.to_list(limit)
        return [ProjectIdOnly(**doc) for doc in docs]

    async def find_many_with_scan_id(
        self,
        query: Dict[str, Any],
        limit: int = 1000,
    ) -> List[ProjectWithScanId]:
        """Find projects with scan IDs. Returns Pydantic models."""
        cursor = self.collection.find(
            query, {"_id": 1, "name": 1, "latest_scan_id": 1}
        ).limit(limit)
        docs = await cursor.to_list(limit)
        return [ProjectWithScanId(**doc) for doc in docs]

    async def find_many_minimal(
        self,
        query: Dict[str, Any],
        limit: int = 1000,
    ) -> List[ProjectMinimal]:
        """Find projects with ID and name only (performance optimized)."""
        cursor = self.collection.find(query, {"_id": 1, "name": 1}).limit(limit)
        docs = await cursor.to_list(limit)
        return [ProjectMinimal(**doc) for doc in docs]

    async def find_all(
        self,
        query: Optional[Dict[str, Any]] = None,
        projection: Optional[Dict[str, int]] = None,
    ) -> List[Dict[str, Any]]:
        """Find all projects matching query. Returns raw dicts (for projections)."""
        cursor = self.collection.find(query or {}, projection)
        return await cursor.to_list(None)

    async def count(self, query: Optional[Dict[str, Any]] = None) -> int:
        """Count projects matching query."""
        return await self.collection.count_documents(query or {})

    async def aggregate(self, pipeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run aggregation pipeline."""
        return await self.collection.aggregate(pipeline).to_list(None)

    async def update_many(
        self, query: Dict[str, Any], update_data: Dict[str, Any]
    ) -> int:
        """Update multiple projects matching query."""
        result = await self.collection.update_many(query, {"$set": update_data})
        return result.modified_count

    async def add_member(self, project_id: str, member_data: Dict[str, Any]) -> None:
        """Add a member to project."""
        await self.collection.update_one(
            {"_id": project_id}, {"$push": {"members": member_data}}
        )

    async def remove_member(self, project_id: str, user_id: str) -> None:
        """Remove a member from project."""
        await self.collection.update_one(
            {"_id": project_id}, {"$pull": {"members": {"user_id": user_id}}}
        )

    async def update_member(
        self, project_id: str, user_id: str, update_data: Dict[str, Any]
    ) -> None:
        """Update a member's data in project.

        Args:
            project_id: The project ID
            user_id: The user ID of the member
            update_data: Dictionary with full field paths (e.g., {'members.0.role': 'admin'})
        """
        await self.collection.update_one(
            {"_id": project_id, "members.user_id": user_id}, {"$set": update_data}
        )

    async def iterate_all(self, query: Optional[Dict[str, Any]] = None):
        """Iterate over all projects (async generator)."""
        async for doc in self.collection.find(query or {}):
            yield doc
