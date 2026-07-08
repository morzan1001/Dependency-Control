"""Repository for projects."""

from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import ReadPreference, ReturnDocument

from app.core.metrics import track_db_operation
from app.models.project import Project
from app.schemas.projections import ProjectIdOnly, ProjectMinimal, ProjectWithScanId

_COL = "projects"


class ProjectRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.projects

    def _primary(self) -> AsyncIOMotorCollection:
        return self.collection.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]

    async def get_by_id(self, project_id: str) -> Optional[Project]:
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one({"_id": project_id})
        return Project(**data) if data else None

    async def get_by_id_strong(self, project_id: str) -> Optional[Project]:
        with track_db_operation(_COL, "find_one"):
            data = await self._primary().find_one({"_id": project_id})
        return Project(**data) if data else None

    async def get_raw_by_id(self, project_id: str) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one({"_id": project_id})

    async def get_by_gitlab_id(self, gitlab_project_id: int) -> Optional[Project]:
        data = await self.collection.find_one({"gitlab_project_id": gitlab_project_id})
        if data:
            return Project(**data)
        return None

    async def get_by_gitlab_composite_key(self, gitlab_instance_id: str, gitlab_project_id: int) -> Optional[Project]:
        data = await self.collection.find_one(
            {"gitlab_instance_id": gitlab_instance_id, "gitlab_project_id": gitlab_project_id}
        )
        if data:
            return Project(**data)
        return None

    async def get_raw_by_gitlab_composite_key(
        self, gitlab_instance_id: str, gitlab_project_id: int
    ) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one(
            {"gitlab_instance_id": gitlab_instance_id, "gitlab_project_id": gitlab_project_id}
        )

    async def list_by_instance(self, gitlab_instance_id: str, skip: int = 0, limit: int = 100) -> List[Project]:
        cursor = self.collection.find({"gitlab_instance_id": gitlab_instance_id}).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [Project(**doc) for doc in docs]

    async def count_by_instance(self, gitlab_instance_id: str) -> int:
        return await self.collection.count_documents({"gitlab_instance_id": gitlab_instance_id})

    async def get_by_github_composite_key(
        self, github_instance_id: str, github_repository_id: str
    ) -> Optional[Project]:
        data = await self.collection.find_one(
            {"github_instance_id": github_instance_id, "github_repository_id": github_repository_id}
        )
        if data:
            return Project(**data)
        return None

    async def get_raw_by_github_composite_key(
        self, github_instance_id: str, github_repository_id: str
    ) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one(
            {"github_instance_id": github_instance_id, "github_repository_id": github_repository_id}
        )

    async def list_by_github_instance(self, github_instance_id: str, skip: int = 0, limit: int = 100) -> List[Project]:
        cursor = self.collection.find({"github_instance_id": github_instance_id}).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [Project(**doc) for doc in docs]

    async def count_by_github_instance(self, github_instance_id: str) -> int:
        return await self.collection.count_documents({"github_instance_id": github_instance_id})

    async def find_or_create_by_gitlab_key(
        self, gitlab_instance_id: str, gitlab_project_id: int, project: Project
    ) -> Tuple[Project, bool]:
        """Atomic find-or-create by GitLab composite key ($setOnInsert leaves existing projects untouched); returns (project, created)."""
        result = await self.collection.find_one_and_update(
            {"gitlab_instance_id": gitlab_instance_id, "gitlab_project_id": gitlab_project_id},
            {"$setOnInsert": project.model_dump(by_alias=True)},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        created = result["_id"] == project.id
        return Project(**result), created

    async def find_or_create_by_github_key(
        self, github_instance_id: str, github_repository_id: str, project: Project
    ) -> Tuple[Project, bool]:
        """Atomic find-or-create by GitHub composite key ($setOnInsert leaves existing projects untouched); returns (project, created)."""
        result = await self.collection.find_one_and_update(
            {"github_instance_id": github_instance_id, "github_repository_id": github_repository_id},
            {"$setOnInsert": project.model_dump(by_alias=True)},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        created = result["_id"] == project.id
        return Project(**result), created

    async def create(self, project: Project) -> Project:
        with track_db_operation(_COL, "insert_one"):
            await self.collection.insert_one(project.model_dump(by_alias=True))
        return project

    async def create_raw(self, project_data: Dict[str, Any]) -> None:
        with track_db_operation(_COL, "insert_one"):
            await self.collection.insert_one(project_data)

    async def update(self, project_id: str, update_data: Dict[str, Any]) -> Optional[Project]:
        if update_data:
            with track_db_operation(_COL, "update_one"):
                await self.collection.update_one({"_id": project_id}, {"$set": update_data})
        return await self.get_by_id(project_id)

    async def update_raw(self, project_id: str, update_ops: Dict[str, Any]) -> None:
        with track_db_operation(_COL, "update_one"):
            await self.collection.update_one({"_id": project_id}, update_ops)

    async def delete(self, project_id: str) -> bool:
        with track_db_operation(_COL, "delete_one"):
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
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(query, projection).sort(sort_by, sort_order).skip(skip).limit(limit)
            docs = await cursor.to_list(limit)
        return [Project(**doc) for doc in docs]

    async def find_many_raw(
        self,
        query: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "name",
        sort_order: int = 1,
        projection: Optional[Dict[str, int]] = None,
    ) -> List[Dict[str, Any]]:
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(query, projection).sort(sort_by, sort_order).skip(skip).limit(limit)
            return await cursor.to_list(limit)

    async def find_many_ids(
        self,
        query: Dict[str, Any],
        limit: int = 1000,
    ) -> List[ProjectIdOnly]:
        cursor = self.collection.find(query, {"_id": 1}).limit(limit)
        docs = await cursor.to_list(limit)
        return [ProjectIdOnly(**doc) for doc in docs]

    async def find_many_with_scan_id(
        self,
        query: Dict[str, Any],
        limit: int = 1000,
    ) -> List[ProjectWithScanId]:
        cursor = self.collection.find(query, {"_id": 1, "name": 1, "latest_scan_id": 1, "deleted_branches": 1}).limit(
            limit
        )
        docs = await cursor.to_list(limit)
        return [ProjectWithScanId(**doc) for doc in docs]

    async def find_many_minimal(
        self,
        query: Dict[str, Any],
        limit: int = 1000,
    ) -> List[ProjectMinimal]:
        cursor = self.collection.find(query, {"_id": 1, "name": 1}).limit(limit)
        docs = await cursor.to_list(limit)
        return [ProjectMinimal(**doc) for doc in docs]

    async def count(self, query: Optional[Dict[str, Any]] = None) -> int:
        with track_db_operation(_COL, "count"):
            return await self.collection.count_documents(query or {})

    async def aggregate(self, pipeline: List[Dict[str, Any]], limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Prefer $limit inside the pipeline over the limit arg."""
        with track_db_operation(_COL, "aggregate"):
            return await self.collection.aggregate(pipeline).to_list(limit)

    async def update_many(self, query: Dict[str, Any], update_data: Dict[str, Any]) -> int:
        with track_db_operation(_COL, "update_many"):
            result = await self.collection.update_many(query, {"$set": update_data})
        return result.modified_count

    async def add_member(self, project_id: str, member_data: Dict[str, Any]) -> None:
        await self.collection.update_one({"_id": project_id}, {"$push": {"members": member_data}})

    async def remove_member(self, project_id: str, user_id: str) -> None:
        await self.collection.update_one({"_id": project_id}, {"$pull": {"members": {"user_id": user_id}}})

    async def update_member(self, project_id: str, user_id: str, update_data: Dict[str, Any]) -> None:
        """update_data uses full field paths, e.g. {'members.0.role': 'admin'}."""
        await self.collection.update_one({"_id": project_id, "members.user_id": user_id}, {"$set": update_data})

    async def iterate(
        self, query: Optional[Dict[str, Any]] = None, projection: Optional[Dict[str, int]] = None
    ) -> AsyncGenerator[Project, None]:
        async for doc in self.collection.find(query or {}, projection):
            yield Project(**doc)

    async def iterate_all(self, query: Optional[Dict[str, Any]] = None) -> AsyncGenerator[Dict[str, Any], None]:
        async for doc in self.collection.find(query or {}):
            yield doc
