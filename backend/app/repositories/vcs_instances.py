"""Shared persistence for VCS (GitLab/GitHub) instance repositories."""

from typing import Any

from app.models.base import VcsInstanceModel
from app.repositories.base import BaseRepository


def _excluding(query: dict[str, Any], exclude_id: str | None) -> dict[str, Any]:
    return {**query, "_id": {"$ne": exclude_id}} if exclude_id else query


class VcsInstanceRepository[T: VcsInstanceModel](BaseRepository[T]):
    """Subclasses set ``collection_name``, ``model_class`` and the project field that links to them."""

    project_link_field: str

    async def get_usable(self, instance_id: str) -> T | None:
        """The instance only while it can be called: present, active and holding a token."""
        instance = await self.get_by_id(instance_id)
        return instance if instance and instance.is_active and instance.access_token else None

    async def get_by_url(self, url: str) -> T | None:
        """Matches the issuer claim with any trailing slash stripped."""
        return await self.find_one({"url": url.rstrip("/")})

    async def create(self, model: T) -> T:
        doc = model.model_dump(by_alias=True)
        # access_token has exclude=True (for API responses), but must be stored in MongoDB
        if model.access_token is not None:
            doc["access_token"] = model.access_token
        await self.collection.insert_one(doc)
        return model

    async def exists_by_url(self, url: str, exclude_id: str | None = None) -> bool:
        return await self.exists(_excluding({"url": url}, exclude_id))

    async def exists_by_name(self, name: str, exclude_id: str | None = None) -> bool:
        return await self.exists(_excluding({"name": name}, exclude_id))
