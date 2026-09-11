"""Repository for teams."""

import re
from datetime import datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import TEAM_ROLE_ADMIN
from app.core.metrics import track_db_operation
from app.models.team import Team

_USER_ID = "user_id"
_MEMBERS_USER_ID = f"members.{_USER_ID}"
_COL = "teams"


class TeamRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.teams

    async def get_by_id(self, team_id: str) -> Team | None:
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one({"_id": team_id})
        if data:
            return Team(**data)
        return None

    async def get_raw_by_id(self, team_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": team_id})

    # Don't match provider-synced teams by name — names aren't unique across instances
    # (cross-tenant collision); use get_raw_by_gitlab_group or get_raw_by_github_team instead.
    async def get_by_name(self, name: str) -> Team | None:
        data = await self.collection.find_one({"name": name})
        if data:
            return Team(**data)
        return None

    async def get_raw_by_gitlab_group(self, gitlab_instance_id: str, gitlab_group_id: int) -> dict[str, Any] | None:
        return await self.collection.find_one(
            {"gitlab_instance_id": gitlab_instance_id, "gitlab_group_id": gitlab_group_id}
        )

    async def get_raw_by_github_team(self, github_instance_id: str, github_team_id: int) -> dict[str, Any] | None:
        """The team already holding a binding. The unique index is built by hand before the deploy
        and its build can be skipped, so the binding endpoint checks the pair here as well."""
        return await self.collection.find_one(
            {"github_instance_id": github_instance_id, "github_team_id": github_team_id}
        )

    async def find_raw_by_github_org(self, github_instance_id: str, github_org: str) -> list[dict[str, Any]]:
        """Every team bound to one organisation of one instance. Scoped to the instance: a team
        number is unique per instance only, and two instances are two tenants."""
        cursor = self.collection.find(
            {
                "github_instance_id": github_instance_id,
                # GitHub organisation names differ only in case, so an equality match reports
                # "nobody holds this repository" whenever the binding was stored in another case.
                "github_org": {"$regex": f"^{re.escape(github_org)}$", "$options": "i"},
                # A binding without a team number addresses no team on GitHub. Keeping it would
                # leave every repository of the organisation undetermined instead of resolving
                # against the teams that are bound properly.
                "github_team_id": {"$ne": None},
            }
        )
        return await cursor.to_list(None)

    async def create(self, team: Team) -> Team:
        await self.collection.insert_one(team.model_dump(by_alias=True))
        return team

    async def update(self, team_id: str, update_data: dict[str, Any]) -> Team | None:
        await self.collection.update_one({"_id": team_id}, {"$set": update_data})
        return await self.get_by_id(team_id)

    async def update_raw(self, team_id: str, update_ops: dict[str, Any]) -> None:
        await self.collection.update_one({"_id": team_id}, update_ops)

    async def delete(self, team_id: str) -> bool:
        result = await self.collection.delete_one({"_id": team_id})
        return result.deleted_count > 0

    async def find_many(
        self,
        query: dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "name",
        sort_order: int = 1,
    ) -> list[Team]:
        cursor = self.collection.find(query).sort(sort_by, sort_order).skip(skip).limit(limit)
        docs = await cursor.to_list(limit)
        return [Team(**doc) for doc in docs]

    async def count(self, query: dict[str, Any] | None = None) -> int:
        return await self.collection.count_documents(query or {})

    async def find_by_member(self, user_id: str) -> list[Team]:
        cursor = self.collection.find({_MEMBERS_USER_ID: user_id})
        docs = await cursor.to_list(None)
        return [Team(**doc) for doc in docs]

    async def add_member(self, team_id: str, member_data: dict[str, Any], updated_at: datetime) -> bool:
        """False when the user is already a member; the filter decides, not an earlier read."""
        result = await self.collection.update_one(
            {"_id": team_id, _MEMBERS_USER_ID: {"$ne": member_data[_USER_ID]}},
            {"$push": {"members": member_data}, "$set": {"updated_at": updated_at}},
        )
        return bool(result.matched_count)

    async def remove_member(self, team_id: str, user_id: str, updated_at: datetime) -> bool:
        """False when the pull would leave the team with no admin.

        Expressed as a filter rather than a count taken from an earlier read, so two admins
        removing each other at once cannot both pass the guard.
        """
        result = await self.collection.update_one(
            {"_id": team_id, "members": {"$elemMatch": {_USER_ID: {"$ne": user_id}, "role": TEAM_ROLE_ADMIN}}},
            {"$pull": {"members": {_USER_ID: user_id}}, "$set": {"updated_at": updated_at}},
        )
        return bool(result.matched_count)

    async def update_member_role(self, team_id: str, user_id: str, role: str, updated_at: datetime) -> None:
        # Address the member by identity: a concurrent $pull shifts array indices under a positional write.
        await self.collection.update_one(
            {"_id": team_id},
            {"$set": {"members.$[m].role": role, "updated_at": updated_at}},
            array_filters=[{f"m.{_USER_ID}": user_id}],
        )

    async def is_member(self, team_id: str, user_id: str) -> bool:
        result = await self.collection.find_one({"_id": team_id, _MEMBERS_USER_ID: user_id}, {"_id": 1})
        return result is not None

    async def aggregate(self, pipeline: list[dict[str, Any]], limit: int | None = None) -> list[dict[str, Any]]:
        return await self.collection.aggregate(pipeline).to_list(limit)
