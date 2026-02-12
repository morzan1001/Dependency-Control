"""
Team Repository

Centralizes all database operations for teams.
"""

from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.team import Team


_MEMBERS_USER_ID = "members.user_id"


class TeamRepository:
    """Repository for team database operations."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.teams

    async def get_by_id(self, team_id: str) -> Optional[Team]:
        """Get team by ID."""
        data = await self.collection.find_one({"_id": team_id})
        if data:
            return Team(**data)
        return None

    async def get_raw_by_id(self, team_id: str) -> Optional[Dict[str, Any]]:
        """Get raw team document by ID."""
        return await self.collection.find_one({"_id": team_id})

    async def get_by_name(self, name: str) -> Optional[Team]:
        """Get team by name."""
        data = await self.collection.find_one({"name": name})
        if data:
            return Team(**data)
        return None

    async def get_raw_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get raw team document by name."""
        return await self.collection.find_one({"name": name})

    async def get_raw_by_gitlab_group(self, gitlab_instance_id: str, gitlab_group_id: int) -> Optional[Dict[str, Any]]:
        """Get raw team document by GitLab instance + group ID."""
        return await self.collection.find_one(
            {"gitlab_instance_id": gitlab_instance_id, "gitlab_group_id": gitlab_group_id}
        )

    async def create(self, team: Team) -> Team:
        """Create a new team."""
        await self.collection.insert_one(team.model_dump(by_alias=True))
        return team

    async def update(self, team_id: str, update_data: Dict[str, Any]) -> Optional[Team]:
        """Update team by ID."""
        await self.collection.update_one({"_id": team_id}, {"$set": update_data})
        return await self.get_by_id(team_id)

    async def update_raw(self, team_id: str, update_ops: Dict[str, Any]) -> None:
        """Update team with raw MongoDB operations."""
        await self.collection.update_one({"_id": team_id}, update_ops)

    async def delete(self, team_id: str) -> bool:
        """Delete team by ID."""
        result = await self.collection.delete_one({"_id": team_id})
        return result.deleted_count > 0

    async def find_many(
        self,
        query: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "name",
        sort_order: int = 1,
    ) -> List[Team]:
        """Find multiple teams with pagination. Returns Pydantic models."""
        cursor = self.collection.find(query).sort(sort_by, sort_order).skip(skip).limit(limit)
        docs = await cursor.to_list(limit)
        return [Team(**doc) for doc in docs]

    async def count(self, query: Optional[Dict[str, Any]] = None) -> int:
        """Count teams matching query."""
        return await self.collection.count_documents(query or {})

    async def find_by_member(self, user_id: str) -> List[Team]:
        """Find teams where user is a member. Returns Pydantic models."""
        cursor = self.collection.find({_MEMBERS_USER_ID: user_id})
        docs = await cursor.to_list(None)
        return [Team(**doc) for doc in docs]

    async def add_member(self, team_id: str, member_data: Dict[str, Any]) -> None:
        """Add a member to team."""
        await self.collection.update_one({"_id": team_id}, {"$push": {"members": member_data}})

    async def remove_member(self, team_id: str, user_id: str) -> None:
        """Remove a member from team."""
        await self.collection.update_one({"_id": team_id}, {"$pull": {"members": {"user_id": user_id}}})

    async def update_member_role(self, team_id: str, user_id: str, role: str) -> None:
        """Update a member's role in team."""
        await self.collection.update_one(
            {"_id": team_id, _MEMBERS_USER_ID: user_id},
            {"$set": {"members.$.role": role}},
        )

    async def set_members(self, team_id: str, members: List[Dict[str, Any]], updated_at) -> None:
        """Replace all members in team."""
        await self.collection.update_one({"_id": team_id}, {"$set": {"members": members, "updated_at": updated_at}})

    async def is_member(self, team_id: str, user_id: str) -> bool:
        """Check if user is a member of team."""
        result = await self.collection.find_one({"_id": team_id, _MEMBERS_USER_ID: user_id})
        return result is not None

    async def aggregate(self, pipeline: List[Dict[str, Any]], limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Run aggregation pipeline."""
        return await self.collection.aggregate(pipeline).to_list(limit)
