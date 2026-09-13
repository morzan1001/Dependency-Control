"""Repository for teams."""

import re
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ReturnDocument

from app.core.constants import TEAM_ROLE_ADMIN, TEAM_SOURCE_GITHUB, team_binding_key
from app.core.metrics import track_db_operation
from app.models.team import Team

_USER_ID = "user_id"
_MEMBERS_USER_ID = f"members.{_USER_ID}"
_COL = "teams"
_BINDINGS = "bindings"
_BINDING_KEY = f"{_BINDINGS}.key"
_BINDING_INSTANCE = f"{_BINDINGS}.instance_id"
# The identifier the array filters address one binding by; the update path has to name the same one.
_ENTRY = "entry"


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
    # (cross-tenant collision); use get_raw_by_binding instead.
    async def get_by_name(self, name: str) -> Team | None:
        data = await self.collection.find_one({"name": name})
        if data:
            return Team(**data)
        return None

    async def get_raw_by_binding_key(self, key: str) -> dict[str, Any] | None:
        """The team holding one binding. The unique index is built by hand before the deploy and
        its build can be skipped, so the binding endpoint checks the key here as well."""
        return await self.collection.find_one({_BINDING_KEY: key})

    async def get_raw_by_binding(self, provider: str, instance_id: str, external_id: int) -> dict[str, Any] | None:
        return await self.get_raw_by_binding_key(team_binding_key(provider, instance_id, external_id))

    async def find_raw_unbound_for_instance(self, instance_id: str) -> list[dict[str, Any]]:
        """Every team this instance has no binding on, with the name a group is matched against.

        Scoped to the instance and not to the provider: a team bound elsewhere is nobody's here, and
        binding it for this instance too is what lets one team answer for several instances. A team
        already bound to *this* instance is somebody's, and taking it would have the one sync
        resolve two groups onto one member list.
        """
        cursor = self.collection.find({_BINDING_INSTANCE: {"$ne": instance_id}}, {"name": 1})
        return await cursor.to_list(None)

    async def add_binding_if_absent(self, team_id: str, binding: dict[str, Any]) -> dict[str, Any] | None:
        """Attach a binding to a team the instance does not hold yet; None when it holds one by now.

        The instance condition is part of the filter, so two ingests cannot both adopt one team, and
        no team ends up with two bindings on one instance — which the unique index cannot refuse,
        because a multikey index deduplicates the keys of a single document.
        """
        adopted: dict[str, Any] | None = await self.collection.find_one_and_update(
            {"_id": team_id, _BINDING_INSTANCE: {"$ne": binding["instance_id"]}},
            {"$push": {_BINDINGS: binding}, "$set": {"updated_at": datetime.now(timezone.utc)}},
            return_document=ReturnDocument.AFTER,
        )
        return adopted

    async def replace_binding_for_instance(self, team_id: str, binding: dict[str, Any]) -> bool:
        """Set the team's binding for one instance, replacing the one it holds there.

        Two writes rather than one: the append and the in-place replacement have different filters,
        and each is atomic on its own, so a binding written between them is replaced, not doubled.
        """
        if await self.add_binding_if_absent(team_id, binding) is not None:
            return True
        result = await self.collection.update_one(
            {"_id": team_id},
            {
                "$set": {f"{_BINDINGS}.$[{_ENTRY}]": binding, "updated_at": datetime.now(timezone.utc)},
            },
            array_filters=[{f"{_ENTRY}.instance_id": binding["instance_id"]}],
        )
        return bool(result.matched_count)

    async def remove_binding_for_instance(self, team_id: str, instance_id: str) -> bool:
        """False when the team holds no binding for that instance."""
        result = await self.collection.update_one(
            {"_id": team_id, _BINDING_INSTANCE: instance_id},
            {
                "$pull": {_BINDINGS: {"instance_id": instance_id}},
                "$set": {"updated_at": datetime.now(timezone.utc)},
            },
        )
        return bool(result.matched_count)

    async def update_with_binding(
        self, team_id: str, update_data: dict[str, Any], key: str, binding_fields: dict[str, Any]
    ) -> None:
        """One write for what a sync learned about a team and about the binding it resolved through.

        ``binding_fields`` addresses the entry by its key, which the display fields it carries are
        not part of, so a renamed group is restamped in place.
        """
        updates = {**update_data, **{f"{_BINDINGS}.$[{_ENTRY}].{name}": v for name, v in binding_fields.items()}}
        await self.collection.update_one(
            {"_id": team_id},
            {"$set": updates},
            # An unused identifier is an error, so it is only declared when the update names it.
            array_filters=[{f"{_ENTRY}.key": key}] if binding_fields else None,
        )

    async def find_raw_by_github_org(self, github_instance_id: str, github_org: str) -> list[dict[str, Any]]:
        """Every team bound to one organisation of one instance. Scoped to the instance: a team
        number is unique per instance only, and two instances are two tenants."""
        cursor = self.collection.find(
            {
                _BINDINGS: {
                    "$elemMatch": {
                        "provider": TEAM_SOURCE_GITHUB,
                        "instance_id": github_instance_id,
                        # GitHub organisation names differ only in case, so an equality match
                        # reports "nobody holds this repository" whenever the binding was stored
                        # in another case.
                        "org": {"$regex": f"^{re.escape(github_org)}$", "$options": "i"},
                    }
                }
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
