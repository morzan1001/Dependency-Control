"""Repository for teams."""

import re
from datetime import datetime, timezone
from typing import Any, NamedTuple

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.core.constants import TEAM_ROLE_ADMIN, TEAM_SOURCE_GITHUB, team_binding_key
from app.models.team import Team

_USER_ID = "user_id"
_MEMBERS = "members"
_MEMBERS_USER_ID = f"{_MEMBERS}.{_USER_ID}"
_MEMBERS_SOURCE = f"{_MEMBERS}.source"
_BINDINGS = "bindings"
_BINDING_KEY = f"{_BINDINGS}.key"
_BINDING_INSTANCE = f"{_BINDINGS}.instance_id"
# The identifier the array filters address one binding by; the update path has to name the same one.
_ENTRY = "entry"


class MemberSubset(NamedTuple):
    """The members one sync resolved, and the provenance tag bounding the entries it may replace."""

    source: str
    members: list[dict[str, Any]]


def _subset_members(subset: MemberSubset) -> dict[str, Any]:
    """Server-side swap of the ``subset.source`` entries: a concurrent add survives and a hand-added member wins."""
    kept = {
        "$filter": {
            "input": {"$ifNull": [f"${_MEMBERS}", []]},
            "as": "member",
            "cond": {"$ne": ["$$member.source", subset.source]},
        }
    }
    kept_ids = {"$map": {"input": "$$kept", "as": "member", "in": f"$$member.{_USER_ID}"}}
    added = {
        "$filter": {
            "input": {"$literal": subset.members},
            "as": "resolved",
            "cond": {"$not": [{"$in": [f"$$resolved.{_USER_ID}", kept_ids]}]},
        }
    }
    return {"$let": {"vars": {"kept": kept}, "in": {"$concatArrays": ["$$kept", added]}}}


def _detach_instance(instance_id: str, source: str) -> dict[str, Any]:
    """Pull the instance's binding and the members its sync added, which no sync would retire any more."""
    return {
        "$pull": {_BINDINGS: {"instance_id": instance_id}, _MEMBERS: {"source": source}},
        "$set": {"updated_at": datetime.now(timezone.utc)},
    }


def _binding_restamp_stage(key: str, binding_fields: dict[str, Any]) -> dict[str, Any]:
    """Restamp the display fields of the entry holding ``key``, leaving every other entry alone.

    A ``$map`` rather than array filters because a classic update and an aggregation pipeline
    cannot be combined, and the member subset above can only be expressed as a pipeline.
    """
    return {
        "$set": {
            _BINDINGS: {
                "$map": {
                    "input": {"$ifNull": [f"${_BINDINGS}", []]},
                    "as": _ENTRY,
                    "in": {
                        "$cond": [
                            {"$eq": [f"$${_ENTRY}.key", key]},
                            {"$mergeObjects": [f"$${_ENTRY}", binding_fields]},
                            f"$${_ENTRY}",
                        ]
                    },
                }
            }
        }
    }


class TeamRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.teams

    async def get_by_id(self, team_id: str) -> Team | None:
        data = await self.collection.find_one({"_id": team_id})
        if data:
            return Team(**data)
        return None

    async def get_raw_by_id(self, team_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": team_id})

    async def get_raw_by_binding_key(self, key: str) -> dict[str, Any] | None:
        """The team holding one binding. The unique index is built by hand before the deploy and
        its build can be skipped, so the binding endpoint checks the key here as well."""
        return await self.collection.find_one({_BINDING_KEY: key})

    async def get_raw_by_binding(self, provider: str, instance_id: str, external_id: int) -> dict[str, Any] | None:
        return await self.get_raw_by_binding_key(team_binding_key(provider, instance_id, external_id))

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

    async def remove_binding_for_instance(self, team_id: str, instance_id: str, source: str) -> bool:
        """False when the team holds no binding for that instance."""
        result = await self.collection.update_one(
            {"_id": team_id, _BINDING_INSTANCE: instance_id}, _detach_instance(instance_id, source)
        )
        return bool(result.matched_count)

    async def remove_instance(self, instance_id: str, source: str) -> int:
        result = await self.collection.update_many(
            {"$or": [{_BINDING_INSTANCE: instance_id}, {_MEMBERS_SOURCE: source}]},
            _detach_instance(instance_id, source),
        )
        return result.modified_count

    async def update_with_binding(
        self,
        team_id: str,
        update_data: dict[str, Any],
        key: str,
        binding_fields: dict[str, Any],
        member_subset: MemberSubset | None = None,
    ) -> None:
        """One write for what a sync learned about a team and about the binding it resolved through.

        ``binding_fields`` addresses the entry by its key, which the display fields it carries are
        not part of, so a renamed group is restamped in place.

        ``member_subset`` is None to leave the stored members alone. Given, it turns the write into
        a pipeline — the only form that can read the stored array — and the restamp travels as a
        ``$map`` because a classic modifier cannot be combined with one.
        """
        now = datetime.now(timezone.utc)
        if member_subset is not None:
            members = _subset_members(member_subset)
            query: dict[str, Any] = {"_id": team_id}
            if not update_data and not binding_fields:
                # An unchanged subset must not bump updated_at, or every ingest rewrites every holder.
                # As sets: each sync appends its entries last, so two sources would reorder forever.
                query["$expr"] = {"$not": [{"$setEquals": [members, {"$ifNull": [f"${_MEMBERS}", []]}]}]}
            stages: list[dict[str, Any]] = [{"$set": {_MEMBERS: members}}]
            if binding_fields:
                stages.append(_binding_restamp_stage(key, binding_fields))
            stages.append({"$set": {**update_data, "updated_at": now}})
            await self.collection.update_one(query, stages)
            return

        updates = {
            **update_data,
            "updated_at": now,
            **{f"{_BINDINGS}.$[{_ENTRY}].{name}": v for name, v in binding_fields.items()},
        }
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
            },
            {"name": 1, _BINDINGS: 1},
        )
        return await cursor.to_list(None)

    async def create(self, team: Team) -> Team:
        await self.collection.insert_one(team.model_dump(by_alias=True))
        return team

    async def create_bound(self, team: Team) -> dict[str, Any] | None:
        """The team as stored: this one, or the one a concurrent sync created for the same binding first."""
        document = team.model_dump(by_alias=True)
        try:
            await self.collection.insert_one(document)
        except DuplicateKeyError:
            return await self.get_raw_by_binding_key(team.bindings[0].key)
        return document

    async def update(self, team_id: str, update_data: dict[str, Any]) -> Team | None:
        await self.collection.update_one({"_id": team_id}, {"$set": update_data})
        return await self.get_by_id(team_id)

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
        if limit <= 0:
            return []
        cursor = self.collection.find(query).sort(sort_by, sort_order).skip(skip).limit(limit)
        docs = await cursor.to_list(limit)
        return [Team(**doc) for doc in docs]

    async def count(self, query: dict[str, Any] | None = None) -> int:
        return await self.collection.count_documents(query or {})

    async def find_ids(self, query: dict[str, Any]) -> list[str]:
        return [str(doc["_id"]) async for doc in self.collection.find(query, {"_id": 1})]

    async def members_by_team(self, team_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
        """Each existing team's member entries (user_id and role), in one read."""
        if not team_ids:
            return {}
        cursor = self.collection.find({"_id": {"$in": list(team_ids)}}, {"members.user_id": 1, "members.role": 1})
        return {str(doc["_id"]): doc.get(_MEMBERS) or [] async for doc in cursor}

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

    async def remove_user_from_all(self, user_id: str, updated_at: datetime) -> None:
        await self.collection.update_many(
            {_MEMBERS_USER_ID: user_id},
            {"$pull": {_MEMBERS: {_USER_ID: user_id}}, "$set": {"updated_at": updated_at}},
        )

    async def update_member_role(self, team_id: str, user_id: str, role: str, updated_at: datetime) -> bool:
        """False when a demotion would leave the team with no admin; the filter decides, as in remove_member."""
        query: dict[str, Any] = {"_id": team_id}
        if role != TEAM_ROLE_ADMIN:
            query[_MEMBERS] = {"$elemMatch": {_USER_ID: {"$ne": user_id}, "role": TEAM_ROLE_ADMIN}}
        # Address the member by identity: a concurrent $pull shifts array indices under a positional write.
        result = await self.collection.update_one(
            query,
            {"$set": {"members.$[m].role": role, "updated_at": updated_at}},
            array_filters=[{f"m.{_USER_ID}": user_id}],
        )
        return bool(result.matched_count)

    async def find_many_raw(
        self, query: dict[str, Any], sort_by: str = "name", sort_order: int = 1, limit: int | None = None
    ) -> list[dict[str, Any]]:
        return await self.collection.find(query).sort(sort_by, sort_order).to_list(limit)
