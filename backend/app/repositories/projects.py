"""Repository for projects."""

from collections.abc import Iterable
from typing import Any

from pymongo import ReturnDocument

from app.core.constants import PROJECT_ROLE_ADMIN, TEAM_SOURCE_MANUAL
from app.models.project import Project
from app.repositories.base import BaseRepository, UpdateOps
from app.schemas.projections import ProjectWithScanId

_MEMBERS_USER_ID = "members.user_id"


# A project whose ``team_ids`` is absent or explicitly null. Measured against the server: this
# matches both, ``$size: 0`` matches neither, and neither shape answers an ownership filter — such a
# project sits in no team view and in no unassigned view at once. Normalising it to ``[]`` at
# startup is what lets everything downstream spell unassigned ``{"team_ids": {"$size": 0}}``.
UNSHAPED_OWNERS: dict[str, Any] = {"team_ids": {"$in": [None]}}


def _team_source_entries(cond: dict[str, Any]) -> dict[str, Any]:
    """The provenance map's ``{k, v}`` entries satisfying ``cond``; a missing map reads as empty."""
    return {
        "$filter": {
            "input": {"$objectToArray": {"$ifNull": ["$team_sources", {}]}},
            "as": "entry",
            "cond": cond,
        }
    }


def _owned_by(source: str) -> dict[str, Any]:
    """The team_sources entries this source wrote, as an array of ``{k, v}`` documents.

    Equality against the whole value and not a provider prefix: ``source`` names one instance, and
    a prefix match would hand every instance of a provider the owners of all the others.
    """
    return _team_source_entries({"$eq": ["$$entry.v", source]})


def _sources_except(source: str) -> dict[str, Any]:
    """The provenance map without the entries ``source`` wrote."""
    return {"$arrayToObject": _team_source_entries({"$ne": ["$$entry.v", source]})}


def _retired_by(source: str) -> dict[str, Any]:
    """The owners a ``source`` write replaces — the ones its own provenance entries name.

    An owner no entry names is therefore never retired by a sync: nothing shows that instance set
    it, and the picker is the only writer that may take it away. A second instance of the same
    provider is as foreign here as the other provider is.
    """
    return {"$map": {"input": _owned_by(source), "as": "entry", "in": "$$entry.k"}}


def owners_replaced_by(project: Project, source: str) -> set[str]:
    """``_retired_by`` in Python, for the callers that must size the result before writing it."""
    return {team_id for team_id, entry in project.team_sources.items() if entry == source}


def replace_team_subset_pipeline(source: str, team_ids: list[str]) -> list[dict[str, Any]]:
    """A pipeline update replacing exactly the owners ``source`` set, leaving the others alone.

    ``source`` is ``team_source(provider, instance_id)``, so "the owners it set" is per instance:
    two GitLab instances resolving different teams onto one project each keep the other's owner,
    where a provider-wide source has them retire each other's on every CI run in turn.

    A pipeline and not two modifiers: ``$pull`` plus ``$addToSet`` on ``team_ids`` in one classic
    update is rejected with code 40, and splitting it into two writes exposes an empty ``team_ids``
    to concurrent readers, which is indistinguishable from an unassigned project.

    Both stored fields are read through ``$ifNull`` because a document missing either one would
    otherwise be written ``team_ids: null`` — a value that matches neither ``{"$size": 0}`` nor an
    element equality, so the project would drop out of the unassigned view and every ownership
    view at once.
    """
    held_elsewhere = {"$setDifference": [{"$ifNull": ["$team_ids", []]}, _retired_by(source)]}
    return [
        {
            "$set": {
                "team_ids": {"$setUnion": [held_elsewhere, team_ids]},
                # Owners held through another writer stay unstamped, so the provider never retires a hand assignment.
                "team_sources": {
                    "$mergeObjects": [
                        _sources_except(source),
                        {
                            "$arrayToObject": {
                                "$map": {
                                    "input": {"$setDifference": [{"$literal": team_ids}, held_elsewhere]},
                                    "as": "owner",
                                    "in": {"k": "$$owner", "v": source},
                                }
                            }
                        },
                    ]
                },
            }
        },
    ]


def _sources_kept(team_ids: list[str]) -> dict[str, Any]:
    """The provenance entries naming one of ``team_ids``."""
    return {"$arrayToObject": _team_source_entries({"$in": ["$$entry.k", {"$literal": team_ids}]})}


def set_owners_pipeline(team_ids: list[str]) -> list[dict[str, Any]]:
    """A pipeline update making ``team_ids`` the project's entire owner set.

    An owner that stays keeps the provenance it had. Restamping one a provider established as a
    hand assignment would exempt it from that provider's next sync for good, so the new map takes
    the stored entry wherever there is one and reads the rest as hand-assigned. An owner left out
    goes whatever set it, and returns only when its provider still resolves it.

    A pipeline because the map is a function of the stored one, which no classic modifier can
    read — and ``$set`` beside ``$pull`` on ``team_ids`` is rejected with code 40 in any case.
    """
    owners = sorted(set(team_ids))
    return [
        {
            "$set": {
                "team_ids": {"$literal": owners},
                "team_sources": {"$mergeObjects": [dict.fromkeys(owners, TEAM_SOURCE_MANUAL), _sources_kept(owners)]},
            }
        },
    ]


def remove_team_pipeline(team_id: str) -> list[dict[str, Any]]:
    """Remove one owner whatever wrote it."""
    return [
        {
            "$set": {
                "team_ids": {"$setDifference": [{"$ifNull": ["$team_ids", []]}, [team_id]]},
                "team_sources": {"$arrayToObject": _team_source_entries({"$ne": ["$$entry.k", team_id]})},
            }
        },
    ]


def _literal_set_stage(fields: dict[str, Any]) -> dict[str, Any]:
    """A ``$set`` stage writing stored values, for a pipeline that also computes some.

    ``$literal`` because a stage reads a bare string beginning with ``$`` as a field path.
    """
    return {"$set": {name: {"$literal": value} for name, value in fields.items()}}


def ownership_fields(team_ids: list[str], source: str) -> dict[str, Any]:
    """The stored ownership of a project being inserted, in the order ``$setUnion`` leaves behind."""
    owners = sorted(set(team_ids))
    return {"team_ids": owners, "team_sources": dict.fromkeys(owners, source)}


def _gitlab_key(instance_id: str, project_id: int) -> dict[str, Any]:
    return {"gitlab_instance_id": instance_id, "gitlab_project_id": project_id}


def _github_key(instance_id: str, repository_id: str) -> dict[str, Any]:
    return {"github_instance_id": instance_id, "github_repository_id": repository_id}


def surviving_admin_filter(admin_owners: list[str], leaving_member: str | None = None) -> dict[str, Any]:
    """Match only while an admin other than ``leaving_member`` remains; the write checks it, so no race removes both."""
    other_admin: dict[str, Any] = {"role": PROJECT_ROLE_ADMIN}
    if leaving_member is not None:
        other_admin["user_id"] = {"$ne": leaving_member}
    return {"$or": [{"members": {"$elemMatch": other_admin}}, {"team_ids": {"$in": admin_owners}}]}


class ProjectRepository(BaseRepository[Project]):
    collection_name = "projects"
    model_class = Project

    async def get_raw_by_gitlab_composite_key(
        self, gitlab_instance_id: str, gitlab_project_id: int
    ) -> dict[str, Any] | None:
        return await self.find_one_raw(_gitlab_key(gitlab_instance_id, gitlab_project_id))

    async def get_raw_by_github_composite_key(
        self, github_instance_id: str, github_repository_id: str
    ) -> dict[str, Any] | None:
        return await self.find_one_raw(_github_key(github_instance_id, github_repository_id))

    async def find_or_create_by_gitlab_key(
        self, gitlab_instance_id: str, gitlab_project_id: int, project: Project
    ) -> tuple[Project, bool]:
        return await self._find_or_create(_gitlab_key(gitlab_instance_id, gitlab_project_id), project)

    async def find_or_create_by_github_key(
        self, github_instance_id: str, github_repository_id: str, project: Project
    ) -> tuple[Project, bool]:
        return await self._find_or_create(_github_key(github_instance_id, github_repository_id), project)

    async def _find_or_create(self, key: dict[str, Any], project: Project) -> tuple[Project, bool]:
        """Atomic find-or-create by a VCS composite key ($setOnInsert leaves existing projects untouched); returns (project, created)."""
        result = await self.collection.find_one_and_update(
            key,
            {"$setOnInsert": project.model_dump(by_alias=True)},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return Project(**result), result["_id"] == project.id

    async def find_many_with_scan_id(
        self,
        query: dict[str, Any],
        limit: int,
    ) -> list[ProjectWithScanId]:
        # Callers derive the limit from the id list they are asking about, and Mongo reads
        # limit(0) as unbounded, so an empty list has to answer before the query is built.
        if limit <= 0:
            return []
        cursor = self.collection.find(
            query,
            {
                "_id": 1,
                "name": 1,
                "latest_scan_id": 1,
                "deleted_branches": 1,
                "default_branch": 1,
                "active_analyzers": 1,
            },
        ).limit(limit)
        docs = await cursor.to_list(limit)
        return [ProjectWithScanId(**doc) for doc in docs]

    async def names_by_ids(self, project_ids: Iterable[str | None]) -> dict[str, str]:
        """Only projects that exist; each caller names a missing one its own way."""
        wanted = list({project_id for project_id in project_ids if project_id})
        docs = await self.find_many_raw({"_id": {"$in": wanted}}, limit=len(wanted), projection={"name": 1})
        return {doc["_id"]: doc["name"] for doc in docs}

    async def update_fields_and_owners(
        self,
        project_id: str,
        fields: dict[str, Any],
        ownership_stages: list[dict[str, Any]],
        guard: dict[str, Any] | None = None,
    ) -> bool:
        """Stored fields and computed ownership as one pipeline, so the project is written once.

        True without a write when there is nothing to write; otherwise whether ``guard`` still held.
        """
        stages = ([_literal_set_stage(fields)] if fields else []) + ownership_stages
        return not stages or await self.update_raw(project_id, stages, guard)

    async def update_many_raw(self, query: dict[str, Any], update_ops: UpdateOps) -> int:
        """``update_ops`` reaches the server verbatim: modifiers as a document, a pipeline as a list.

        Counts modified, not matched: a pipeline that recomputes the value already stored reports 0.
        """
        result = await self.collection.update_many(query, update_ops)
        return result.modified_count

    async def add_member(self, project_id: str, member_data: dict[str, Any]) -> bool:
        """False when the user is already a member; the filter decides, not an earlier read."""
        result = await self.collection.update_one(
            {"_id": project_id, _MEMBERS_USER_ID: {"$ne": member_data["user_id"]}},
            {"$push": {"members": member_data}},
        )
        return bool(result.matched_count)

    async def remove_member(self, project_id: str, user_id: str, guard: dict[str, Any] | None = None) -> bool:
        """False when ``guard`` no longer holds, e.g. ``surviving_admin_filter``."""
        result = await self.collection.update_one(
            {"_id": project_id, **(guard or {})},
            {"$pull": {"members": {"user_id": user_id}}},
        )
        return bool(result.matched_count)

    async def remove_user_from_all(self, user_id: str) -> None:
        await self.collection.update_many({_MEMBERS_USER_ID: user_id}, {"$pull": {"members": {"user_id": user_id}}})

    async def update_member(
        self,
        project_id: str,
        user_id: str,
        member_fields: dict[str, Any],
        guard: dict[str, Any] | None = None,
    ) -> bool:
        """member_fields are plain member field names, e.g. {'role': 'admin'}.

        The member is addressed by identity because a concurrent $pull shifts array indices.
        False when ``guard`` no longer holds.
        """
        result = await self.collection.update_one(
            {"_id": project_id, **(guard or {})},
            {"$set": {f"members.$[m].{field}": value for field, value in member_fields.items()}},
            array_filters=[{"m.user_id": user_id}],
        )
        return bool(result.matched_count)
