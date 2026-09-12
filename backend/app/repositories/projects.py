"""Repository for projects."""

from collections.abc import AsyncGenerator
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import ReadPreference, ReturnDocument

from app.core.constants import PROJECT_ROLE_ADMIN, TEAM_SOURCE_MANUAL
from app.core.metrics import track_db_operation
from app.models.project import Project
from app.schemas.projections import ProjectMinimal, ProjectWithScanId

_COL = "projects"
_MEMBERS_USER_ID = "members.user_id"


UpdateOps = dict[str, Any] | list[dict[str, Any]]

# A project whose ``team_ids`` is absent or explicitly null. Measured against the server: this
# matches both, ``$size: 0`` matches neither, and neither shape answers an ownership filter — such a
# project sits in no team view and in no unassigned view at once. Normalising it to ``[]`` at
# startup is what lets everything downstream spell unassigned ``{"team_ids": {"$size": 0}}``.
UNSHAPED_OWNERS: dict[str, Any] = {"team_ids": {"$in": [None]}}


def _owned_by(source: str) -> dict[str, Any]:
    """The team_sources entries this provider wrote, as an array of ``{k, v}`` documents."""
    return {
        "$filter": {
            "input": {"$objectToArray": {"$ifNull": ["$team_sources", {}]}},
            "as": "entry",
            "cond": {"$eq": ["$$entry.v", source]},
        }
    }


def _sources_except(source: str) -> dict[str, Any]:
    """The provenance map without the entries ``source`` wrote."""
    return {
        "$arrayToObject": {
            "$filter": {
                "input": {"$objectToArray": {"$ifNull": ["$team_sources", {}]}},
                "as": "entry",
                "cond": {"$ne": ["$$entry.v", source]},
            }
        }
    }


def _retired_by(source: str) -> dict[str, Any]:
    """The owners a ``source`` write replaces — the ones its own provenance entries name.

    An owner no entry names is therefore never retired by a sync: nothing shows that provider set
    it, and the picker is the only writer that may take it away.
    """
    return {"$map": {"input": _owned_by(source), "as": "entry", "in": "$$entry.k"}}


def owners_replaced_by(project: Project, source: str) -> set[str]:
    """``_retired_by`` in Python, for the callers that must size the result before writing it."""
    return {team_id for team_id, entry in project.team_sources.items() if entry == source}


# Read against the freshly written list, so it has to run in a stage of its own.
_MIRRORED_OWNER = {
    "$cond": [
        {"$in": [{"$ifNull": ["$team_id", None]}, {"$ifNull": ["$team_ids", []]}]},
        "$team_id",
        {"$ifNull": [{"$arrayElemAt": [{"$ifNull": ["$team_ids", []]}, 0]}, None]},
    ]
}

_MIRRORED_SOURCE = {
    "$ifNull": [
        {
            "$arrayElemAt": [
                {
                    "$map": {
                        "input": {
                            "$filter": {
                                "input": {"$objectToArray": {"$ifNull": ["$team_sources", {}]}},
                                "as": "entry",
                                "cond": {"$eq": ["$$entry.k", {"$ifNull": ["$team_id", None]}]},
                            }
                        },
                        "as": "entry",
                        "in": "$$entry.v",
                    }
                },
                0,
            ]
        },
        None,
    ]
}


def scalar_mirror_stages() -> list[dict[str, Any]]:
    """Point the legacy scalars at one of the stored owners, so the queries still reading them see
    a team that genuinely owns the project rather than one it lost.

    The incumbent is kept whenever it is still an owner: the array's order is whatever ``$setUnion``
    produced, and letting it decide would flip the team a project lists under whenever a co-owner
    with a lower id is added.
    """
    return [
        {"$set": {"team_id": _MIRRORED_OWNER}},
        {"$set": {"team_source": _MIRRORED_SOURCE}},
    ]


def replace_team_subset_pipeline(source: str, team_ids: list[str]) -> list[dict[str, Any]]:
    """A pipeline update replacing exactly the owners ``source`` set, leaving the others alone.

    A pipeline and not two modifiers: ``$pull`` plus ``$addToSet`` on ``team_ids`` in one classic
    update is rejected with code 40, and splitting it into two writes exposes an empty ``team_ids``
    to concurrent readers, which is indistinguishable from an unassigned project.

    Both stored fields are read through ``$ifNull`` because a document missing either one would
    otherwise be written ``team_ids: null`` — a value that matches neither ``{"$size": 0}`` nor an
    element equality, so the project would drop out of the unassigned view and every ownership
    view at once.
    """
    return [
        {
            "$set": {
                "team_ids": {
                    "$setUnion": [
                        {"$setDifference": [{"$ifNull": ["$team_ids", []]}, _retired_by(source)]},
                        team_ids,
                    ]
                },
                "team_sources": {"$mergeObjects": [_sources_except(source), dict.fromkeys(team_ids, source)]},
            }
        },
        *scalar_mirror_stages(),
    ]


def _sources_kept(team_ids: list[str]) -> dict[str, Any]:
    """The provenance entries naming one of ``team_ids``."""
    return {
        "$arrayToObject": {
            "$filter": {
                "input": {"$objectToArray": {"$ifNull": ["$team_sources", {}]}},
                "as": "entry",
                "cond": {"$in": ["$$entry.k", {"$literal": team_ids}]},
            }
        }
    }


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
                "team_sources": {
                    "$mergeObjects": [dict.fromkeys(owners, TEAM_SOURCE_MANUAL), _sources_kept(owners)]
                },
            }
        },
        *scalar_mirror_stages(),
    ]


def remove_team_pipeline(team_id: str) -> list[dict[str, Any]]:
    """Remove one owner whatever wrote it, and the scalars with it when it was the mirrored one.

    ``$pull`` and ``$unset`` would express the first half in one classic update, but not the
    second: only a pipeline can point the scalars at a remaining owner in the same write.
    """
    return [
        {
            "$set": {
                "team_ids": {"$setDifference": [{"$ifNull": ["$team_ids", []]}, [team_id]]},
                "team_sources": {
                    "$arrayToObject": {
                        "$filter": {
                            "input": {"$objectToArray": {"$ifNull": ["$team_sources", {}]}},
                            "as": "entry",
                            "cond": {"$ne": ["$$entry.k", team_id]},
                        }
                    }
                },
            }
        },
        *scalar_mirror_stages(),
    ]


def literal_set_stage(fields: dict[str, Any]) -> dict[str, Any]:
    """A ``$set`` stage writing stored values, for a pipeline that also computes some.

    ``$literal`` because a stage reads a bare string beginning with ``$`` as a field path.
    """
    return {"$set": {name: {"$literal": value} for name, value in fields.items()}}


def ownership_fields(team_ids: list[str], source: str) -> dict[str, Any]:
    """The stored ownership of a project being inserted, scalars included.

    Sorted, because that is the order ``$setUnion`` leaves behind: an unsorted insert would have
    the first sync reorder the list and move the scalars to a different owner for no reason.
    """
    owners = sorted(set(team_ids))
    return {
        "team_ids": owners,
        "team_sources": dict.fromkeys(owners, source),
        "team_id": owners[0] if owners else None,
        "team_source": source if owners else None,
    }


def _surviving_admin_filter(user_id: str, required: bool) -> dict[str, Any]:
    """Match only while a member other than ``user_id`` is an admin, so a write that would take
    the last one finds nothing to write to instead of racing a count from an earlier read."""
    if not required:
        return {}
    return {"members": {"$elemMatch": {"user_id": {"$ne": user_id}, "role": PROJECT_ROLE_ADMIN}}}


def surviving_owner_admin_filter(incumbent_admin_owners: list[str]) -> dict[str, Any]:
    """Match only while the project still holds an admin — a direct member, or one of the owners
    that supplies one and the write leaves in place.

    The same shape as ``_surviving_admin_filter`` and for the same reason: two concurrent writes
    each taking one of the last two admin-supplying owners both pass a check made beforehand, and
    the project ends up with nobody who can administer it.
    """
    return {
        "$or": [
            {"members": {"$elemMatch": {"role": PROJECT_ROLE_ADMIN}}},
            {"team_ids": {"$in": incumbent_admin_owners}},
        ]
    }


class ProjectRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.projects

    def _primary(self) -> AsyncIOMotorCollection:
        return self.collection.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]

    async def get_by_id(self, project_id: str) -> Project | None:
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one({"_id": project_id})
        return Project(**data) if data else None

    async def get_by_id_strong(self, project_id: str) -> Project | None:
        with track_db_operation(_COL, "find_one"):
            data = await self._primary().find_one({"_id": project_id})
        return Project(**data) if data else None

    async def get_raw_by_id(self, project_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": project_id})

    async def get_by_gitlab_id(self, gitlab_project_id: int) -> Project | None:
        data = await self.collection.find_one({"gitlab_project_id": gitlab_project_id})
        if data:
            return Project(**data)
        return None

    async def get_by_gitlab_composite_key(self, gitlab_instance_id: str, gitlab_project_id: int) -> Project | None:
        data = await self.collection.find_one(
            {"gitlab_instance_id": gitlab_instance_id, "gitlab_project_id": gitlab_project_id}
        )
        if data:
            return Project(**data)
        return None

    async def get_raw_by_gitlab_composite_key(
        self, gitlab_instance_id: str, gitlab_project_id: int
    ) -> dict[str, Any] | None:
        return await self.collection.find_one(
            {"gitlab_instance_id": gitlab_instance_id, "gitlab_project_id": gitlab_project_id}
        )

    async def list_by_instance(self, gitlab_instance_id: str, skip: int = 0, limit: int = 100) -> list[Project]:
        cursor = self.collection.find({"gitlab_instance_id": gitlab_instance_id}).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [Project(**doc) for doc in docs]

    async def count_by_instance(self, gitlab_instance_id: str) -> int:
        return await self.collection.count_documents({"gitlab_instance_id": gitlab_instance_id})

    async def get_by_github_composite_key(self, github_instance_id: str, github_repository_id: str) -> Project | None:
        data = await self.collection.find_one(
            {"github_instance_id": github_instance_id, "github_repository_id": github_repository_id}
        )
        if data:
            return Project(**data)
        return None

    async def get_raw_by_github_composite_key(
        self, github_instance_id: str, github_repository_id: str
    ) -> dict[str, Any] | None:
        return await self.collection.find_one(
            {"github_instance_id": github_instance_id, "github_repository_id": github_repository_id}
        )

    async def list_by_github_instance(self, github_instance_id: str, skip: int = 0, limit: int = 100) -> list[Project]:
        cursor = self.collection.find({"github_instance_id": github_instance_id}).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [Project(**doc) for doc in docs]

    async def count_by_github_instance(self, github_instance_id: str) -> int:
        return await self.collection.count_documents({"github_instance_id": github_instance_id})

    async def find_or_create_by_gitlab_key(
        self, gitlab_instance_id: str, gitlab_project_id: int, project: Project
    ) -> tuple[Project, bool]:
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
    ) -> tuple[Project, bool]:
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

    async def create_raw(self, project_data: dict[str, Any]) -> None:
        with track_db_operation(_COL, "insert_one"):
            await self.collection.insert_one(project_data)

    async def update(self, project_id: str, update_data: dict[str, Any]) -> Project | None:
        if update_data:
            with track_db_operation(_COL, "update_one"):
                await self.collection.update_one({"_id": project_id}, {"$set": update_data})
        return await self.get_by_id(project_id)

    async def update_raw(self, project_id: str, update_ops: UpdateOps, guard: dict[str, Any] | None = None) -> bool:
        """``update_ops`` reaches the server verbatim: modifiers as a document, a pipeline as a list.

        ``guard`` joins the write's own filter so a condition established beforehand cannot go
        stale in between. False when it no longer held.
        """
        with track_db_operation(_COL, "update_one"):
            result = await self.collection.update_one({"_id": project_id, **(guard or {})}, update_ops)
        return bool(result.matched_count)

    async def delete(self, project_id: str) -> bool:
        with track_db_operation(_COL, "delete_one"):
            result = await self.collection.delete_one({"_id": project_id})
        return result.deleted_count > 0

    async def find_many(
        self,
        query: dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "name",
        sort_order: int = 1,
        projection: dict[str, int] | None = None,
    ) -> list[Project]:
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(query, projection).sort(sort_by, sort_order).skip(skip).limit(limit)
            docs = await cursor.to_list(limit)
        return [Project(**doc) for doc in docs]

    async def find_many_raw(
        self,
        query: dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "name",
        sort_order: int = 1,
        projection: dict[str, int] | None = None,
    ) -> list[dict[str, Any]]:
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(query, projection).sort(sort_by, sort_order).skip(skip).limit(limit)
            return await cursor.to_list(limit)

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
            query, {"_id": 1, "name": 1, "latest_scan_id": 1, "deleted_branches": 1, "default_branch": 1}
        ).limit(limit)
        docs = await cursor.to_list(limit)
        return [ProjectWithScanId(**doc) for doc in docs]

    async def find_many_minimal(
        self,
        query: dict[str, Any],
        limit: int,
    ) -> list[ProjectMinimal]:
        cursor = self.collection.find(query, {"_id": 1, "name": 1}).limit(limit)
        docs = await cursor.to_list(limit)
        return [ProjectMinimal(**doc) for doc in docs]

    async def count(self, query: dict[str, Any] | None = None) -> int:
        with track_db_operation(_COL, "count"):
            return await self.collection.count_documents(query or {})

    async def aggregate(self, pipeline: list[dict[str, Any]], limit: int | None = None) -> list[dict[str, Any]]:
        """Prefer $limit inside the pipeline over the limit arg."""
        with track_db_operation(_COL, "aggregate"):
            return await self.collection.aggregate(pipeline).to_list(limit)

    async def update_many(self, query: dict[str, Any], update_data: dict[str, Any]) -> int:
        """``update_data`` is a document of field values; use ``update_many_raw`` for operators."""
        with track_db_operation(_COL, "update_many"):
            result = await self.collection.update_many(query, {"$set": update_data})
        return result.modified_count

    async def update_many_raw(self, query: dict[str, Any], update_ops: UpdateOps) -> int:
        """``update_ops`` reaches the server verbatim: modifiers as a document, a pipeline as a list.

        Counts modified, not matched: a pipeline that recomputes the value already stored reports 0.
        """
        with track_db_operation(_COL, "update_many"):
            result = await self.collection.update_many(query, update_ops)
        return result.modified_count

    async def add_member(self, project_id: str, member_data: dict[str, Any]) -> bool:
        """False when the user is already a member; the filter decides, not an earlier read."""
        result = await self.collection.update_one(
            {"_id": project_id, _MEMBERS_USER_ID: {"$ne": member_data["user_id"]}},
            {"$push": {"members": member_data}},
        )
        return bool(result.matched_count)

    async def remove_member(self, project_id: str, user_id: str, *, require_another_admin: bool = False) -> bool:
        """False when require_another_admin holds and no other member is an admin."""
        result = await self.collection.update_one(
            {"_id": project_id, **_surviving_admin_filter(user_id, require_another_admin)},
            {"$pull": {"members": {"user_id": user_id}}},
        )
        return bool(result.matched_count)

    async def update_member(
        self,
        project_id: str,
        user_id: str,
        member_fields: dict[str, Any],
        *,
        require_another_admin: bool = False,
    ) -> bool:
        """member_fields are plain member field names, e.g. {'role': 'admin'}.

        The member is addressed by identity because a concurrent $pull shifts array indices.
        False when require_another_admin holds and no other member is an admin.
        """
        result = await self.collection.update_one(
            {"_id": project_id, **_surviving_admin_filter(user_id, require_another_admin)},
            {"$set": {f"members.$[m].{field}": value for field, value in member_fields.items()}},
            array_filters=[{"m.user_id": user_id}],
        )
        return bool(result.matched_count)

    async def iterate(
        self, query: dict[str, Any] | None = None, projection: dict[str, int] | None = None
    ) -> AsyncGenerator[Project, None]:
        async for doc in self.collection.find(query or {}, projection):
            yield Project(**doc)

    async def iterate_all(self, query: dict[str, Any] | None = None) -> AsyncGenerator[dict[str, Any], None]:
        async for doc in self.collection.find(query or {}):
            yield doc
