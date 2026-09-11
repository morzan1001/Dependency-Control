"""The project update primitives: what reaches the server, and what the ownership pipeline writes.

``update`` and ``update_many`` take field documents and wrap them in ``$set``; the ``_raw`` pair
hands the update to the server untouched, which is the only way to express ``$pull``, ``$unset``
or an aggregation pipeline.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.repositories.projects import ProjectRepository, replace_team_subset_pipeline
from tests.mocks.fake_mongo import FakeDatabase


def _spy_repo() -> tuple[ProjectRepository, MagicMock]:
    """A repository whose collection records the exact update it was handed."""
    collection = MagicMock()
    collection.update_one = AsyncMock(return_value=MagicMock(matched_count=1, modified_count=1))
    collection.update_many = AsyncMock(return_value=MagicMock(matched_count=1, modified_count=1))
    db = MagicMock()
    db.projects = collection
    repo = ProjectRepository(db)
    repo.get_by_id = AsyncMock(return_value=None)  # type: ignore[method-assign]
    return repo, collection


_PIPELINE = [{"$set": {"team_ids": {"$setUnion": [{"$ifNull": ["$team_ids", []]}, ["t1"]]}}}]


@pytest.mark.asyncio
async def test_update_many_raw_hands_a_pipeline_to_the_server_unwrapped():
    """A list wrapped in $set is not a pipeline; the server would reject it as a field named $set."""
    repo, collection = _spy_repo()

    await repo.update_many_raw({"team_ids": "t1"}, _PIPELINE)

    assert collection.update_many.await_args.args[1] == _PIPELINE


@pytest.mark.asyncio
async def test_update_raw_hands_a_pipeline_to_the_server_unwrapped():
    repo, collection = _spy_repo()

    await repo.update_raw("p1", _PIPELINE)

    assert collection.update_one.await_args.args[1] == _PIPELINE


@pytest.mark.asyncio
async def test_update_many_raw_hands_modifiers_through_untouched():
    """Team deletion needs $pull and $unset in one write; $set-wrapping either is a field write."""
    repo, collection = _spy_repo()
    ops = {"$pull": {"team_ids": "t1"}, "$unset": {"team_sources.t1": ""}}

    await repo.update_many_raw({"team_ids": "t1"}, ops)

    assert collection.update_many.await_args.args[1] == ops


@pytest.mark.asyncio
async def test_update_many_still_wraps_a_field_document_in_set():
    repo, collection = _spy_repo()

    await repo.update_many({"team_id": "t1"}, {"team_id": None})

    assert collection.update_many.await_args.args == ({"team_id": "t1"}, {"$set": {"team_id": None}})


@pytest.mark.asyncio
async def test_update_still_wraps_a_field_document_in_set():
    repo, collection = _spy_repo()

    await repo.update("p1", {"name": "renamed"})

    assert collection.update_one.await_args.args == ({"_id": "p1"}, {"$set": {"name": "renamed"}})


@pytest.mark.asyncio
async def test_update_many_raw_reports_how_many_documents_changed():
    db = FakeDatabase()
    await db.projects.insert_one({"_id": "p1", "team_ids": ["t1", "keep"], "team_sources": {"t1": "gitlab"}})
    await db.projects.insert_one({"_id": "p2", "team_ids": ["t1"], "team_sources": {"t1": "manual"}})
    await db.projects.insert_one({"_id": "p3", "team_ids": ["other"], "team_sources": {}})

    changed = await ProjectRepository(db).update_many_raw(
        {"team_ids": "t1"},
        {"$pull": {"team_ids": "t1"}, "$unset": {"team_sources.t1": ""}},
    )

    assert changed == 2
    assert (await db.projects.find_one({"_id": "p1"}))["team_ids"] == ["keep"]
    assert (await db.projects.find_one({"_id": "p1"}))["team_sources"] == {}
    assert (await db.projects.find_one({"_id": "p3"}))["team_ids"] == ["other"]


@pytest.mark.asyncio
async def test_the_ownership_pipeline_never_writes_null_over_absent_fields():
    """team_ids: null matches neither {"$size": 0} nor an element equality, so a project written
    that way disappears from the unassigned view and every ownership view at the same time."""
    db = FakeDatabase()
    await db.projects.insert_one({"_id": "p1", "name": "never-owned"})

    await ProjectRepository(db).update_raw("p1", replace_team_subset_pipeline("github", []))

    assert (await db.projects.find_one({"_id": "p1"}))["team_ids"] == []
    assert await db.projects.count_documents({"team_ids": {"$size": 0}}) == 1


@pytest.mark.asyncio
async def test_a_sync_does_not_evict_a_manual_co_owner():
    """The near-miss this codebase already had on team member sync, in its multi-team shape."""
    db = FakeDatabase()
    await db.projects.insert_one(
        {
            "_id": "p1",
            "team_ids": ["gl-stale", "kept-by-hand"],
            "team_sources": {"gl-stale": "gitlab", "kept-by-hand": "manual"},
        }
    )

    await ProjectRepository(db).update_raw("p1", replace_team_subset_pipeline("gitlab", ["gl-fresh"]))

    stored = await db.projects.find_one({"_id": "p1"})
    assert sorted(stored["team_ids"]) == ["gl-fresh", "kept-by-hand"]
    assert stored["team_sources"] == {"kept-by-hand": "manual", "gl-fresh": "gitlab"}
