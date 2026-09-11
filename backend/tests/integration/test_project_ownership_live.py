"""The ownership write the whole phase rests on, through the repository, against a real server.

The shared operator table pins the pipeline's semantics; this pins the path around it — that
``update_raw`` hands a list to the server as a pipeline rather than a ``$set`` of a field named
``$set``, and that what comes back loads into the model with every owner intact.
"""

import pytest

from app.models.project import Project
from app.repositories.projects import ProjectRepository, remove_team_pipeline, replace_team_subset_pipeline
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT = {
    "_id": "p-live",
    "name": "demo",
    "team_ids": ["gl-stale", "kept-by-hand"],
    "team_sources": {"gl-stale": "gitlab", "kept-by-hand": "manual"},
    "team_id": "gl-stale",
    "team_source": "gitlab",
}


async def _assert_a_sync_keeps_the_manual_co_owner(db) -> None:
    repo = ProjectRepository(db)
    await db.projects.insert_one(dict(_PROJECT))

    await repo.update_raw("p-live", replace_team_subset_pipeline("gitlab", ["gl-fresh"]))

    project = Project(**await db.projects.find_one({"_id": "p-live"}))
    assert sorted(project.team_ids) == ["gl-fresh", "kept-by-hand"]
    assert project.team_sources == {"kept-by-hand": "manual", "gl-fresh": "gitlab"}
    # The scalar named the owner that was just retired, so it follows the list rather than a team
    # that no longer owns anything.
    assert project.team_id == "gl-fresh"
    assert project.team_source == "gitlab"
    # The project must stay findable: an ownership write that stored null would drop it out of
    # the unassigned view and every ownership view at once.
    assert await db.projects.count_documents({"team_ids": {"$size": 0}}) == 0
    assert await db.projects.count_documents({"team_ids": "kept-by-hand"}) == 1


async def _assert_a_deleted_team_leaves_the_others_owning(db) -> None:
    repo = ProjectRepository(db)
    await db.projects.insert_one(dict(_PROJECT))

    changed = await repo.update_many_raw({"team_ids": "gl-stale"}, remove_team_pipeline("gl-stale"))

    assert changed == 1
    project = Project(**await db.projects.find_one({"_id": "p-live"}))
    assert project.team_ids == ["kept-by-hand"]
    assert project.team_id == "kept-by-hand"


async def _assert_an_untouched_document_gains_both_shapes(db) -> None:
    repo = ProjectRepository(db)
    await db.projects.insert_one({"_id": "p-bare", "name": "never-owned"})

    await repo.update_raw("p-bare", replace_team_subset_pipeline("github", []))

    stored = await db.projects.find_one({"_id": "p-bare"})
    assert stored["team_ids"] == []
    assert stored["team_sources"] == {}
    assert stored["team_id"] is None
    assert await db.projects.count_documents({"team_ids": {"$size": 0}}) == 1


@pytest.mark.asyncio
async def test_a_sync_keeps_the_manual_co_owner():
    await _assert_a_sync_keeps_the_manual_co_owner(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_sync_keeps_the_manual_co_owner_on_real_mongo(db):
    await _assert_a_sync_keeps_the_manual_co_owner(db)


@pytest.mark.asyncio
async def test_a_deleted_team_leaves_the_others_owning():
    await _assert_a_deleted_team_leaves_the_others_owning(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_deleted_team_leaves_the_others_owning_on_real_mongo(db):
    await _assert_a_deleted_team_leaves_the_others_owning(db)


@pytest.mark.asyncio
async def test_an_untouched_document_gains_both_shapes():
    await _assert_an_untouched_document_gains_both_shapes(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_an_untouched_document_gains_both_shapes_on_real_mongo(db):
    await _assert_an_untouched_document_gains_both_shapes(db)
