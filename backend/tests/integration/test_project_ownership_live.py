"""The ownership write the whole phase rests on, through the repository, against a real server.

The shared operator table pins the pipeline's semantics; this pins the path around it — that
``update_raw`` hands a list to the server as a pipeline rather than a ``$set`` of a field named
``$set``, and that what comes back loads into the model with every owner intact.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.projects import remove_project_team
from app.models.project import Project
from app.models.user import User
from app.repositories.projects import (
    ProjectRepository,
    owners_replaced_by,
    remove_team_pipeline,
    replace_team_subset_pipeline,
)
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


_LEGACY_PROJECT = {
    "_id": "p-legacy",
    "name": "predates-provenance",
    "team_ids": ["legacy"],
    "team_sources": {},
    "team_id": "legacy",
}


async def _assert_a_legacy_owner_outlives_a_sync_but_not_the_hand_assignment(db) -> None:
    """An owner no provenance entry names belongs to no provider, so a sync must add beside it.

    Read as anything but a hand assignment it would be immortal: no provider owns the entry, so
    none can retire it, and the picker replaces only what it is told is manual.
    """
    repo = ProjectRepository(db)
    await db.projects.insert_one(dict(_LEGACY_PROJECT))

    await repo.update_raw("p-legacy", replace_team_subset_pipeline("gitlab", ["gl-new"]))

    after_sync = Project(**await db.projects.find_one({"_id": "p-legacy"}))
    assert sorted(after_sync.team_ids) == ["gl-new", "legacy"]
    assert after_sync.team_sources == {"gl-new": "gitlab"}

    await repo.update_raw("p-legacy", replace_team_subset_pipeline("manual", ["by-hand"]))

    after_picker = Project(**await db.projects.find_one({"_id": "p-legacy"}))
    assert sorted(after_picker.team_ids) == ["by-hand", "gl-new"]
    assert after_picker.team_sources == {"by-hand": "manual", "gl-new": "gitlab"}
    assert await db.projects.count_documents({"team_ids": "legacy"}) == 0


_RACE_PROJECT = {
    "_id": "p-race",
    "name": "two-admins",
    "team_ids": ["t-a", "t-b"],
    "team_sources": {"t-a": "manual", "t-b": "manual"},
    "team_id": "t-a",
    "team_source": "manual",
}


async def _assert_two_concurrent_removals_cannot_both_take_the_last_admin(db) -> None:
    """Both callers read the project before either writes, so a check made in Python passes twice
    and the project is left with no owner and nobody able to add one back."""
    await db.projects.insert_one(dict(_RACE_PROJECT))
    for team_id in ("t-a", "t-b"):
        await db.teams.insert_one({"_id": team_id, "name": team_id, "members": [{"user_id": "u", "role": "admin"}]})

    project = Project(**await db.projects.find_one({"_id": "p-race"}))
    actor = User(id="u", username="u", email="u@test.com", permissions=[])

    with patch(
        "app.api.v1.endpoints.projects._load_project_for_update", AsyncMock(return_value=project)
    ):
        outcomes = await asyncio.gather(
            remove_project_team("p-race", "t-a", actor, db),
            remove_project_team("p-race", "t-b", actor, db),
            return_exceptions=True,
        )

    refused = [o for o in outcomes if isinstance(o, HTTPException)]
    assert len(refused) == 1
    assert refused[0].status_code == 400
    assert len((await db.projects.find_one({"_id": "p-race"}))["team_ids"]) == 1


_MIXED_PROJECT = {
    "_id": "p-mirror",
    "name": "mixed",
    "team_ids": ["gl-a", "gh-a", "by-hand", "legacy"],
    "team_sources": {"gl-a": "gitlab", "gh-a": "github", "by-hand": "manual"},
}


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["gitlab", "github", "manual"])
async def test_the_python_mirror_names_the_owners_the_pipeline_retires(source):
    """The cap and the picker size the outcome in Python before the server computes it, so the two
    spellings have to select the same entries or one of them is deciding about a different set."""
    db = FakeDatabase()
    await db.projects.insert_one(dict(_MIXED_PROJECT))
    project = Project(**_MIXED_PROJECT)

    await ProjectRepository(db).update_raw("p-mirror", replace_team_subset_pipeline(source, []))

    stored = await db.projects.find_one({"_id": "p-mirror"})
    assert set(_MIXED_PROJECT["team_ids"]) - set(stored["team_ids"]) == owners_replaced_by(project, source)


@pytest.mark.asyncio
async def test_a_legacy_owner_outlives_a_sync_but_not_the_hand_assignment():
    await _assert_a_legacy_owner_outlives_a_sync_but_not_the_hand_assignment(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_legacy_owner_outlives_a_sync_but_not_the_hand_assignment_on_real_mongo(db):
    await _assert_a_legacy_owner_outlives_a_sync_but_not_the_hand_assignment(db)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_two_concurrent_removals_cannot_both_take_the_last_admin_on_real_mongo(db):
    await _assert_two_concurrent_removals_cannot_both_take_the_last_admin(db)


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
