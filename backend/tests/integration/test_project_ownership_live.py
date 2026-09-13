"""The ownership write the whole phase rests on, through the repository, against a real server.

The shared operator table pins the pipeline's semantics; this pins the path around it — that
``update_raw`` hands a list to the server as a pipeline rather than a ``$set`` of a field named
``$set``, and that what comes back loads into the model with every owner intact.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.api.deps import _gitlab_team_sync_stages
from app.api.v1.endpoints.projects import update_project
from app.core.constants import TEAM_SOURCE_GITHUB, TEAM_SOURCE_GITLAB, team_source
from app.models.project import Project
from app.models.user import User
from app.repositories.projects import (
    ProjectRepository,
    owners_replaced_by,
    remove_team_pipeline,
    replace_team_subset_pipeline,
    set_owners_pipeline,
)
from app.schemas.project import ProjectUpdate
from app.services.gitlab import GitLabTeamSyncResult
from tests.mocks.fake_mongo import FakeDatabase

_GITLAB_A = team_source(TEAM_SOURCE_GITLAB, "gl-inst-a")
_GITLAB_B = team_source(TEAM_SOURCE_GITLAB, "gl-inst-b")
_GITHUB_A = team_source(TEAM_SOURCE_GITHUB, "gh-inst-a")

_PROJECT = {
    "_id": "p-live",
    "name": "demo",
    "team_ids": ["gl-stale", "kept-by-hand"],
    "team_sources": {"gl-stale": _GITLAB_A, "kept-by-hand": "manual"},
    "team_id": "gl-stale",
    "team_source": _GITLAB_A,
}


async def _assert_a_sync_keeps_the_manual_co_owner(db) -> None:
    repo = ProjectRepository(db)
    await db.projects.insert_one(dict(_PROJECT))

    await repo.update_raw("p-live", replace_team_subset_pipeline(_GITLAB_A, ["gl-fresh"]))

    project = Project(**await db.projects.find_one({"_id": "p-live"}))
    assert sorted(project.team_ids) == ["gl-fresh", "kept-by-hand"]
    assert project.team_sources == {"kept-by-hand": "manual", "gl-fresh": _GITLAB_A}
    # The scalar named the owner that was just retired, so it follows the list rather than a team
    # that no longer owns anything.
    assert project.team_id == "gl-fresh"
    assert project.team_source == _GITLAB_A
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

    await repo.update_raw("p-bare", replace_team_subset_pipeline(_GITHUB_A, []))

    stored = await db.projects.find_one({"_id": "p-bare"})
    assert stored["team_ids"] == []
    assert stored["team_sources"] == {}
    assert stored["team_id"] is None
    assert await db.projects.count_documents({"team_ids": {"$size": 0}}) == 1


_UNMIGRATED_PROJECT = {
    "_id": "p-unmigrated",
    "name": "predates-the-instance-ids",
    "gitlab_instance_id": "gl-inst-a",
    "gitlab_project_id": 100,
    "team_ids": ["gl-still-held", "gl-group-left", "by-hand"],
    "team_sources": {"gl-still-held": "gitlab", "gl-group-left": "gitlab", "by-hand": "manual"},
    "team_id": "gl-still-held",
    "team_source": "gitlab",
}


async def _assert_an_ingest_repairs_the_unmigrated_owners_it_still_resolves(db) -> None:
    """What the new image does to a document the migration has not reached, which is what decides
    the deploy order: the image ships first, so it meets bare values for as long as that takes.

    A bare value matches no instance, so the sync treats those owners as somebody else's and adds
    beside them — access is kept, never dropped. The owner it resolves again comes back carrying
    the instance, because ``$setUnion`` dedupes the id and ``$mergeObjects`` overwrites its entry.
    The owner it no longer resolves keeps its bare value, and that is the migration's remaining
    work: nothing repairs a project whose sync no longer names the team.
    """
    await db.projects.insert_one(dict(_UNMIGRATED_PROJECT))
    project = Project(**_UNMIGRATED_PROJECT)
    service = MagicMock()
    service.get_project_details = AsyncMock(return_value=MagicMock())
    service.sync_team_from_gitlab = AsyncMock(return_value=GitLabTeamSyncResult(["gl-still-held"]))

    stages = await _gitlab_team_sync_stages(project, "gl-inst-a", 100, "grp/proj", service, db)
    assert stages, "a bare value names no instance, so the unchanged-subset short circuit must not fire"
    await ProjectRepository(db).update_raw("p-unmigrated", stages)

    stored = Project(**await db.projects.find_one({"_id": "p-unmigrated"}))
    assert sorted(stored.team_ids) == ["by-hand", "gl-group-left", "gl-still-held"]
    assert stored.team_sources == {
        "gl-still-held": _GITLAB_A,
        "gl-group-left": "gitlab",
        "by-hand": "manual",
    }


_TWO_INSTANCE_PROJECT = {
    "_id": "p-two-gitlabs",
    "name": "owned-from-two-instances",
    "team_ids": ["gl-a-team", "gl-b-team", "kept-by-hand"],
    "team_sources": {"gl-a-team": _GITLAB_A, "gl-b-team": _GITLAB_B, "kept-by-hand": "manual"},
    "team_id": "gl-a-team",
    "team_source": _GITLAB_A,
}


async def _assert_two_gitlab_instances_do_not_retire_each_other_s_owner(db) -> None:
    """The production shape: two GitLab instances, each holding a different team on one project.

    Under a provider-wide source each ingest reads the other's owner as its own, so B's run deletes
    A's team, A's next run deletes B's, and the project's owners alternate on every CI run. Both
    directions are exercised, because a one-sided check passes on exactly that alternation.
    """
    repo = ProjectRepository(db)
    await db.projects.insert_one(dict(_TWO_INSTANCE_PROJECT))

    await repo.update_raw("p-two-gitlabs", replace_team_subset_pipeline(_GITLAB_B, ["gl-b-moved"]))

    after_b = Project(**await db.projects.find_one({"_id": "p-two-gitlabs"}))
    assert sorted(after_b.team_ids) == ["gl-a-team", "gl-b-moved", "kept-by-hand"]
    assert after_b.team_sources == {
        "gl-a-team": _GITLAB_A,
        "gl-b-moved": _GITLAB_B,
        "kept-by-hand": "manual",
    }

    await repo.update_raw("p-two-gitlabs", replace_team_subset_pipeline(_GITLAB_A, ["gl-a-moved"]))

    after_a = Project(**await db.projects.find_one({"_id": "p-two-gitlabs"}))
    assert sorted(after_a.team_ids) == ["gl-a-moved", "gl-b-moved", "kept-by-hand"]
    assert after_a.team_sources == {
        "gl-a-moved": _GITLAB_A,
        "gl-b-moved": _GITLAB_B,
        "kept-by-hand": "manual",
    }


_LEGACY_PROJECT = {
    "_id": "p-legacy",
    "name": "predates-provenance",
    "team_ids": ["legacy"],
    "team_sources": {},
    "team_id": "legacy",
}


async def _assert_a_legacy_owner_outlives_a_sync_but_not_the_picker(db) -> None:
    """An owner no provenance entry names belongs to no provider, so a sync must add beside it.

    Nothing else can retire it either, which is why the picker — the one writer that states the
    whole owner set — has to be able to leave it out.
    """
    repo = ProjectRepository(db)
    await db.projects.insert_one(dict(_LEGACY_PROJECT))

    await repo.update_raw("p-legacy", replace_team_subset_pipeline(_GITLAB_A, ["gl-new"]))

    after_sync = Project(**await db.projects.find_one({"_id": "p-legacy"}))
    assert sorted(after_sync.team_ids) == ["gl-new", "legacy"]
    assert after_sync.team_sources == {"gl-new": _GITLAB_A}

    await repo.update_raw("p-legacy", set_owners_pipeline(["by-hand", "gl-new"]))

    after_picker = Project(**await db.projects.find_one({"_id": "p-legacy"}))
    assert sorted(after_picker.team_ids) == ["by-hand", "gl-new"]
    assert after_picker.team_sources == {"by-hand": "manual", "gl-new": _GITLAB_A}
    assert await db.projects.count_documents({"team_ids": "legacy"}) == 0


_RACE_PROJECT = {
    "_id": "p-race",
    "name": "two-admins",
    "team_ids": ["t-a", "t-b"],
    "team_sources": {"t-a": "manual", "t-b": "manual"},
    "team_id": "t-a",
    "team_source": "manual",
}


async def _assert_two_concurrent_saves_cannot_both_take_the_last_admin(db) -> None:
    """Both callers read the project before either writes, so a check made in Python passes twice
    and the project is left with no owner and nobody able to add one back."""
    await db.projects.insert_one(dict(_RACE_PROJECT))
    for team_id in ("t-a", "t-b"):
        await db.teams.insert_one({"_id": team_id, "name": team_id, "members": [{"user_id": "u", "role": "admin"}]})

    project = Project(**await db.projects.find_one({"_id": "p-race"}))
    actor = User(id="u", username="u", email="u@test.com", permissions=[])
    settings = MagicMock(retention_mode=None, rescan_mode=None)

    with (
        patch("app.api.v1.endpoints.projects._load_project_for_update", AsyncMock(return_value=project)),
        patch("app.api.v1.endpoints.projects.deps.get_system_settings", AsyncMock(return_value=settings)),
        patch("app.api.v1.endpoints.projects._audit_license_policy_change", AsyncMock()),
    ):
        outcomes = await asyncio.gather(
            update_project("p-race", ProjectUpdate(team_ids=["t-b"]), actor, db),
            update_project("p-race", ProjectUpdate(team_ids=["t-a"]), actor, db),
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
    "team_sources": {"gl-a": _GITLAB_A, "gh-a": _GITHUB_A, "by-hand": "manual"},
}


@pytest.mark.asyncio
@pytest.mark.parametrize("source", [_GITLAB_A, _GITHUB_A])
async def test_the_python_mirror_names_the_owners_the_pipeline_retires(source):
    """Ingest sizes the outcome in Python before the server computes it, so the two spellings have
    to select the same entries or one of them is deciding about a different set."""
    db = FakeDatabase()
    await db.projects.insert_one(dict(_MIXED_PROJECT))
    project = Project(**_MIXED_PROJECT)

    await ProjectRepository(db).update_raw("p-mirror", replace_team_subset_pipeline(source, []))

    stored = await db.projects.find_one({"_id": "p-mirror"})
    assert set(_MIXED_PROJECT["team_ids"]) - set(stored["team_ids"]) == owners_replaced_by(project, source)


@pytest.mark.asyncio
async def test_an_ingest_repairs_the_unmigrated_owners_it_still_resolves():
    await _assert_an_ingest_repairs_the_unmigrated_owners_it_still_resolves(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_an_ingest_repairs_the_unmigrated_owners_it_still_resolves_on_real_mongo(db):
    await _assert_an_ingest_repairs_the_unmigrated_owners_it_still_resolves(db)


@pytest.mark.asyncio
async def test_two_gitlab_instances_do_not_retire_each_other_s_owner():
    await _assert_two_gitlab_instances_do_not_retire_each_other_s_owner(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_two_gitlab_instances_do_not_retire_each_other_s_owner_on_real_mongo(db):
    await _assert_two_gitlab_instances_do_not_retire_each_other_s_owner(db)


@pytest.mark.asyncio
async def test_a_legacy_owner_outlives_a_sync_but_not_the_picker():
    await _assert_a_legacy_owner_outlives_a_sync_but_not_the_picker(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_legacy_owner_outlives_a_sync_but_not_the_picker_on_real_mongo(db):
    await _assert_a_legacy_owner_outlives_a_sync_but_not_the_picker(db)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_two_concurrent_saves_cannot_both_take_the_last_admin_on_real_mongo(db):
    await _assert_two_concurrent_saves_cannot_both_take_the_last_admin(db)


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
