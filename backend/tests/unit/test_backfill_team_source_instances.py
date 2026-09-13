"""The migration that gives every provenance value its instance, and the gate that releases it.

The gate has to be exactly as strict as the migration itself, so the two are checked against one
corpus rather than each other's description. It also has to survive the runbook: an operator who
pastes the mongosh spelling must run the filter the script runs.
"""

import json
import pathlib

import pytest

from app.core.constants import TEAM_SOURCE_GITHUB, TEAM_SOURCE_GITLAB, team_source
from scripts.backfill_team_source_instances import (
    EXIT_BARE_SOURCES_FOUND,
    InstanceNotResolvable,
    bare_source_filter,
    count_bare_sources,
    plan_instance_stamping,
    resolve_instances,
    resolve_sync_instance,
    run_stamp,
    run_verify,
)
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.mongo_array_cases import BARE_SOURCE_DOCS

_RUNBOOK = pathlib.Path(__file__).parents[2] / "scripts" / "README-deploy-team-source-instances.md"
_COUNT_CALL = "db.projects.countDocuments("
_GATE_SECTION = "### 4b."

_GITLAB_INSTANCE = "gl-inst-a"
_GITHUB_INSTANCE = "gh-inst-a"
_INSTANCES = {TEAM_SOURCE_GITLAB: _GITLAB_INSTANCE, TEAM_SOURCE_GITHUB: _GITHUB_INSTANCE}
_GITLAB_A = team_source(TEAM_SOURCE_GITLAB, _GITLAB_INSTANCE)
_GITHUB_A = team_source(TEAM_SOURCE_GITHUB, _GITHUB_INSTANCE)


async def _seeded(*docs) -> FakeDatabase:
    db = FakeDatabase()
    for doc in docs:
        await db.projects.insert_one(doc)
    return db


async def _with_instances(db: FakeDatabase, *, gitlab: int = 1, github: int = 1) -> FakeDatabase:
    for index in range(gitlab):
        await db.gitlab_instances.insert_one({"_id": f"gl-inst-{chr(ord('a') + index)}", "sync_teams": True})
    for index in range(github):
        await db.github_instances.insert_one({"_id": f"gh-inst-{chr(ord('a') + index)}", "sync_teams": True})
    return db


def test_a_bare_value_gains_the_instance_that_established_it():
    docs = [{"_id": "p", "team_sources": {"t1": "gitlab"}, "team_source": "gitlab"}]

    (update,) = plan_instance_stamping(docs, _INSTANCES)

    assert update.fields == {"team_sources": {"t1": _GITLAB_A}, "team_source": _GITLAB_A}


def test_manual_is_never_rewritten():
    docs = [{"_id": "p", "team_sources": {"t1": "manual", "t2": "gitlab"}, "team_source": "manual"}]

    (update,) = plan_instance_stamping(docs, _INSTANCES)

    assert update.fields == {"team_sources": {"t1": "manual", "t2": _GITLAB_A}}


def test_a_value_already_naming_an_instance_is_left_exactly_as_stored():
    """Re-attributing one would move an owner between instances, which no evidence supports."""
    other = team_source(TEAM_SOURCE_GITLAB, "gl-inst-z")
    docs = [{"_id": "p", "team_sources": {"t1": other}, "team_source": other}]

    assert plan_instance_stamping(docs, _INSTANCES) == []


def test_a_project_with_no_provenance_at_all_is_left_alone():
    assert plan_instance_stamping([{"_id": "p", "team_ids": ["legacy"], "team_sources": {}}], _INSTANCES) == []


def test_the_scalar_is_stamped_even_when_the_map_is_already_migrated():
    """The scalar mirrors one of the map's entries; left bare it contradicts the map it mirrors."""
    docs = [{"_id": "p", "team_sources": {"t1": _GITLAB_A}, "team_source": "gitlab"}]

    (update,) = plan_instance_stamping(docs, _INSTANCES)

    assert update.fields == {"team_source": _GITLAB_A}


def test_each_provider_gets_its_own_instance():
    docs = [{"_id": "p", "team_sources": {"t1": "gitlab", "t2": "github"}}]

    (update,) = plan_instance_stamping(docs, _INSTANCES)

    assert update.fields == {"team_sources": {"t1": _GITLAB_A, "t2": _GITHUB_A}}


@pytest.mark.asyncio
async def test_the_gate_agrees_with_the_migration_over_the_whole_corpus():
    """A count of 0 has to mean a re-run of the migration would plan nothing, or it proves nothing."""
    docs = [{"_id": f"p{index}", **doc} for index, doc in enumerate(BARE_SOURCE_DOCS)]
    db = await _seeded(*docs)

    selected = sorted(doc["_id"] for doc in await db.projects.find(bare_source_filter(), {"_id": 1}).to_list(None))

    assert selected == sorted(update.project_id for update in plan_instance_stamping(docs, _INSTANCES))
    assert selected, "the corpus must contain unmigrated documents, or the comparison is vacuous"


@pytest.mark.asyncio
async def test_verify_reports_success_only_on_a_migrated_database():
    migrated = {"_id": "ok", "team_ids": ["t1"], "team_sources": {"t1": _GITLAB_A}, "team_source": _GITLAB_A}
    bare = {"_id": "bare", "team_ids": ["t1"], "team_sources": {"t1": "gitlab"}, "team_source": "gitlab"}

    assert await run_verify(await _seeded(migrated)) == 0
    assert await run_verify(await _seeded(migrated, bare)) == EXIT_BARE_SOURCES_FOUND


@pytest.mark.asyncio
async def test_verify_answers_to_a_bare_scalar_on_its_own():
    """The map is what the sync reads, but a bare scalar is a value an older writer would mirror
    back into the map on the next ownership write."""
    db = await _seeded({"_id": "p", "team_ids": ["t1"], "team_sources": {"t1": _GITLAB_A}, "team_source": "gitlab"})

    assert await run_verify(db) == EXIT_BARE_SOURCES_FOUND


@pytest.mark.asyncio
async def test_the_instance_comes_from_the_one_that_syncs_teams():
    db = await _seeded({"_id": "p", "team_sources": {"t1": "gitlab"}})
    await db.gitlab_instances.insert_one({"_id": "gl-off", "sync_teams": False})
    await db.gitlab_instances.insert_one({"_id": "gl-on", "sync_teams": True})

    assert await resolve_sync_instance(db, TEAM_SOURCE_GITLAB) == "gl-on"


@pytest.mark.asyncio
async def test_two_syncing_instances_of_one_provider_abort_the_run():
    """Either instance could have written the bare value, and the wrong one hands that owner to
    its next ingest to delete."""
    db = await _with_instances(await _seeded({"_id": "p", "team_sources": {"t1": "gitlab"}}), gitlab=2)

    with pytest.raises(InstanceNotResolvable):
        await resolve_instances(db)


@pytest.mark.asyncio
async def test_a_provider_with_no_bare_values_needs_no_instance():
    """A single-provider installation must not be blocked by the other provider having none."""
    db = await _seeded({"_id": "p", "team_sources": {"t1": "gitlab"}})
    await db.gitlab_instances.insert_one({"_id": _GITLAB_INSTANCE, "sync_teams": True})

    assert await resolve_instances(db) == {TEAM_SOURCE_GITLAB: _GITLAB_INSTANCE}


@pytest.mark.asyncio
async def test_execute_migrates_every_selected_project_and_is_idempotent():
    db = await _with_instances(
        await _seeded(*[{"_id": f"p{index}", **doc} for index, doc in enumerate(BARE_SOURCE_DOCS)])
    )

    planned, matched = await run_stamp(db, batch_size=2, sleep_ms=0, execute=True)

    assert (planned, matched) == (4, 4)
    assert await count_bare_sources(db) == 0
    assert await run_stamp(db, batch_size=2, sleep_ms=0, execute=False) == (0, 0)


def _published_filters() -> list[dict]:
    """Every ``countDocuments`` argument the runbook's gate section publishes, in order."""
    body = _RUNBOOK.read_text()
    cursor = body.index(_GATE_SECTION)
    # Bounded to the gate's own section: later sections publish counts of their own, and reading
    # those as gate filters would compare the gate against a query it never runs.
    body = body[: body.index("\n## ", cursor)]
    filters = []
    while (call := body.find(_COUNT_CALL, cursor)) != -1:
        start = call + len(_COUNT_CALL)
        end = body.index("\n})", start) + 2  # keep the closing brace, drop the call's own paren
        filters.append(json.loads(body[start:end]))
        cursor = end
    return filters


def test_the_runbook_publishes_the_filter_the_script_runs():
    """An operator pastes the mongosh spelling; if it drifts from the script it checks nothing."""
    assert _published_filters() == [bare_source_filter()]
