"""The binding-key index must keep a group to one team without making an unbound team unwritable.

Against a real server: the uniqueness is a multikey partial index, and the two properties that
matter — a document holding no binding is outside the unique scope, and a document's own duplicate
keys collapse — are server behaviour a fake cannot establish.
"""

import pytest
from pymongo.errors import DuplicateKeyError

from app.core.constants import TEAM_SOURCE_GITHUB, TEAM_SOURCE_GITLAB
from app.core.init_db import create_indexes, create_team_indexes
from app.models.team import GitHubTeamBinding, GitLabGroupBinding, Team
from app.repositories.teams import TeamRepository

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]


def _github(instance_id="gh-1", external_id=4711, org="acme", slug="payments") -> GitHubTeamBinding:
    return GitHubTeamBinding(instance_id=instance_id, org=org, external_id=external_id, slug=slug)


async def test_two_teams_holding_no_binding_coexist(db):
    """Every team document carries the field as an empty array, and a unique index over a path
    inside it would otherwise index both under the key null."""
    await create_indexes(db)
    repo = TeamRepository(db)

    await repo.create(Team(name="Atlas"))
    await repo.create(Team(name="Borealis"))

    assert await repo.count({}) == 2


async def test_a_second_team_cannot_take_a_binding_another_team_holds(db):
    await create_team_indexes(db)
    repo = TeamRepository(db)

    await repo.create(Team(name="GitHub Team: acme/payments", bindings=[_github()]))
    with pytest.raises(DuplicateKeyError):
        await repo.create(Team(name="Payments Guild", bindings=[_github()]))


async def test_a_binding_pushed_onto_a_second_team_is_refused_just_as_a_created_one_is(db):
    """Adoption appends to a team that already exists, so the index has to answer to $push too."""
    await create_team_indexes(db)
    repo = TeamRepository(db)
    await repo.create(Team(id="t-holder", name="Payments", bindings=[_github()]))
    await repo.create(Team(id="t-other", name="Orion"))

    with pytest.raises(DuplicateKeyError):
        await repo.add_binding_if_absent("t-other", _github().model_dump())


async def test_the_same_gitlab_group_cannot_be_bound_twice(db):
    await create_team_indexes(db)
    repo = TeamRepository(db)
    binding = GitLabGroupBinding(instance_id="gl-1", external_id=77, path="mo/edge")

    await repo.create(Team(name="GitLab Group: mo/edge", bindings=[binding]))
    with pytest.raises(DuplicateKeyError):
        await repo.create(Team(name="Edge Guild", bindings=[binding]))


async def test_an_external_id_beyond_int32_is_still_unique(db):
    """The key is a string, so a BSON long id is inside the unique scope where a $type: "int"
    filter over the numeric field would have exempted it."""
    await create_team_indexes(db)
    repo = TeamRepository(db)
    binding = _github(external_id=2**31 + 7, slug="wide")

    await repo.create(Team(name="GitHub Team: acme/wide", bindings=[binding]))
    with pytest.raises(DuplicateKeyError):
        await repo.create(Team(name="Wide Again", bindings=[binding]))


async def test_a_team_cleared_of_a_binding_leaves_the_group_free(db):
    await create_team_indexes(db)
    repo = TeamRepository(db)
    binding = GitLabGroupBinding(instance_id="gl-1", external_id=77)

    await repo.create(Team(id="t-1", name="Edge Guild", bindings=[binding]))
    assert await repo.remove_binding_for_instance("t-1", "gl-1")
    await repo.create(Team(id="t-2", name="Edge Again", bindings=[binding]))

    assert (await repo.get_raw_by_binding(TEAM_SOURCE_GITLAB, "gl-1", 77))["_id"] == "t-2"


async def test_one_team_holds_a_group_and_an_organisation_at_once(db):
    await create_team_indexes(db)
    repo = TeamRepository(db)

    await repo.create(
        Team(
            id="t-both", name="Edge Guild", bindings=[GitLabGroupBinding(instance_id="gl-1", external_id=77), _github()]
        )
    )

    assert (await repo.get_raw_by_binding(TEAM_SOURCE_GITLAB, "gl-1", 77))["_id"] == "t-both"
    assert (await repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, "gh-1", 4711))["_id"] == "t-both"


async def test_one_team_holds_the_same_group_number_on_two_instances_of_one_provider(db):
    """The key names the instance, so two tenants' group 4711 are two keys, not a duplicate."""
    await create_team_indexes(db)
    repo = TeamRepository(db)

    await repo.create(Team(id="t-two", name="Payments", bindings=[_github(), _github(instance_id="gh-2")]))

    assert (await repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, "gh-1", 4711))["_id"] == "t-two"
    assert (await repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, "gh-2", 4711))["_id"] == "t-two"


async def test_a_second_binding_on_one_instance_is_refused_by_the_write_and_not_by_the_index(db):
    """A multikey index deduplicates the keys of a single document, so it cannot see a second
    binding on the same instance; the filter on the write is the only thing that can."""
    await create_team_indexes(db)
    repo = TeamRepository(db)
    await repo.create(Team(id="t-1", name="Payments", bindings=[_github()]))

    assert await repo.add_binding_if_absent("t-1", _github(external_id=900, slug="cards").model_dump()) is None

    stored = await repo.get_raw_by_id("t-1")
    assert [binding["key"] for binding in stored["bindings"]] == ["github:gh-1:4711"]


async def test_replacing_the_binding_of_an_instance_rewrites_the_entry_in_place(db):
    await create_team_indexes(db)
    repo = TeamRepository(db)
    await repo.create(Team(id="t-1", name="Payments", bindings=[_github(), _github(instance_id="gh-2")]))

    assert await repo.replace_binding_for_instance("t-1", _github(external_id=900, slug="cards").model_dump())

    stored = await repo.get_raw_by_id("t-1")
    assert sorted(binding["key"] for binding in stored["bindings"]) == ["github:gh-1:900", "github:gh-2:4711"]


async def test_a_display_field_is_restamped_without_disturbing_the_other_bindings(db):
    await create_team_indexes(db)
    repo = TeamRepository(db)
    gitlab = GitLabGroupBinding(instance_id="gl-1", external_id=77, path="mo/old")
    await repo.create(Team(id="t-1", name="Edge", bindings=[gitlab, _github()]))

    await repo.update_with_binding("t-1", {"name": "Edge Guild"}, gitlab.key, {"path": "mo/edge"})

    stored = await repo.get_raw_by_id("t-1")
    assert stored["name"] == "Edge Guild"
    assert {binding["key"]: binding.get("path") or binding.get("slug") for binding in stored["bindings"]} == {
        "gitlab:gl-1:77": "mo/edge",
        "github:gh-1:4711": "payments",
    }
