"""One GitHub sync, end to end, through the real repositories."""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import TEAM_SOURCE_GITHUB, team_source
from app.models.team import GitHubTeamBinding, GitLabGroupBinding, Team, TeamMember
from app.repositories.teams import TeamRepository
from app.services.github import GitHubService, GitHubTeamSyncResult
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.github import make_github_instance

_ORG_TEAMS = [
    {"id": 4711, "slug": "payments", "name": "Payments", "parent": None},
    {"id": 9000, "slug": "platform", "name": "Platform", "parent": None},
]

# The member subset the syncing instance owns, and one another instance owns.
_OWN = team_source(TEAM_SOURCE_GITHUB, "gh-1")
_THEIRS = team_source(TEAM_SOURCE_GITHUB, "gh-2")

def _service(*, sync_teams=False):
    return GitHubService(make_github_instance(id="gh-1", access_token="ghp-secret", sync_teams=sync_teams))


def _stubbed_reads(service, holders=("payments",), repo_map=None, org_teams=None):
    async def _check(_org, team_slug, _owner, _repo):
        return team_slug in holders

    return (
        patch.object(service, "get_org_teams", new=AsyncMock(return_value=org_teams or _ORG_TEAMS)),
        patch.object(service, "get_team_repository", new=AsyncMock(side_effect=_check)),
        patch.object(service, "get_team_members", new=AsyncMock(return_value=[{"login": "ada", "role": "maintainer"}])),
        patch.object(service, "get_org_repository_map", new=AsyncMock(return_value=repo_map or {})),
    )


def _github(instance_id="gh-1", external_id=4711, org="acme", slug="payments") -> GitHubTeamBinding:
    return GitHubTeamBinding(instance_id=instance_id, org=org, external_id=external_id, slug=slug)


def _bound_team(binding: GitHubTeamBinding | None = None, **overrides) -> Team:
    fields: dict = {"id": "t-1", "name": "Payments Guild", "bindings": [binding or _github()], "members": []}
    fields.update(overrides)
    return Team(**fields)


async def _binding_holder(repo: TeamRepository, instance_id: str, external_id: int) -> dict:
    return await repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, instance_id, external_id)


def _binding_keys(team: dict) -> list[str]:
    return sorted(binding["key"] for binding in team["bindings"])


async def _assert_the_maintainer_lands_in_the_bound_team(db) -> None:
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    await repo.create(_bound_team(_github(slug="pay-old")))
    service = _service()
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(service)

    with org_reads, check_reads, member_reads, map_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult(["t-1"])
    team = await _binding_holder(repo, "gh-1", 4711)
    assert team["name"] == "Payments Guild"
    assert team["bindings"][0]["slug"] == "payments"
    assert team["members"] == [{"user_id": "u-1", "role": "admin", "source": _OWN}]


_HELD_BY_PLATFORM = {"acme/widgets": [9000]}


async def _assert_an_unbound_github_group_becomes_a_team(db) -> None:
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    service = _service(sync_teams=True)
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(service, holders=(), repo_map=_HELD_BY_PLATFORM)

    with org_reads, check_reads, member_reads, map_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert await repo.count({}) == 1
    team = await _binding_holder(repo, "gh-1", 9000)
    assert result == GitHubTeamSyncResult([team["_id"]])
    assert team["name"] == "GitHub Team: acme/platform"
    assert (team["bindings"][0]["org"], team["bindings"][0]["slug"]) == ("acme", "platform")
    assert team["members"] == [{"user_id": "u-1", "role": "admin", "source": _OWN}]


async def _assert_the_group_is_not_created_twice(db) -> None:
    """Once created the team is bound, so the next scan resolves it through the direct check and
    the map only confirms that nothing else has been granted access since."""
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    service = _service(sync_teams=True)
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(
        service, holders=("platform",), repo_map=_HELD_BY_PLATFORM
    )

    with org_reads, check_reads, member_reads, map_reads:
        first = await service.sync_team_from_github(db, "acme", "acme/widgets")
        second = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert await repo.count({}) == 1
    assert second == first


async def _assert_a_team_of_the_same_name_is_left_alone(db) -> None:
    """The escalation: a team named to match an unbound group collected project-admin over every
    repository that group holds, for anyone who could create or rename a team. Only the
    system:manage binding endpoint grants a team a group's projects."""
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    await repo.create(Team(id="t-llama", name="Shangri Llama", members=[TeamMember(user_id="u-squatter")]))
    service = _service(sync_teams=True)
    org_teams = [{"id": 9000, "slug": "team-shangri-llama", "name": "team-shangri-llama", "parent": None}]
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(
        service, holders=(), repo_map=_HELD_BY_PLATFORM, org_teams=org_teams
    )

    with org_reads, check_reads, member_reads, map_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    created = await _binding_holder(repo, "gh-1", 9000)
    assert created["_id"] != "t-llama"
    assert created["name"] == "GitHub Team: acme/team-shangri-llama"
    assert result == GitHubTeamSyncResult([created["_id"]])

    squatted = await repo.get_raw_by_id("t-llama")
    assert squatted["bindings"] == []
    assert squatted["members"] == [{"user_id": "u-squatter", "role": "member", "source": "manual"}]


async def _assert_a_cleared_binding_stays_cleared(db) -> None:
    """An unbound group is what the organisation walk goes looking for, so an ingest that bound the
    team back left its members without access in between and handed the group to them again."""
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    await repo.create(Team(id="t-platform", name="Platform", bindings=[_github(external_id=9000, slug="platform")]))
    service = _service(sync_teams=True)
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(
        service, holders=("platform",), repo_map=_HELD_BY_PLATFORM
    )

    with org_reads, check_reads, member_reads, map_reads:
        owned = await service.sync_team_from_github(db, "acme", "acme/widgets")
        assert owned == GitHubTeamSyncResult(["t-platform"])
        assert await repo.remove_binding_for_instance("t-platform", "gh-1")
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert (await repo.get_raw_by_id("t-platform"))["bindings"] == []
    created = await _binding_holder(repo, "gh-1", 9000)
    assert created["_id"] != "t-platform"
    assert result == GitHubTeamSyncResult([created["_id"]])


async def _sync_against_the_existing_team(db, existing: Team) -> tuple[GitHubTeamSyncResult, TeamRepository]:
    repo = TeamRepository(db)
    await repo.create(existing)
    service = _service(sync_teams=True)
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(service, holders=(), repo_map=_HELD_BY_PLATFORM)

    with org_reads, check_reads, member_reads, map_reads:
        return await service.sync_team_from_github(db, "acme", "acme/widgets"), repo


async def _assert_a_team_bound_to_another_instance_keeps_only_that_binding(db) -> None:
    """Two instances are two tenants; a team already bound on one is no answer for a group on the
    other just because the names read alike."""
    result, repo = await _sync_against_the_existing_team(
        db,
        Team(id="t-elsewhere", name="Platform", bindings=[_github(instance_id="gh-2", external_id=1234, org="other")]),
    )

    created = await _binding_holder(repo, "gh-1", 9000)
    assert created["_id"] != "t-elsewhere"
    assert result == GitHubTeamSyncResult([created["_id"]])
    assert _binding_keys(await repo.get_raw_by_id("t-elsewhere")) == ["github:gh-2:1234"]


async def _assert_a_team_this_instance_already_holds_is_not_stolen(db) -> None:
    """One sync cannot serve two groups: the second group would keep replacing the first's members."""
    result, repo = await _sync_against_the_existing_team(
        db, Team(id="t-held", name="Platform", bindings=[_github(external_id=1234, org="other")])
    )

    created = await _binding_holder(repo, "gh-1", 9000)
    assert created["name"] == "GitHub Team: acme/platform"
    assert result == GitHubTeamSyncResult([created["_id"]])

    untouched = await repo.get_raw_by_id("t-held")
    assert _binding_keys(untouched) == ["github:gh-1:1234"]


async def _assert_the_group_gets_one_team_however_many_answer_to_its_name(db) -> None:
    """Two teams read as "Platform" and neither is bound here. Both keep their own names and their
    own projects: what decides is the rule, not how many teams answer to a group's name."""
    repo = TeamRepository(db)
    await repo.create(Team(id="t-held", name="Platform", bindings=[_github(external_id=1234, org="other")]))
    await repo.create(Team(id="t-free", name="Platform"))
    service = _service(sync_teams=True)
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(service, holders=(), repo_map=_HELD_BY_PLATFORM)

    with org_reads, check_reads, member_reads, map_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    created = await _binding_holder(repo, "gh-1", 9000)
    assert result == GitHubTeamSyncResult([created["_id"]])
    assert await repo.count({}) == 3
    assert (await repo.get_raw_by_id("t-free"))["bindings"] == []
    assert _binding_keys(await repo.get_raw_by_id("t-held")) == ["github:gh-1:1234"]


async def _assert_a_team_synced_from_gitlab_gains_no_github_binding(db) -> None:
    """One team answering for a group on both providers is a deliberate binding, not something an
    ingest may arrange by reading names."""
    result, repo = await _sync_against_the_existing_team(
        db, Team(id="t-gitlab", name="Platform", bindings=[GitLabGroupBinding(instance_id="gl-1", external_id=77)])
    )

    created = await _binding_holder(repo, "gh-1", 9000)
    assert result == GitHubTeamSyncResult([created["_id"]])
    assert _binding_keys(await repo.get_raw_by_id("t-gitlab")) == ["gitlab:gl-1:77"]


async def _assert_an_unbound_github_group_gets_no_team_while_creation_is_off(db) -> None:
    """Creation follows the instance's switch, as it does on GitLab. The bound team holding nothing
    is what carries the resolution past the shortcut for an organisation with no binding at all."""
    repo = TeamRepository(db)
    await repo.create(_bound_team())
    service = _service()
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(
        service, holders=(), repo_map=_HELD_BY_PLATFORM
    )

    with org_reads, check_reads, member_reads, map_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult([])
    assert await repo.count({}) == 1


async def _assert_a_second_sync_merges_into_the_bound_team(db) -> None:
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    await repo.create(
        _bound_team(
            members=[
                TeamMember(user_id="u-manual", role="admin", source="manual"),
                TeamMember(user_id="u-departed", role="member", source=_OWN),
                TeamMember(user_id="u-theirs", role="member", source=_THEIRS),
            ]
        )
    )
    # Same team number on another instance: the sync must not read or write across the tenant line.
    await repo.create(
        Team(
            id="t-other",
            name="Billing",
            bindings=[_github(instance_id="gh-2")],
            members=[TeamMember(user_id="u-other", role="member", source=_THEIRS)],
        )
    )
    service = _service()
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(service)

    with org_reads, check_reads, member_reads, map_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult(["t-1"])
    assert await repo.count({}) == 2

    team = await _binding_holder(repo, "gh-1", 4711)
    assert team["members"] == [
        {"user_id": "u-manual", "role": "admin", "source": "manual"},
        {"user_id": "u-theirs", "role": "member", "source": _THEIRS},
        {"user_id": "u-1", "role": "admin", "source": _OWN},
    ]

    other = await _binding_holder(repo, "gh-2", 4711)
    assert other["members"] == [{"user_id": "u-other", "role": "member", "source": _THEIRS}]


async def _assert_the_organisation_case_does_not_decide(db) -> None:
    """The OIDC claim is lower-case; a binding stored in GitHub's own spelling must still match."""
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    await repo.create(_bound_team(_github(org="Acme")))
    service = _service()
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(service)

    with org_reads, check_reads, member_reads, map_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult(["t-1"])
    team = await _binding_holder(repo, "gh-1", 4711)
    assert team["members"] == [{"user_id": "u-1", "role": "admin", "source": _OWN}]


@pytest.mark.asyncio
async def test_a_repository_lands_in_the_bound_team_with_its_maintainer_as_admin():
    await _assert_the_maintainer_lands_in_the_bound_team(FakeDatabase())


@pytest.mark.asyncio
async def test_a_binding_stored_in_another_case_still_resolves():
    await _assert_the_organisation_case_does_not_decide(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_binding_stored_in_another_case_still_resolves_on_real_mongo(db):
    await _assert_the_organisation_case_does_not_decide(db)


@pytest.mark.asyncio
async def test_a_repository_whose_github_group_nobody_bound_gains_that_group_as_a_team():
    await _assert_an_unbound_github_group_becomes_a_team(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_repository_whose_github_group_nobody_bound_gains_that_group_as_a_team_on_real_mongo(db):
    await _assert_an_unbound_github_group_becomes_a_team(db)


@pytest.mark.asyncio
async def test_a_group_already_created_is_adopted_rather_than_created_again():
    await _assert_the_group_is_not_created_twice(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_group_already_created_is_adopted_rather_than_created_again_on_real_mongo(db):
    await _assert_the_group_is_not_created_twice(db)


@pytest.mark.asyncio
async def test_a_repository_whose_github_group_nobody_bound_gains_no_owner_while_creation_is_off():
    await _assert_an_unbound_github_group_gets_no_team_while_creation_is_off(FakeDatabase())


@pytest.mark.asyncio
async def test_a_team_whose_name_matches_an_unbound_group_is_never_bound_to_it():
    await _assert_a_team_of_the_same_name_is_left_alone(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_team_whose_name_matches_an_unbound_group_is_never_bound_to_it_on_real_mongo(db):
    await _assert_a_team_of_the_same_name_is_left_alone(db)


@pytest.mark.asyncio
async def test_a_cleared_binding_stays_cleared_across_the_next_ingest():
    await _assert_a_cleared_binding_stays_cleared(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_cleared_binding_stays_cleared_across_the_next_ingest_on_real_mongo(db):
    await _assert_a_cleared_binding_stays_cleared(db)


@pytest.mark.asyncio
async def test_a_team_bound_to_another_instance_keeps_only_that_binding():
    await _assert_a_team_bound_to_another_instance_keeps_only_that_binding(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_team_bound_to_another_instance_keeps_only_that_binding_on_real_mongo(db):
    await _assert_a_team_bound_to_another_instance_keeps_only_that_binding(db)


@pytest.mark.asyncio
async def test_a_team_this_instance_already_holds_is_not_stolen():
    await _assert_a_team_this_instance_already_holds_is_not_stolen(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_team_this_instance_already_holds_is_not_stolen_on_real_mongo(db):
    await _assert_a_team_this_instance_already_holds_is_not_stolen(db)


@pytest.mark.asyncio
async def test_a_team_gitlab_already_syncs_gains_no_github_binding_from_an_ingest():
    await _assert_a_team_synced_from_gitlab_gains_no_github_binding(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_team_gitlab_already_syncs_gains_no_github_binding_from_an_ingest_on_real_mongo(db):
    await _assert_a_team_synced_from_gitlab_gains_no_github_binding(db)


@pytest.mark.asyncio
async def test_a_second_sync_merges_into_the_team_it_already_wrote():
    await _assert_a_second_sync_merges_into_the_bound_team(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_repository_lands_in_the_bound_team_with_its_maintainer_as_admin_on_real_mongo(db):
    await _assert_the_maintainer_lands_in_the_bound_team(db)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_repository_whose_github_group_nobody_bound_gains_no_owner_while_creation_is_off_on_real_mongo(db):
    await _assert_an_unbound_github_group_gets_no_team_while_creation_is_off(db)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_second_sync_merges_into_the_team_it_already_wrote_on_real_mongo(db):
    await _assert_a_second_sync_merges_into_the_bound_team(db)


@pytest.mark.asyncio
async def test_the_group_gets_one_team_however_many_answer_to_its_name():
    await _assert_the_group_gets_one_team_however_many_answer_to_its_name(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_group_gets_one_team_however_many_answer_to_its_name_on_real_mongo(db):
    await _assert_the_group_gets_one_team_however_many_answer_to_its_name(db)
