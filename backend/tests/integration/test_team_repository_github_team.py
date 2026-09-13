"""A bound team is looked up by (provider, instance, id) or (instance, organisation), never by id alone."""

import pytest

from app.core.constants import TEAM_SOURCE_GITHUB
from app.models.team import GitHubTeamBinding, GitLabGroupBinding, Team
from app.repositories.teams import TeamRepository
from tests.mocks.fake_mongo import FakeDatabase


def _github(instance_id, external_id, org, slug) -> GitHubTeamBinding:
    return GitHubTeamBinding(instance_id=instance_id, external_id=external_id, org=org, slug=slug)


async def _seed(db) -> TeamRepository:
    repo = TeamRepository(db)
    await repo.create(Team(id="t-a", name="Payments", bindings=[_github("gh-1", 4711, "acme", "payments")]))
    await repo.create(Team(id="t-b", name="Billing", bindings=[_github("gh-2", 4711, "acme", "billing")]))
    await repo.create(Team(id="t-c", name="Widgets", bindings=[_github("gh-1", 8150, "acme-labs", "widgets")]))
    await repo.create(Team(id="t-manual", name="Atlas"))
    return repo


async def _assert_scoped_to_the_instance(db) -> None:
    repo = await _seed(db)

    assert (await repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, "gh-1", 4711))["_id"] == "t-a"
    assert (await repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, "gh-2", 4711))["_id"] == "t-b"
    assert await repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, "gh-3", 4711) is None
    assert await repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, "gh-1", 9999) is None


async def _assert_the_org_listing_is_scoped(db) -> None:
    repo = await _seed(db)

    # A team number is unique per instance only, and another organisation is another repository namespace.
    assert [team["_id"] for team in await repo.find_raw_by_github_org("gh-1", "acme")] == ["t-a"]
    assert [team["_id"] for team in await repo.find_raw_by_github_org("gh-2", "acme")] == ["t-b"]
    assert [team["_id"] for team in await repo.find_raw_by_github_org("gh-1", "acme-labs")] == ["t-c"]
    assert await repo.find_raw_by_github_org("gh-3", "acme") == []


async def _assert_the_stored_case_does_not_decide(db) -> None:
    repo = await _seed(db)
    await repo.create(Team(id="t-caps", name="Ops", bindings=[_github("gh-1", 99, "ACME", "ops")]))

    # GitHub answers with whichever spelling the caller used; the OIDC claim is lower-case.
    assert {team["_id"] for team in await repo.find_raw_by_github_org("gh-1", "acme")} == {"t-a", "t-caps"}
    assert {team["_id"] for team in await repo.find_raw_by_github_org("gh-1", "AcMe")} == {"t-a", "t-caps"}


async def _assert_the_organisation_is_matched_whole(db) -> None:
    repo = await _seed(db)

    assert await repo.find_raw_by_github_org("gh-1", "acm") == []
    # The dot stands for itself: an unescaped one would match the hyphen of acme-labs.
    assert await repo.find_raw_by_github_org("gh-1", "acme.labs") == []


async def _assert_a_gitlab_binding_of_the_same_instance_id_is_left_out(db) -> None:
    repo = await _seed(db)
    await repo.create(Team(id="t-gl", name="Edge", bindings=[GitLabGroupBinding(instance_id="gh-1", external_id=1)]))

    # Instance ids are unique across providers, but a filter that dropped the provider would read
    # a GitLab group as a GitHub team and ask the organisation about a number it never issued.
    assert [team["_id"] for team in await repo.find_raw_by_github_org("gh-1", "acme")] == ["t-a"]


@pytest.mark.asyncio
async def test_lookup_is_scoped_to_the_instance():
    await _assert_scoped_to_the_instance(FakeDatabase())


@pytest.mark.asyncio
async def test_the_bound_teams_of_an_organisation_exclude_every_other_binding():
    await _assert_the_org_listing_is_scoped(FakeDatabase())


@pytest.mark.asyncio
async def test_an_organisation_bound_in_another_case_is_still_found():
    await _assert_the_stored_case_does_not_decide(FakeDatabase())


@pytest.mark.asyncio
async def test_the_organisation_name_is_matched_whole_and_literally():
    await _assert_the_organisation_is_matched_whole(FakeDatabase())


@pytest.mark.asyncio
async def test_a_gitlab_binding_is_not_read_as_a_github_one():
    await _assert_a_gitlab_binding_of_the_same_instance_id_is_left_out(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_lookup_is_scoped_to_the_instance_on_real_mongo(db):
    await _assert_scoped_to_the_instance(db)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_an_organisation_bound_in_another_case_is_still_found_on_real_mongo(db):
    await _assert_the_stored_case_does_not_decide(db)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_organisation_name_is_matched_whole_and_literally_on_real_mongo(db):
    await _assert_the_organisation_is_matched_whole(db)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_gitlab_binding_is_not_read_as_a_github_one_on_real_mongo(db):
    await _assert_a_gitlab_binding_of_the_same_instance_id_is_left_out(db)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_bound_teams_of_an_organisation_exclude_every_other_binding_on_real_mongo(db):
    await _assert_the_org_listing_is_scoped(db)
