"""A GitHub-bound team is looked up by (instance, team id) or (instance, organisation), never by id alone."""

import pytest

from app.models.team import Team
from app.repositories.teams import TeamRepository
from tests.mocks.fake_mongo import FakeDatabase


async def _seed(db) -> TeamRepository:
    repo = TeamRepository(db)
    await repo.create(
        Team(
            id="t-a",
            name="Payments",
            github_instance_id="gh-1",
            github_org="acme",
            github_team_id=4711,
            github_team_slug="payments",
        )
    )
    await repo.create(
        Team(
            id="t-b",
            name="Billing",
            github_instance_id="gh-2",
            github_org="acme",
            github_team_id=4711,
            github_team_slug="billing",
        )
    )
    await repo.create(
        Team(
            id="t-c",
            name="Widgets",
            github_instance_id="gh-1",
            github_org="acme-labs",
            github_team_id=8150,
            github_team_slug="widgets",
        )
    )
    await repo.create(Team(id="t-manual", name="Atlas"))
    return repo


async def _assert_scoped_to_the_instance(db) -> None:
    repo = await _seed(db)

    assert (await repo.get_raw_by_github_team("gh-1", 4711))["_id"] == "t-a"
    assert (await repo.get_raw_by_github_team("gh-2", 4711))["_id"] == "t-b"
    assert await repo.get_raw_by_github_team("gh-3", 4711) is None
    assert await repo.get_raw_by_github_team("gh-1", 9999) is None


async def _assert_the_org_listing_is_scoped(db) -> None:
    repo = await _seed(db)

    # A team number is unique per instance only, and another organisation is another repository namespace.
    assert [team["_id"] for team in await repo.find_raw_by_github_org("gh-1", "acme")] == ["t-a"]
    assert [team["_id"] for team in await repo.find_raw_by_github_org("gh-2", "acme")] == ["t-b"]
    assert [team["_id"] for team in await repo.find_raw_by_github_org("gh-1", "acme-labs")] == ["t-c"]
    assert await repo.find_raw_by_github_org("gh-3", "acme") == []


async def _assert_the_stored_case_does_not_decide(db) -> None:
    repo = await _seed(db)
    await repo.create(
        Team(
            id="t-caps",
            name="Ops",
            github_instance_id="gh-1",
            github_org="ACME",
            github_team_id=99,
            github_team_slug="ops",
        )
    )

    # GitHub answers with whichever spelling the caller used; the OIDC claim is lower-case.
    assert {team["_id"] for team in await repo.find_raw_by_github_org("gh-1", "acme")} == {"t-a", "t-caps"}
    assert {team["_id"] for team in await repo.find_raw_by_github_org("gh-1", "AcMe")} == {"t-a", "t-caps"}


async def _assert_the_organisation_is_matched_whole(db) -> None:
    repo = await _seed(db)

    assert await repo.find_raw_by_github_org("gh-1", "acm") == []
    # The dot stands for itself: an unescaped one would match the hyphen of acme-labs.
    assert await repo.find_raw_by_github_org("gh-1", "acme.labs") == []


async def _assert_a_binding_without_a_team_number_is_left_out(db) -> None:
    repo = await _seed(db)
    await repo.create(Team(id="t-half", name="Halfway", github_instance_id="gh-1", github_org="acme"))

    # Such a team addresses no team on GitHub, and returning it leaves the whole organisation
    # undetermined instead of resolving against the teams that are bound properly.
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
async def test_a_binding_without_a_team_number_is_not_returned():
    await _assert_a_binding_without_a_team_number_is_left_out(FakeDatabase())


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
async def test_a_binding_without_a_team_number_is_not_returned_on_real_mongo(db):
    await _assert_a_binding_without_a_team_number_is_left_out(db)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_bound_teams_of_an_organisation_exclude_every_other_binding_on_real_mongo(db):
    await _assert_the_org_listing_is_scoped(db)
