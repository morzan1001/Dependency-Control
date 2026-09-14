"""Tests for Team and TeamMember models."""

import pytest
from pydantic import ValidationError

from app.core.constants import TEAM_ROLE_MEMBER, TEAM_SOURCE_GITHUB, TEAM_SOURCE_GITLAB, team_source
from app.models.team import (
    GitHubTeamBinding,
    GitLabGroupBinding,
    Team,
    TeamMember,
    binding_of,
)


class TestTeamMember:
    def test_minimal(self):
        member = TeamMember(user_id="user-1")
        assert member.user_id == "user-1"
        assert member.role == TEAM_ROLE_MEMBER

    def test_custom_role(self):
        member = TeamMember(user_id="user-1", role="admin")
        assert member.role == "admin"

    def test_source_defaults_to_manual(self):
        # Default "manual" so manually-added members survive the merge sync.
        member = TeamMember(user_id="user-1")
        assert member.source == "manual"

    def test_source_names_the_instance_that_added_the_member(self):
        member = TeamMember(user_id="user-1", source=team_source(TEAM_SOURCE_GITLAB, "gl-1"))
        assert member.source == "gitlab:gl-1"


class TestTeamModel:
    def test_minimal(self):
        team = Team(name="Dev Team")
        assert team.name == "Dev Team"
        assert team.description is None
        assert team.members == []

    def test_with_members(self):
        members = [
            TeamMember(user_id="user-1", role="admin"),
            TeamMember(user_id="user-2"),
        ]
        team = Team(name="Team", members=members)
        assert len(team.members) == 2
        assert team.members[0].role == "admin"
        assert team.members[1].role == TEAM_ROLE_MEMBER

    def test_id_auto_generated(self):
        a = Team(name="A")
        b = Team(name="B")
        assert a.id != b.id

    def test_timestamps_set(self):
        team = Team(name="T")
        assert team.created_at is not None
        assert team.updated_at is not None

    def test_id_alias(self):
        team = Team(name="T")
        dumped = team.model_dump(by_alias=True)
        assert "_id" in dumped


class TestTeamBindings:
    def test_a_binding_carries_the_key_the_unique_index_is_on(self):
        team = Team(
            name="GitHub Team: acme/payments",
            bindings=[GitHubTeamBinding(instance_id="gh-inst-1", org="acme", external_id=4711, slug="payments")],
        )
        assert team.model_dump()["bindings"][0]["key"] == "github:gh-inst-1:4711"

    def test_a_stored_key_never_overrides_the_one_the_binding_derives(self):
        """A key that named another binding would hand that binding's uniqueness to this team."""
        team = Team(
            name="Edge", bindings=[
                    {"provider": "gitlab", "instance_id": "gl-1", "external_id": 77, "key": "gitlab:gl-9:1"}
                ]
        )
        assert team.bindings[0].key == "gitlab:gl-1:77"

    def test_the_provider_decides_which_display_fields_a_binding_carries(self):
        team = Team(
            name="Both",
            bindings=[
                GitHubTeamBinding(instance_id="gh-1", org="acme", external_id=1),
                GitLabGroupBinding(instance_id="gl-1", external_id=2, path="mo/edge"),
            ],
        )
        assert isinstance(team.bindings[0], GitHubTeamBinding)
        assert isinstance(team.bindings[1], GitLabGroupBinding)

    def test_a_github_binding_without_an_organisation_is_refused(self):
        """It addresses no team on GitHub, and storing it leaves every repository of an
        organisation undetermined instead of resolving against the bindings that are whole."""
        with pytest.raises(ValidationError):
            Team(name="Half", bindings=[{"provider": "github", "instance_id": "gh-1", "external_id": 1}])

    def test_a_manual_team_holds_no_binding(self):
        assert Team(name="Atlas").bindings == []

    def test_binding_of_answers_for_one_instance_only(self):
        team = Team(
            name="Both",
            bindings=[
                GitHubTeamBinding(instance_id="gh-1", org="acme", external_id=1),
                GitHubTeamBinding(instance_id="gh-2", org="acme", external_id=2),
            ],
        ).model_dump()

        assert binding_of(team, "gh-2")["external_id"] == 2
        assert binding_of(team, "gh-3") is None

    def test_member_can_be_sourced_from_a_github_instance(self):
        assert TeamMember(user_id="u-1", source=team_source(TEAM_SOURCE_GITHUB, "gh-1")).source == "github:gh-1"

    def test_a_member_whose_source_names_no_instance_still_loads(self):
        """A team holding an unmigrated member is read by every request that resolves the caller's
        teams; rejecting the value here answers 500 instead of leaving the member in place."""
        assert TeamMember(user_id="u-1", source="gitlab").source == "gitlab"

