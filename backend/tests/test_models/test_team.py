"""Tests for Team and TeamMember models."""

import pytest
from pydantic import ValidationError

from app.core.constants import TEAM_ROLE_MEMBER
from app.models.team import Team, TeamMember


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

    def test_source_can_be_gitlab(self):
        member = TeamMember(user_id="user-1", source="gitlab")
        assert member.source == "gitlab"


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


class TestTeamGitHubProvenance:
    def test_team_carries_the_github_identity_pair(self):
        team = Team(
            name="GitHub Team: acme/payments",
            github_instance_id="gh-inst-1",
            github_org="acme",
            github_team_id=4711,
            github_team_slug="payments",
        )
        assert team.github_instance_id == "gh-inst-1"
        assert team.github_org == "acme"
        assert team.github_team_id == 4711
        assert team.github_team_slug == "payments"

    def test_manual_team_leaves_the_github_fields_unset(self):
        team = Team(name="Atlas")
        assert team.github_team_id is None
        assert team.github_instance_id is None

    def test_member_can_be_sourced_from_github(self):
        assert TeamMember(user_id="u-1", source="github").source == "github"

    def test_member_source_rejects_an_unknown_provider(self):
        with pytest.raises(ValidationError):
            TeamMember(user_id="u-1", source="bitbucket")
