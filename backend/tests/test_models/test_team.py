"""Tests for Team and TeamMember models."""

from app.models.team import Team, TeamMember
from app.core.constants import TEAM_ROLE_MEMBER


class TestTeamMember:
    def test_minimal(self):
        member = TeamMember(user_id="user-1")
        assert member.user_id == "user-1"
        assert member.role == TEAM_ROLE_MEMBER

    def test_custom_role(self):
        member = TeamMember(user_id="user-1", role="admin")
        assert member.role == "admin"


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
