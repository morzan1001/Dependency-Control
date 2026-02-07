"""Tests for team API endpoints.

Tests CRUD operations, member management, access control, and cascade behavior.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.core.constants import TEAM_ROLE_ADMIN, TEAM_ROLE_MEMBER, TEAM_ROLE_OWNER
from app.models.team import Team, TeamMember

MODULE = "app.api.v1.endpoints.teams"


def _make_team(id="team-1", name="Test Team", members=None):
    """Create a Team with sensible defaults."""
    if members is None:
        members = [TeamMember(user_id="user-1", role=TEAM_ROLE_OWNER)]
    return Team(id=id, name=name, members=members)


class TestCreateTeam:
    def test_creator_becomes_owner(self, regular_user):
        from app.api.v1.endpoints.teams import create_team
        from app.schemas.team import TeamCreate

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
            result = asyncio.run(
                create_team(
                    team_in=TeamCreate(name="New Team", description="desc"),
                    current_user=regular_user,
                    db=MagicMock(),
                )
            )

        assert result["name"] == "New Team"
        assert result["members"][0]["role"] == TEAM_ROLE_OWNER
        assert result["members"][0]["user_id"] == str(regular_user.id)
        assert result["members"][0]["username"] == regular_user.username
        mock_repo.create.assert_called_once()

    def test_team_without_description(self, regular_user):
        from app.api.v1.endpoints.teams import create_team
        from app.schemas.team import TeamCreate

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
            result = asyncio.run(
                create_team(
                    team_in=TeamCreate(name="Minimal"),
                    current_user=regular_user,
                    db=MagicMock(),
                )
            )

        assert result["name"] == "Minimal"
        assert result["description"] is None


class TestReadTeams:
    def test_admin_sees_all_teams(self, admin_user):
        from app.api.v1.endpoints.teams import read_teams

        mock_repo = MagicMock()
        mock_repo.aggregate = AsyncMock(
            return_value=[
                {"_id": "t1", "name": "Team A", "members": [], "created_at": "2024-01-01", "updated_at": "2024-01-01"},
            ]
        )

        with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
            with patch(f"{MODULE}.build_team_enrichment_pipeline") as mock_pipeline:
                mock_pipeline.return_value = [{"$match": {}}]
                result = asyncio.run(
                    read_teams(
                        search=None,
                        sort_by="name",
                        sort_order="asc",
                        current_user=admin_user,
                        db=MagicMock(),
                    )
                )

        assert len(result) == 1
        # Admin has team:read_all, so query should not filter by membership
        pipeline_query = mock_pipeline.call_args[0][0]
        assert "members.user_id" not in pipeline_query

    def test_regular_user_sees_only_own_teams(self, regular_user):
        from app.api.v1.endpoints.teams import read_teams

        mock_repo = MagicMock()
        mock_repo.aggregate = AsyncMock(return_value=[])

        with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
            with patch(f"{MODULE}.build_team_enrichment_pipeline") as mock_pipeline:
                mock_pipeline.return_value = [{"$match": {}}]
                asyncio.run(
                    read_teams(
                        search=None,
                        sort_by="name",
                        sort_order="asc",
                        current_user=regular_user,
                        db=MagicMock(),
                    )
                )

        pipeline_query = mock_pipeline.call_args[0][0]
        assert "members.user_id" in pipeline_query

    def test_search_filter(self, admin_user):
        from app.api.v1.endpoints.teams import read_teams

        mock_repo = MagicMock()
        mock_repo.aggregate = AsyncMock(return_value=[])

        with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
            with patch(f"{MODULE}.build_team_enrichment_pipeline") as mock_pipeline:
                mock_pipeline.return_value = [{"$match": {}}]
                asyncio.run(
                    read_teams(
                        search="frontend",
                        sort_by="name",
                        sort_order="asc",
                        current_user=admin_user,
                        db=MagicMock(),
                    )
                )

        pipeline_query = mock_pipeline.call_args[0][0]
        assert "name" in pipeline_query
        assert "$regex" in pipeline_query["name"]

    def test_viewer_without_read_perm_raises_403(self, viewer_user):
        from app.api.v1.endpoints.teams import read_teams

        # Remove team:read permission from viewer
        viewer_user.permissions = []

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                read_teams(
                    search=None,
                    sort_by="name",
                    sort_order="asc",
                    current_user=viewer_user,
                    db=MagicMock(),
                )
            )
        assert exc_info.value.status_code == 403


class TestReadTeam:
    def test_returns_enriched_team(self, admin_user):
        from app.api.v1.endpoints.teams import read_team

        enriched = [
            {
                "_id": "team-1",
                "name": "My Team",
                "members": [{"user_id": "u1", "role": "owner", "username": "admin"}],
                "created_at": "2024-01-01T00:00:00",
                "updated_at": "2024-01-01T00:00:00",
            }
        ]

        mock_repo = MagicMock()
        mock_repo.aggregate = AsyncMock(return_value=enriched)

        with patch(f"{MODULE}.check_team_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
                with patch(f"{MODULE}.build_team_enrichment_pipeline", return_value=[]):
                    result = asyncio.run(
                        read_team(
                            team_id="team-1",
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )

        assert result["name"] == "My Team"

    def test_raises_404_when_not_found(self, admin_user):
        from app.api.v1.endpoints.teams import read_team

        mock_repo = MagicMock()
        mock_repo.aggregate = AsyncMock(return_value=[])

        with patch(f"{MODULE}.check_team_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
                with patch(f"{MODULE}.build_team_enrichment_pipeline", return_value=[]):
                    with pytest.raises(HTTPException) as exc_info:
                        asyncio.run(
                            read_team(
                                team_id="missing",
                                current_user=admin_user,
                                db=MagicMock(),
                            )
                        )
        assert exc_info.value.status_code == 404


class TestUpdateTeam:
    def test_success_updates_team(self, admin_user):
        from app.api.v1.endpoints.teams import update_team
        from app.schemas.team import TeamUpdate, TeamResponse

        team = _make_team()
        enriched_response = TeamResponse(
            _id="team-1",
            name="Updated",
            members=[],
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
        )

        mock_repo = MagicMock()
        mock_repo.update = AsyncMock()

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=team):
            with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
                with patch(f"{MODULE}.fetch_and_enrich_team", new_callable=AsyncMock, return_value=enriched_response):
                    result = asyncio.run(
                        update_team(
                            team_id="team-1",
                            team_in=TeamUpdate(name="Updated"),
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )

        assert result.name == "Updated"
        mock_repo.update.assert_called_once()


class TestDeleteTeam:
    def test_cascades_project_unassignment(self, admin_user):
        from app.api.v1.endpoints.teams import delete_team

        mock_team_repo = MagicMock()
        mock_team_repo.delete = AsyncMock()

        mock_proj_repo = MagicMock()
        mock_proj_repo.update_many = AsyncMock(return_value=2)

        with patch(f"{MODULE}.check_team_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.TeamRepository", return_value=mock_team_repo):
                # Patched at source: delete_team uses a function-level import
                with patch("app.repositories.ProjectRepository", return_value=mock_proj_repo):
                    asyncio.run(
                        delete_team(
                            team_id="team-1",
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )

        mock_proj_repo.update_many.assert_called_once_with({"team_id": "team-1"}, {"team_id": None})
        mock_team_repo.delete.assert_called_once_with("team-1")


class TestAddTeamMember:
    def test_success_adds_member(self, admin_user):
        from app.api.v1.endpoints.teams import add_team_member
        from app.schemas.team import TeamMemberAdd, TeamResponse

        team = _make_team(members=[TeamMember(user_id="admin-1", role=TEAM_ROLE_OWNER)])
        user_doc = {"_id": "new-user-id", "username": "newuser", "email": "new@test.com"}
        enriched = TeamResponse(
            _id="team-1",
            name="Test Team",
            members=[
                {"user_id": "admin-1", "role": "owner", "username": "admin"},
                {"user_id": "new-user-id", "role": "member", "username": "newuser"},
            ],
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
        )

        mock_team_repo = MagicMock()
        mock_team_repo.update_raw = AsyncMock()
        mock_user_repo = MagicMock()
        mock_user_repo.get_raw_by_email = AsyncMock(return_value=user_doc)

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=team):
            with patch(f"{MODULE}.TeamRepository", return_value=mock_team_repo):
                with patch(f"{MODULE}.UserRepository", return_value=mock_user_repo):
                    with patch(f"{MODULE}.fetch_and_enrich_team", new_callable=AsyncMock, return_value=enriched):
                        result = asyncio.run(
                            add_team_member(
                                team_id="team-1",
                                member_in=TeamMemberAdd(email="new@test.com"),
                                current_user=admin_user,
                                db=MagicMock(),
                            )
                        )

        assert len(result.members) == 2
        mock_team_repo.update_raw.assert_called_once()

    def test_raises_404_when_user_not_found(self, admin_user):
        from app.api.v1.endpoints.teams import add_team_member
        from app.schemas.team import TeamMemberAdd

        team = _make_team()
        mock_team_repo = MagicMock()
        mock_user_repo = MagicMock()
        mock_user_repo.get_raw_by_email = AsyncMock(return_value=None)

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=team):
            with patch(f"{MODULE}.TeamRepository", return_value=mock_team_repo):
                with patch(f"{MODULE}.UserRepository", return_value=mock_user_repo):
                    with pytest.raises(HTTPException) as exc_info:
                        asyncio.run(
                            add_team_member(
                                team_id="team-1",
                                member_in=TeamMemberAdd(email="unknown@test.com"),
                                current_user=admin_user,
                                db=MagicMock(),
                            )
                        )
        assert exc_info.value.status_code == 404

    def test_raises_400_when_already_member(self, admin_user):
        from app.api.v1.endpoints.teams import add_team_member
        from app.schemas.team import TeamMemberAdd

        team = _make_team(members=[TeamMember(user_id="existing-id", role=TEAM_ROLE_MEMBER)])
        user_doc = {"_id": "existing-id", "username": "existing", "email": "e@test.com"}

        mock_team_repo = MagicMock()
        mock_user_repo = MagicMock()
        mock_user_repo.get_raw_by_email = AsyncMock(return_value=user_doc)

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=team):
            with patch(f"{MODULE}.TeamRepository", return_value=mock_team_repo):
                with patch(f"{MODULE}.UserRepository", return_value=mock_user_repo):
                    with pytest.raises(HTTPException) as exc_info:
                        asyncio.run(
                            add_team_member(
                                team_id="team-1",
                                member_in=TeamMemberAdd(email="e@test.com"),
                                current_user=admin_user,
                                db=MagicMock(),
                            )
                        )
        assert exc_info.value.status_code == 400
        assert "already" in exc_info.value.detail.lower()


class TestUpdateTeamMember:
    def test_success_updates_role(self, admin_user):
        from app.api.v1.endpoints.teams import update_team_member
        from app.schemas.team import TeamMemberUpdate, TeamResponse

        team = _make_team(
            members=[
                TeamMember(user_id="admin-1", role=TEAM_ROLE_OWNER),
                TeamMember(user_id="target-user", role=TEAM_ROLE_MEMBER),
            ]
        )
        enriched = TeamResponse(
            _id="team-1",
            name="Test Team",
            members=[
                {"user_id": "admin-1", "role": "owner", "username": "admin"},
                {"user_id": "target-user", "role": "admin", "username": "target"},
            ],
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
        )

        mock_repo = MagicMock()
        mock_repo.update_raw = AsyncMock()

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=team):
            with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
                with patch(f"{MODULE}.fetch_and_enrich_team", new_callable=AsyncMock, return_value=enriched):
                    asyncio.run(
                        update_team_member(
                            team_id="team-1",
                            user_id="target-user",
                            member_in=TeamMemberUpdate(role=TEAM_ROLE_ADMIN),
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )

        mock_repo.update_raw.assert_called_once()

    def test_raises_404_when_user_not_in_team(self, admin_user):
        from app.api.v1.endpoints.teams import update_team_member
        from app.schemas.team import TeamMemberUpdate

        team = _make_team(members=[TeamMember(user_id="admin-1", role=TEAM_ROLE_OWNER)])

        mock_repo = MagicMock()

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=team):
            with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        update_team_member(
                            team_id="team-1",
                            user_id="nonexistent",
                            member_in=TeamMemberUpdate(role=TEAM_ROLE_ADMIN),
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )
        assert exc_info.value.status_code == 404


class TestRemoveTeamMember:
    def test_success_removes_member(self, admin_user):
        from app.api.v1.endpoints.teams import remove_team_member
        from app.schemas.team import TeamResponse

        team = _make_team(
            members=[
                TeamMember(user_id="admin-1", role=TEAM_ROLE_OWNER),
                TeamMember(user_id="to-remove", role=TEAM_ROLE_MEMBER),
            ]
        )
        enriched = TeamResponse(
            _id="team-1",
            name="Test Team",
            members=[{"user_id": "admin-1", "role": "owner", "username": "admin"}],
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
        )

        mock_repo = MagicMock()
        mock_repo.update_raw = AsyncMock()

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=team):
            with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
                with patch(f"{MODULE}.fetch_and_enrich_team", new_callable=AsyncMock, return_value=enriched):
                    asyncio.run(
                        remove_team_member(
                            team_id="team-1",
                            user_id="to-remove",
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )

        mock_repo.update_raw.assert_called_once()

    def test_raises_400_when_removing_owner(self, admin_user):
        from app.api.v1.endpoints.teams import remove_team_member

        team = _make_team(
            members=[
                TeamMember(user_id="owner-id", role=TEAM_ROLE_OWNER),
                TeamMember(user_id="admin-1", role=TEAM_ROLE_ADMIN),
            ]
        )

        mock_repo = MagicMock()

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=team):
            with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        remove_team_member(
                            team_id="team-1",
                            user_id="owner-id",
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )
        assert exc_info.value.status_code == 400
        assert "owner" in exc_info.value.detail.lower()

    def test_raises_404_when_not_member(self, admin_user):
        from app.api.v1.endpoints.teams import remove_team_member

        team = _make_team(members=[TeamMember(user_id="admin-1", role=TEAM_ROLE_OWNER)])

        mock_repo = MagicMock()

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=team):
            with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        remove_team_member(
                            team_id="team-1",
                            user_id="nonexistent",
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# Permission-focused tests
# ---------------------------------------------------------------------------


class TestDeleteTeamPermissions:
    """delete_team has dual-path permission logic: team:delete OR owner role."""

    def test_user_with_team_delete_bypasses_ownership_check(self, admin_user):
        """Admin with team:delete can delete any team without being a member."""
        from app.api.v1.endpoints.teams import delete_team

        mock_team_repo = MagicMock()
        mock_team_repo.delete = AsyncMock()
        mock_proj_repo = MagicMock()
        mock_proj_repo.update_many = AsyncMock(return_value=0)

        # check_team_access is NOT called when has_permission("team:delete") is True
        with patch(f"{MODULE}.check_team_access", new_callable=AsyncMock) as mock_access:
            with patch(f"{MODULE}.TeamRepository", return_value=mock_team_repo):
                # Patched at source: delete_team uses a function-level import
                with patch("app.repositories.ProjectRepository", return_value=mock_proj_repo):
                    asyncio.run(
                        delete_team(
                            team_id="team-1",
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )

        mock_access.assert_not_called()
        mock_team_repo.delete.assert_called_once()

    def test_user_without_team_delete_must_be_owner(self, regular_user):
        """User without team:delete falls through to owner role check."""
        from app.api.v1.endpoints.teams import delete_team

        with patch(f"{MODULE}.check_team_access", new_callable=AsyncMock) as mock_access:
            mock_access.side_effect = HTTPException(status_code=403, detail="Not enough permissions")
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    delete_team(
                        team_id="team-1",
                        current_user=regular_user,
                        db=MagicMock(),
                    )
                )

        assert exc_info.value.status_code == 403
        # Verify the required_role=TEAM_ROLE_OWNER was passed
        call_kwargs = mock_access.call_args
        assert call_kwargs.kwargs["required_role"] == TEAM_ROLE_OWNER


class TestUpdateTeamMemberOwnerProtection:
    """Only owners can modify another owner's role."""

    def test_non_owner_cannot_modify_owner_role(self, regular_user):
        from app.api.v1.endpoints.teams import update_team_member
        from app.schemas.team import TeamMemberUpdate

        team = _make_team(
            members=[
                TeamMember(user_id="the-owner", role=TEAM_ROLE_OWNER),
                TeamMember(user_id=str(regular_user.id), role=TEAM_ROLE_ADMIN),
            ]
        )

        mock_repo = MagicMock()

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=team):
            with patch(f"{MODULE}.TeamRepository", return_value=mock_repo):
                # check_team_access is called again for owner verification
                with patch(f"{MODULE}.check_team_access", new_callable=AsyncMock) as mock_access:
                    mock_access.side_effect = HTTPException(
                        status_code=403,
                        detail="Not enough permissions in this team",
                    )
                    with pytest.raises(HTTPException) as exc_info:
                        asyncio.run(
                            update_team_member(
                                team_id="team-1",
                                user_id="the-owner",
                                member_in=TeamMemberUpdate(role=TEAM_ROLE_ADMIN),
                                current_user=regular_user,
                                db=MagicMock(),
                            )
                        )

        assert exc_info.value.status_code == 403
        # Verify owner role was required
        call_kwargs = mock_access.call_args
        assert call_kwargs.kwargs["required_role"] == TEAM_ROLE_OWNER
