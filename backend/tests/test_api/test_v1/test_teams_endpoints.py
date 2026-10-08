"""Tests for team API endpoints."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.core.constants import TEAM_ROLE_ADMIN, TEAM_ROLE_MEMBER
from app.models.team import Team, TeamMember
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.api.v1.endpoints.teams"
_TEAM_TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _make_team(id="team-1", name="Test Team", members=None):
    if members is None:
        members = [TeamMember(user_id="user-1", role=TEAM_ROLE_ADMIN)]
    return Team(id=id, name=name, members=members)


def _fake_db_with_team(members) -> FakeDatabase:
    db = FakeDatabase()
    db.teams._docs["team-1"] = {
        "_id": "team-1",
        "name": "Test Team",
        "members": [{"user_id": user_id, "role": role} for user_id, role in members],
        "created_at": _TEAM_TIMESTAMP,
        "updated_at": _TEAM_TIMESTAMP,
    }
    for user_id, _role in members:
        db.users._docs[user_id] = {"_id": user_id, "username": user_id}
    return db


def _stored_team(db: FakeDatabase) -> Team:
    return Team(**db.teams._docs["team-1"])


def _stored_roles(db: FakeDatabase) -> dict[str, str]:
    return {member["user_id"]: member["role"] for member in db.teams._docs["team-1"]["members"]}


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
        assert result["members"][0]["role"] == TEAM_ROLE_ADMIN
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
    def test_the_search_matches_the_team_name_whatever_the_case(self, admin_user):
        from app.api.v1.endpoints.teams import read_teams

        db = FakeDatabase()
        for team_id, name in (("t-front", "Frontend"), ("t-back", "Backend")):
            db.teams._docs[team_id] = {
                "_id": team_id,
                "name": name,
                "members": [],
                "created_at": _TEAM_TIMESTAMP,
                "updated_at": _TEAM_TIMESTAMP,
            }

        teams = asyncio.run(
            read_teams(search="FRONT", sort_by="name", sort_order="asc", current_user=admin_user, db=db)
        )

        assert [team["_id"] for team in teams] == ["t-front"]

    def test_viewer_without_read_perm_raises_403(self, viewer_user):
        from app.api.v1.endpoints.teams import read_teams

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
    def test_returns_the_team_with_its_members_named(self, admin_user):
        from app.api.v1.endpoints.teams import read_team

        db = _fake_db_with_team([("u1", TEAM_ROLE_ADMIN)])

        with patch(f"{MODULE}.check_team_access", new_callable=AsyncMock):
            result = asyncio.run(read_team(team_id="team-1", current_user=admin_user, db=db))

        assert result.name == "Test Team"
        assert [(member.user_id, member.username) for member in result.members] == [("u1", "u1")]

    def test_raises_404_when_not_found(self, admin_user):
        from app.api.v1.endpoints.teams import read_team

        with patch(f"{MODULE}.check_team_access", new_callable=AsyncMock):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(read_team(team_id="missing", current_user=admin_user, db=FakeDatabase()))
        assert exc_info.value.status_code == 404


class TestUpdateTeam:
    def test_success_updates_team(self, admin_user):
        from app.api.v1.endpoints.teams import update_team
        from app.schemas.team import TeamResponse, TeamUpdate

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

    def test_a_rename_cannot_write_a_null_name(self):
        from app.schemas.team import TeamUpdate

        with pytest.raises(ValidationError):
            TeamUpdate(name=None)

    def test_the_description_can_still_be_cleared(self):
        from app.schemas.team import TeamUpdate

        cleared = TeamUpdate(description=None).model_dump(exclude_unset=True)
        assert Team(name="t", **cleared).description is None


class TestDeleteTeam:
    def test_the_deleted_team_stops_owning_every_project_and_its_co_owners_stay(self, admin_user):
        """Deleting a team is the reaper for its id: nothing else removes an owner whose team is
        gone, and a co-owner must not be reaped with it."""
        from app.api.v1.endpoints.teams import delete_team

        db = _fake_db_with_team([("admin-1", TEAM_ROLE_ADMIN)])
        asyncio.run(
            db.projects.insert_one(
                {
                    "_id": "p-shared",
                    "name": "shared",
                    "team_ids": ["team-1", "team-keep"],
                    "team_sources": {"team-1": "gitlab", "team-keep": "manual"},
                }
            )
        )
        asyncio.run(
            db.projects.insert_one(
                {
                    "_id": "p-sole",
                    "name": "sole",
                    "team_ids": ["team-1"],
                    "team_sources": {"team-1": "gitlab"},
                }
            )
        )

        with patch(f"{MODULE}.check_team_access", new_callable=AsyncMock):
            asyncio.run(delete_team(team_id="team-1", current_user=admin_user, db=db))

        shared = db.projects._docs["p-shared"]
        assert shared["team_ids"] == ["team-keep"]
        assert shared["team_sources"] == {"team-keep": "manual"}

        sole = db.projects._docs["p-sole"]
        assert sole["team_ids"] == []
        assert "team-1" not in db.teams._docs


class TestAddTeamMember:
    def test_success_adds_member(self, admin_user):
        from app.api.v1.endpoints.teams import add_team_member
        from app.schemas.team import TeamMemberAdd

        db = _fake_db_with_team([("admin-1", TEAM_ROLE_ADMIN)])
        asyncio.run(
            db.users.insert_one(
                {"_id": "new-user-id", "username": "newuser", "email": "new@test.com", "is_verified": True}
            )
        )

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=_stored_team(db)):
            result = asyncio.run(
                add_team_member(
                    team_id="team-1",
                    member_in=TeamMemberAdd(email="new@test.com"),
                    current_user=admin_user,
                    db=db,
                )
            )

        assert [(m.user_id, m.role) for m in result.members] == [
            ("admin-1", TEAM_ROLE_ADMIN),
            ("new-user-id", TEAM_ROLE_MEMBER),
        ]
        assert _stored_roles(db) == {"admin-1": TEAM_ROLE_ADMIN, "new-user-id": TEAM_ROLE_MEMBER}

    def test_raises_404_when_user_not_found(self, admin_user):
        from app.api.v1.endpoints.teams import add_team_member
        from app.schemas.team import TeamMemberAdd

        team = _make_team()
        mock_team_repo = MagicMock()
        mock_user_repo = MagicMock()
        mock_user_repo.get_raw_by_verified_email = AsyncMock(return_value=None)

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
        """The refusal comes from the push's own filter, so a second add cannot duplicate the row."""
        from app.api.v1.endpoints.teams import add_team_member
        from app.schemas.team import TeamMemberAdd

        db = _fake_db_with_team([("admin-1", TEAM_ROLE_ADMIN), ("existing-id", TEAM_ROLE_MEMBER)])
        asyncio.run(db.users.update_one({"_id": "existing-id"}, {"$set": {"email": "e@test.com", "is_verified": True}}))

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=_stored_team(db)):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    add_team_member(
                        team_id="team-1",
                        member_in=TeamMemberAdd(email="e@test.com"),
                        current_user=admin_user,
                        db=db,
                    )
                )
        assert exc_info.value.status_code == 400
        assert "already" in exc_info.value.detail.lower()
        assert _stored_roles(db) == {"admin-1": TEAM_ROLE_ADMIN, "existing-id": TEAM_ROLE_MEMBER}


class TestMemberRoleIsConstrained:
    """`update_member_role` writes with a bare `$set`, so an illegal role that gets past the request
    schema is stored unvalidated and then fails every later `Team(**data)` read — including the two
    endpoints that would repair it."""

    @pytest.mark.parametrize("role", ["owner", "Admin", "ADMIN", "", "viewer"])
    def test_illegal_roles_rejected_at_the_boundary(self, role):
        from app.schemas.team import TeamMemberAdd, TeamMemberUpdate

        with pytest.raises(ValidationError):
            TeamMemberUpdate(role=role)
        with pytest.raises(ValidationError):
            TeamMemberAdd(email="a@b.c", role=role)

    @pytest.mark.parametrize("role", [TEAM_ROLE_MEMBER, TEAM_ROLE_ADMIN])
    def test_legal_roles_accepted(self, role):
        from app.schemas.team import TeamMemberUpdate

        assert TeamMemberUpdate(role=role).role == role

    def test_storage_model_would_reject_what_the_schema_now_blocks(self):
        with pytest.raises(ValidationError):
            TeamMember(user_id="u1", role="owner")


class TestUpdateTeamMember:
    def test_raises_404_when_user_not_in_team(self, admin_user):
        from app.api.v1.endpoints.teams import update_team_member
        from app.schemas.team import TeamMemberUpdate

        team = _make_team(members=[TeamMember(user_id="admin-1", role=TEAM_ROLE_ADMIN)])

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

        db = _fake_db_with_team(
            [("admin-1", TEAM_ROLE_ADMIN), ("to-remove", TEAM_ROLE_MEMBER), ("stay", TEAM_ROLE_MEMBER)]
        )

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=_stored_team(db)):
            result = asyncio.run(
                remove_team_member(
                    team_id="team-1",
                    user_id="to-remove",
                    current_user=admin_user,
                    db=db,
                )
            )

        assert [m.user_id for m in result.members] == ["admin-1", "stay"]
        assert _stored_roles(db) == {"admin-1": TEAM_ROLE_ADMIN, "stay": TEAM_ROLE_MEMBER}

    def test_raises_400_when_removing_last_admin_self(self, admin_user):
        """admin_user (id="admin-1") is the only admin; the pull's filter is what refuses."""
        from app.api.v1.endpoints.teams import remove_team_member

        db = _fake_db_with_team([("admin-1", TEAM_ROLE_ADMIN), ("other-user", TEAM_ROLE_MEMBER)])

        with patch(f"{MODULE}.get_team_with_access", new_callable=AsyncMock, return_value=_stored_team(db)):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    remove_team_member(
                        team_id="team-1",
                        user_id="admin-1",
                        current_user=admin_user,
                        db=db,
                    )
                )
        assert exc_info.value.status_code == 400
        assert "admin" in exc_info.value.detail.lower()
        assert _stored_roles(db) == {"admin-1": TEAM_ROLE_ADMIN, "other-user": TEAM_ROLE_MEMBER}

    def test_raises_404_when_not_member(self, admin_user):
        from app.api.v1.endpoints.teams import remove_team_member

        team = _make_team(members=[TeamMember(user_id="admin-1", role=TEAM_ROLE_ADMIN)])

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


class TestDeleteTeamPermissions:
    """team:delete deletes any team; everyone else has to be an admin of it."""

    def test_user_with_team_delete_needs_no_membership(self, admin_user):
        from app.api.v1.endpoints.teams import delete_team

        db = _fake_db_with_team([("someone-else", TEAM_ROLE_ADMIN)])

        asyncio.run(delete_team(team_id="team-1", current_user=admin_user, db=db))

        assert "team-1" not in db.teams._docs

    def test_user_without_team_delete_must_be_a_team_admin(self, regular_user):
        from app.api.v1.endpoints.teams import delete_team

        db = _fake_db_with_team([("someone-else", TEAM_ROLE_ADMIN), (regular_user.id, TEAM_ROLE_MEMBER)])

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(delete_team(team_id="team-1", current_user=regular_user, db=db))

        assert exc_info.value.status_code == 403
        assert "team-1" in db.teams._docs


class TestTeamScopingAndRolePersistence:
    """FakeDatabase-backed: the query and the write are the behaviour, so a mock that answers
    every query the same way cannot see either of them."""

    @staticmethod
    async def _seeded(teams, users=()):
        db = FakeDatabase()
        for user in users:
            await db.users.insert_one(user)
        for team in teams:
            await db.teams.insert_one(team)
        return db

    @staticmethod
    def _team_doc(team_id, name, member_ids):
        return {
            "_id": team_id,
            "name": name,
            "members": [{"user_id": uid, "role": TEAM_ROLE_MEMBER} for uid in member_ids],
            "created_at": _TEAM_TIMESTAMP,
            "updated_at": _TEAM_TIMESTAMP,
        }

    @pytest.mark.asyncio
    async def test_a_team_read_user_sees_only_the_teams_holding_them(self, regular_user):
        from app.api.v1.endpoints.teams import read_teams

        caller = str(regular_user.id)
        db = await self._seeded(
            teams=[
                self._team_doc("t-mine", "Mine", [caller]),
                self._team_doc("t-theirs", "Theirs", ["someone-else"]),
                self._team_doc("t-empty", "Empty", []),
            ],
            users=[{"_id": caller, "username": regular_user.username}],
        )

        teams = await read_teams(search=None, sort_by="name", sort_order="asc", current_user=regular_user, db=db)

        assert [team["_id"] for team in teams] == ["t-mine"]

    @pytest.mark.asyncio
    async def test_a_read_all_user_sees_every_team(self, admin_user):
        from app.api.v1.endpoints.teams import read_teams

        db = await self._seeded(
            teams=[
                self._team_doc("t-mine", "Mine", [str(admin_user.id)]),
                self._team_doc("t-theirs", "Theirs", ["someone-else"]),
            ]
        )

        teams = await read_teams(search=None, sort_by="name", sort_order="asc", current_user=admin_user, db=db)

        assert sorted(team["_id"] for team in teams) == ["t-mine", "t-theirs"]

    @pytest.mark.asyncio
    async def test_the_listing_and_the_detail_name_every_member_and_none_for_a_deleted_account(self, admin_user):
        from app.api.v1.endpoints.teams import read_team, read_teams
        from app.schemas.team import TeamResponse

        db = await self._seeded(
            teams=[self._team_doc("t-1", "One", ["u-ada", "u-gone"]), self._team_doc("t-2", "Two", ["u-bob"])],
            users=[{"_id": "u-ada", "username": "ada"}, {"_id": "u-bob", "username": "bob"}],
        )

        listed = await read_teams(search=None, sort_by="name", sort_order="asc", current_user=admin_user, db=db)
        detail = await read_team(team_id="t-1", current_user=admin_user, db=db)

        def names(team):
            return [(member.user_id, member.username) for member in TeamResponse.model_validate(team).members]

        assert [names(team) for team in listed] == [[("u-ada", "ada"), ("u-gone", None)], [("u-bob", "bob")]]
        assert names(detail) == [("u-ada", "ada"), ("u-gone", None)]

    @pytest.mark.asyncio
    async def test_the_requested_role_is_the_one_persisted(self, admin_user):
        from app.api.v1.endpoints.teams import update_team_member
        from app.schemas.team import TeamMemberUpdate

        target = "target-user"
        db = await self._seeded(
            teams=[self._team_doc("team-1", "Test Team", [str(admin_user.id), target])],
            users=[{"_id": target, "username": "target"}],
        )

        await update_team_member(
            team_id="team-1",
            user_id=target,
            member_in=TeamMemberUpdate(role=TEAM_ROLE_ADMIN),
            current_user=admin_user,
            db=db,
        )

        stored = await db.teams.find_one({"_id": "team-1"})
        roles = {member["user_id"]: member["role"] for member in stored["members"]}
        assert roles[target] == TEAM_ROLE_ADMIN

    @pytest.mark.asyncio
    async def test_a_removal_landing_between_the_read_and_the_write_cannot_redirect_the_role(self, admin_user):
        from app.api.v1.endpoints.teams import update_team_member
        from app.schemas.team import TeamMemberUpdate

        earlier, target, bystander = "earlier-user", "target-user", "bystander-user"
        db = await self._seeded(
            teams=[self._team_doc("team-1", "Test Team", [str(admin_user.id), earlier, target, bystander])],
            users=[{"_id": uid, "username": uid} for uid in (earlier, target, bystander)],
        )

        write = db.teams.update_one

        async def remove_earlier_then_write(*args, **kwargs):
            db.teams.update_one = write
            await write({"_id": "team-1"}, {"$pull": {"members": {"user_id": earlier}}})
            return await write(*args, **kwargs)

        db.teams.update_one = remove_earlier_then_write

        await update_team_member(
            team_id="team-1",
            user_id=target,
            member_in=TeamMemberUpdate(role=TEAM_ROLE_ADMIN),
            current_user=admin_user,
            db=db,
        )

        stored = await db.teams.find_one({"_id": "team-1"})
        assert {member["user_id"]: member["role"] for member in stored["members"]} == {
            str(admin_user.id): TEAM_ROLE_MEMBER,
            target: TEAM_ROLE_ADMIN,
            bystander: TEAM_ROLE_MEMBER,
        }
