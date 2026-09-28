"""One team read rule, and the team writes that must hold across every path: REST, chat and analytics
scopes read teams the same way, a missing team is a 404 for every caller, the last admin cannot be
demoted, and an entry a live sync owns is not edited by hand."""

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import teams
from app.core.constants import TEAM_ROLE_ADMIN, TEAM_ROLE_MEMBER, team_source
from app.core.permissions import Permissions
from app.models.user import User
from app.schemas.team import TeamMemberUpdate
from app.services.analytics.scopes import ScopeResolutionError, ScopeResolver
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools.definitions import TOOL_PERMISSIONS
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
_GITLAB = team_source("gitlab", "gl-1")


def _user(*permissions: str, user_id: str = "u-1") -> User:
    return User(id=user_id, username=user_id, email=f"{user_id}@corp.com", permissions=list(permissions))


def _member(user_id: str, role: str = TEAM_ROLE_MEMBER, source: str = "manual") -> dict:
    return {"user_id": user_id, "role": role, "source": source}


_A_MEMBER = (_member("u-1"),)


async def _db(members=_A_MEMBER, bindings=()) -> FakeDatabase:
    db = FakeDatabase()
    for team_id, name, team_members in (("t-1", "Alpha", list(members)), ("t-2", "Beta", [])):
        await db.teams.insert_one(
            {
                "_id": team_id,
                "name": name,
                "members": team_members,
                "bindings": list(bindings) if team_id == "t-1" else [],
                "created_at": _NOW,
                "updated_at": _NOW,
            }
        )
    for project_id, members_of, critical in (("p-mine", [{"user_id": "u-1", "role": "viewer"}], 1), ("p-other", [], 5)):
        await db.projects.insert_one(
            {
                "_id": project_id,
                "name": project_id,
                "team_ids": ["t-1"],
                "members": members_of,
                "stats": {"critical": critical},
            }
        )
    return db


class TestChatTeamTools:
    def test_every_team_tool_demands_a_team_read_permission(self):
        for tool in ("list_teams", "get_team_details", "get_team_projects", "get_team_risk_overview"):
            assert TOOL_PERMISSIONS[tool] == [Permissions.TEAM_READ, Permissions.TEAM_READ_ALL]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("caller", "readable"),
        [
            (_user(Permissions.TEAM_READ), True),
            (_user(Permissions.CHAT_ACCESS), False),
            (_user(Permissions.TEAM_READ, user_id="u-out"), False),
            (_user(Permissions.TEAM_READ_ALL, user_id="u-out"), True),
        ],
    )
    async def test_team_details_follow_rests_read_rule(self, caller, readable):
        result = await ChatToolRegistry().execute_tool("get_team_details", {"team_id": "t-1"}, caller, await _db())
        assert ("team" in result) is readable

    @pytest.mark.asyncio
    async def test_a_read_all_holder_lists_every_team(self):
        db = await _db()
        result = await ChatToolRegistry().execute_tool(
            "list_teams", {}, _user(Permissions.TEAM_READ_ALL, user_id="u-out"), db
        )
        assert sorted(team["id"] for team in result["teams"]) == ["t-1", "t-2"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("permissions", "critical"),
        [((Permissions.TEAM_READ_ALL,), 0), ((Permissions.TEAM_READ_ALL, Permissions.PROJECT_READ), 1)],
    )
    async def test_the_risk_overview_sums_only_projects_the_caller_reads(self, permissions, critical):
        result = await ChatToolRegistry().execute_tool(
            "get_team_risk_overview", {"team_id": "t-1"}, _user(*permissions), await _db(members=())
        )

        assert result["severity_totals"].get("critical", 0) == critical


class TestAnalyticsTeamScope:
    @pytest.mark.asyncio
    async def test_a_member_without_team_read_is_refused(self):
        db = await _db()
        with pytest.raises(ScopeResolutionError):
            await ScopeResolver(db, _user(Permissions.PROJECT_READ)).resolve(scope="team", scope_id="t-1")

    @pytest.mark.asyncio
    async def test_a_read_all_holder_sees_only_the_team_projects_they_may_read(self):
        db = await _db()
        await db.projects.update_one({"_id": "p-mine"}, {"$set": {"members": [{"user_id": "u-out", "role": "viewer"}]}})
        caller = _user(Permissions.TEAM_READ_ALL, Permissions.PROJECT_READ, user_id="u-out")

        resolved = await ScopeResolver(db, caller).resolve(scope="team", scope_id="t-1")

        assert resolved.project_ids == ["p-mine"]


class TestTeamWrites:
    @pytest.mark.asyncio
    async def test_a_team_delete_holder_gets_404_for_a_missing_team(self):
        with pytest.raises(HTTPException) as exc_info:
            await teams.delete_team("t-missing", _user(Permissions.TEAM_DELETE), FakeDatabase())
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_the_last_admin_cannot_be_demoted(self):
        db = await _db(members=(_member("u-a", TEAM_ROLE_ADMIN), _member("u-b", TEAM_ROLE_ADMIN)))
        caller = _user(Permissions.TEAM_UPDATE)

        await teams.update_team_member("t-1", "u-b", TeamMemberUpdate(role=TEAM_ROLE_MEMBER), caller, db)
        with pytest.raises(HTTPException) as exc_info:
            await teams.update_team_member("t-1", "u-a", TeamMemberUpdate(role=TEAM_ROLE_MEMBER), caller, db)

        assert (exc_info.value.status_code, exc_info.value.detail) == (
            400,
            "Cannot demote the last admin. Add another admin first.",
        )
        roles = {m["user_id"]: m["role"] for m in (await db.teams.find_one({"_id": "t-1"}))["members"]}
        assert roles == {"u-a": TEAM_ROLE_ADMIN, "u-b": TEAM_ROLE_MEMBER}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action", ["update", "remove"])
    async def test_an_entry_a_live_sync_owns_is_not_edited_by_hand(self, action):
        db = await _db(
            members=(_member("u-a", TEAM_ROLE_ADMIN), _member("u-synced", source=_GITLAB)),
            bindings=({"provider": "gitlab", "instance_id": "gl-1", "external_id": 12, "key": "gitlab:gl-1:12"},),
        )
        await db.gitlab_instances.insert_one(
            {"_id": "gl-1", "name": "gl", "url": "https://gitlab.corp", "sync_teams": True, "created_by": "u-a"}
        )
        caller = _user(Permissions.TEAM_UPDATE)

        with pytest.raises(HTTPException) as exc_info:
            if action == "update":
                await teams.update_team_member("t-1", "u-synced", TeamMemberUpdate(role=TEAM_ROLE_ADMIN), caller, db)
            else:
                await teams.remove_team_member("t-1", "u-synced", caller, db)

        assert exc_info.value.status_code == 409
        assert "GitLab group 12" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_an_entry_no_live_sync_refreshes_can_be_removed(self):
        db = await _db(members=(_member("u-a", TEAM_ROLE_ADMIN), _member("u-synced", source=_GITLAB)))

        await teams.remove_team_member("t-1", "u-synced", _user(Permissions.TEAM_UPDATE), db)

        assert [m["user_id"] for m in (await db.teams.find_one({"_id": "t-1"}))["members"]] == ["u-a"]
