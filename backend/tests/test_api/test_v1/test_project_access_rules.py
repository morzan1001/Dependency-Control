"""The project rules check_project_access owns, applied the same way on every path."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.v1.endpoints import projects
from app.api.v1.helpers.projects import team_derived_role
from app.core.permissions import Permissions
from app.models.project import Project
from app.models.system import SystemSettings
from app.models.user import User
from app.repositories import ProjectRepository, TeamRepository
from app.repositories.base import and_filters
from app.schemas.project import ProjectCreate, ProjectMemberUpdate, ProjectNotificationSettings
from app.services.notifications.service import notification_service
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT = "p-1"
_TEAM = "t-ops"


def _user(user_id: str, *permissions: str) -> User:
    return User(id=user_id, username=user_id, email=f"{user_id}@corp.com", permissions=list(permissions))


_ADMIN_BY_TEAM = _user("u-team-admin", Permissions.PROJECT_READ)
_MEMBER_BY_TEAM = _user("u-team-member", Permissions.PROJECT_READ)


async def _db(*, members=(("u-direct-admin", "admin"),), team_members=(("u-team-admin", "admin"),)) -> FakeDatabase:
    db = FakeDatabase()
    await db.teams.insert_one(
        {"_id": _TEAM, "name": "Ops", "members": [{"user_id": uid, "role": role} for uid, role in team_members]}
    )
    await db.projects.insert_one(
        {
            "_id": _PROJECT,
            "name": "proj",
            "team_ids": [_TEAM],
            "members": [{"user_id": uid, "role": role} for uid, role in members],
        }
    )
    for uid in ("u-direct-admin", "u-team-admin", "u-team-member", "u-viewer"):
        await db.users.insert_one({"_id": uid, "username": uid, "email": f"{uid}@corp.com", "is_active": True})
    return db


def _stored(db) -> dict:
    return db.projects._docs[_PROJECT]


class TestCreateProjectTeamGrant:
    @staticmethod
    async def _create(db, user, team_id):
        with patch("app.api.v1.endpoints.projects._audit_license_policy_change", AsyncMock()):
            return await projects.create_project(ProjectCreate(name="new", team_id=team_id), user, db, SystemSettings())

    @pytest.mark.asyncio
    async def test_a_write_superuser_may_hand_it_to_a_team_they_are_not_in(self):
        db = await _db()
        created = await self._create(db, _user("u-su", Permissions.PROJECT_CREATE, Permissions.PROJECT_UPDATE), _TEAM)
        assert db.projects._docs[created.project_id]["team_ids"] == [_TEAM]

    @pytest.mark.asyncio
    async def test_an_unknown_team_is_not_found(self):
        with pytest.raises(HTTPException) as exc_info:
            await self._create(await _db(), _user("u-su", Permissions.PROJECT_CREATE), "t-missing")
        assert exc_info.value.status_code == 404


class TestUpdateAndDeleteAreSeparateGrants:
    @pytest.mark.asyncio
    async def test_project_update_does_not_delete(self):
        db = await _db()
        with pytest.raises(HTTPException) as exc_info:
            await projects.delete_project(_PROJECT, _user("u-editor", Permissions.PROJECT_UPDATE), db)
        assert exc_info.value.status_code == 403
        assert _PROJECT in db.projects._docs

    @pytest.mark.asyncio
    async def test_project_delete_deletes(self):
        db = await _db()
        await projects.delete_project(_PROJECT, _user("u-deleter", Permissions.PROJECT_DELETE), db)
        assert _PROJECT not in db.projects._docs

    @pytest.mark.asyncio
    async def test_project_delete_does_not_rotate_the_api_key(self):
        with pytest.raises(HTTPException) as exc_info:
            await projects.rotate_api_key(_PROJECT, _user("u-deleter", Permissions.PROJECT_DELETE), await _db())
        assert exc_info.value.status_code == 403


class TestProjectDeleteCascade:
    @pytest.mark.asyncio
    async def test_the_projects_webhooks_and_crypto_policy_go_with_it(self):
        db = await _db()
        for owner in (_PROJECT, "p-other"):
            await db.webhooks.insert_one({"_id": f"wh-{owner}", "project_id": owner, "url": "https://hook"})
            await db.crypto_policies.insert_one({"_id": f"cp-{owner}", "scope": "project", "project_id": owner})

        await projects.delete_project(_PROJECT, _user("u-direct-admin", Permissions.PROJECT_READ), db)

        assert [w["_id"] async for w in db.webhooks.find({})] == ["wh-p-other"]
        assert [c["_id"] async for c in db.crypto_policies.find({})] == ["cp-p-other"]


class TestEffectiveRoleOnThePage:
    @pytest.mark.asyncio
    async def test_a_direct_viewer_who_admins_an_owning_team_reads_as_admin(self):
        db = await _db(members=(("u-direct-admin", "admin"), ("u-team-admin", "viewer")))

        project = await projects.read_project(_PROJECT, _ADMIN_BY_TEAM, db)

        member = next(m for m in project.members if m.user_id == "u-team-admin")
        assert (member.role, member.effective_role) == ("viewer", "admin")


class TestLastAdmin:
    @pytest.mark.asyncio
    async def test_a_write_superuser_may_remove_the_last_direct_admin(self):
        db = await _db(team_members=())

        await projects.remove_project_member(_PROJECT, "u-direct-admin", _user("u-su", Permissions.PROJECT_UPDATE), db)

        assert _stored(db)["members"] == []

    @pytest.mark.asyncio
    async def test_the_member_guard_holds_against_a_concurrent_owner_removal(self):
        from app.api.v1.helpers.projects import last_admin_guard

        db = await _db()
        project = Project(**_stored(db))
        guard = await last_admin_guard(project, _ADMIN_BY_TEAM, TeamRepository(db), leaving_member="u-direct-admin")

        await db.projects.update_one({"_id": _PROJECT}, {"$set": {"team_ids": []}})

        assert not await ProjectRepository(db).remove_member(_PROJECT, "u-direct-admin", guard)
        assert [m["user_id"] for m in _stored(db)["members"]] == ["u-direct-admin"]

    def test_a_member_update_names_the_role(self):
        with pytest.raises(ValidationError):
            ProjectMemberUpdate.model_validate({"notification_preferences": {"analysis_completed": ["email"]}})


class TestTeamMembersNotificationSettings:
    @pytest.mark.asyncio
    async def test_a_team_admin_enforces_and_saves_without_a_member_row(self):
        db = await _db()
        prefs = {"analysis_completed": ["email"]}

        await projects.update_notification_settings(
            _PROJECT,
            ProjectNotificationSettings(notification_preferences=prefs, enforce_notification_settings=True),
            _ADMIN_BY_TEAM,
            db,
        )

        stored = _stored(db)
        assert stored["enforce_notification_settings"] is True
        assert stored["notification_overrides"] == {"u-team-admin": prefs}
        assert [m["user_id"] for m in stored["members"]] == ["u-direct-admin"]

    @pytest.mark.asyncio
    async def test_a_team_members_override_reaches_the_notifier(self):
        db = await _db(team_members=(("u-team-admin", "admin"), ("u-team-member", "member")))
        prefs = {"analysis_completed": ["slack"]}
        await projects.update_notification_settings(
            _PROJECT, ProjectNotificationSettings(notification_preferences=prefs), _MEMBER_BY_TEAM, db
        )

        with patch.object(notification_service, "_send_based_on_prefs", AsyncMock()) as notified:
            await notification_service.notify_project_members(
                Project(**_stored(db)), "analysis_completed", "s", "m", db
            )

        sent = {call.args[0].id: call.args[1] for call in notified.await_args_list}
        assert sent["u-team-member"] == prefs


@pytest.mark.asyncio
async def test_the_team_derived_role_reads_every_owning_team_at_once():
    db = await _db()
    await db.teams.insert_one({"_id": "t-2", "name": "Two", "members": [{"user_id": "u-team-admin", "role": "member"}]})
    reads = 0
    find = db.teams.find

    def counting_find(*args, **kwargs):
        nonlocal reads
        reads += 1
        return find(*args, **kwargs)

    db.teams.find = counting_find
    db.teams.find_one = None

    assert await team_derived_role([_TEAM, "t-2"], "u-team-admin", TeamRepository(db)) == "admin"
    assert reads == 1


class TestAndFilters:
    def test_empty_filters_drop_out(self):
        assert and_filters({}, {"a": 1}, {}) == {"a": 1}

    def test_nothing_left_matches_everything(self):
        assert and_filters({}, {}) == {}

    def test_two_filters_are_both_required(self):
        assert and_filters({"$or": [{"a": 1}]}, {"$or": [{"b": 2}]}) == {
            "$and": [{"$or": [{"a": 1}]}, {"$or": [{"b": 2}]}]
        }

    def test_the_single_filter_is_a_copy(self):
        own = {"a": 1}
        and_filters(own)["b"] = 2
        assert own == {"a": 1}
