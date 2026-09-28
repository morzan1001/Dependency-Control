"""One waiver read rule for the list, the filtered list and a single waiver: waiver:read or
waiver:read_all opens global waivers, read_all opens every project's, and waiver:read alone opens
the projects the caller may view."""

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import waivers
from app.core.permissions import Permissions
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools.definitions import TOOL_PERMISSIONS
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)


def _user(*permissions: str) -> User:
    return User(id="u-1", username="u", email="u@corp.com", permissions=list(permissions))


async def _db() -> FakeDatabase:
    db = FakeDatabase()
    await db.projects.insert_one({"_id": "p-foreign", "name": "foreign", "team_ids": [], "members": []})
    for waiver_id, project_id in (("w-project", "p-foreign"), ("w-global", None)):
        await db.waivers.insert_one(
            {
                "_id": waiver_id,
                "project_id": project_id,
                "finding_id": "CVE-1",
                "reason": "accepted",
                "created_by": "admin",
                "created_at": _NOW,
            }
        )
    return db


async def _listed(user: User, **filters) -> set[str]:
    page = await waivers.list_waivers(
        await _db(),
        user,
        project_id=filters.get("project_id"),
        global_only=filters.get("global_only", False),
        finding_id=None,
        package_name=None,
        search=None,
        orphaned=False,
        sort_by="created_at",
        sort_order="desc",
        skip=0,
        limit=50,
    )
    return {item["id"] for item in page["items"]}


class TestReadAll:
    @pytest.mark.asyncio
    async def test_opens_a_project_waiver_without_project_access(self):
        waiver = await waivers.get_waiver("w-project", await _db(), _user(Permissions.WAIVER_READ_ALL))
        assert waiver.id == "w-project"

    @pytest.mark.asyncio
    async def test_filters_by_a_project_without_project_access(self):
        assert await _listed(_user(Permissions.WAIVER_READ_ALL), project_id="p-foreign") == {"w-project"}


class TestReadOnly:
    @pytest.mark.asyncio
    async def test_opens_a_global_waiver(self):
        waiver = await waivers.get_waiver("w-global", await _db(), _user(Permissions.WAIVER_READ))
        assert waiver.id == "w-global"

    @pytest.mark.asyncio
    async def test_lists_global_waivers_only(self):
        assert await _listed(_user(Permissions.WAIVER_READ), global_only=True) == {"w-global"}

    @pytest.mark.asyncio
    async def test_cannot_open_a_waiver_of_a_project_it_cannot_view(self):
        with pytest.raises(HTTPException) as exc_info:
            await waivers.get_waiver("w-project", await _db(), _user(Permissions.WAIVER_READ, Permissions.PROJECT_READ))
        assert exc_info.value.status_code == 403


class TestChatWaiverTools:
    @pytest.mark.parametrize(
        "tool", ["list_project_waivers", "list_global_waivers", "get_waiver_status", "get_expiring_waivers"]
    )
    def test_follow_rests_waiver_read_permissions(self, tool):
        assert TOOL_PERMISSIONS[tool] == [Permissions.WAIVER_READ, Permissions.WAIVER_READ_ALL]

    @pytest.mark.asyncio
    async def test_read_all_lists_a_foreign_projects_waivers_as_rest_does(self):
        result = await ChatToolRegistry().execute_tool(
            "list_project_waivers", {"project_id": "p-foreign"}, _user(Permissions.WAIVER_READ_ALL), await _db()
        )
        assert [w["id"] for w in result["waivers"]] == ["w-project"]

    @pytest.mark.asyncio
    async def test_read_alone_cannot_list_a_project_it_cannot_view(self):
        result = await ChatToolRegistry().execute_tool(
            "list_project_waivers",
            {"project_id": "p-foreign"},
            _user(Permissions.WAIVER_READ, Permissions.PROJECT_READ),
            await _db(),
        )
        assert "waivers" not in result
        assert result["error"]
