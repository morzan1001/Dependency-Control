"""A stored reference to a person is the account's id, and every read names the account by its current
username; a value that names no account, like a username stored before the ids, reads as stored."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi import BackgroundTasks

from app.api.v1.endpoints import invitations, waivers
from app.core.constants import SCAN_STATUS_COMPLETED
from app.schemas.waiver import WaiverCreate, WaiverUpdate
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.auth import make_admin

ADMIN = make_admin()
PROJECT = "p-1"
NOW = datetime.now(timezone.utc)
# Ada was renamed after she wrote; Grace's waiver predates the ids; the third account is gone.
ADA = {"_id": "u-ada", "username": "ada.lovelace", "email": "ada@corp.com", "permissions": []}
CREATORS = {"w-ada": "u-ada", "w-legacy": "grace", "w-gone": "u-gone"}
SHOWN = {"w-ada": "ada.lovelace", "w-legacy": "grace", "w-gone": "u-gone"}


def _waiver(waiver_id: str, created_by: str, project_id: str | None, **fields) -> dict:
    return {
        "_id": waiver_id,
        "project_id": project_id,
        "finding_id": f"QUALITY:{waiver_id}:1.0",
        "package_name": waiver_id,
        "reason": "accepted",
        "status": "accepted_risk",
        "created_by": created_by,
        "created_at": datetime(2026, 9, 1, tzinfo=timezone.utc),
        **fields,
    }


@pytest_asyncio.fixture
async def db(db):
    await db.users.insert_many([ADMIN.model_dump(by_alias=True), dict(ADA)])
    await db.projects.insert_one(
        {"_id": PROJECT, "name": "P", "default_branch": "main", "deleted_branches": [], "latest_scan_id": "s-1"}
    )
    await db.scans.insert_one(
        {"_id": "s-1", "project_id": PROJECT, "branch": "main", "status": SCAN_STATUS_COMPLETED, "created_at": NOW}
    )
    for waiver_id, created_by in CREATORS.items():
        await db.waivers.insert_one(_waiver(waiver_id, created_by, PROJECT))
        await db.waivers.insert_one(_waiver(f"g-{waiver_id}", created_by, None))
    return db


async def _tool(db, name: str, **args) -> dict:
    return await ChatToolRegistry().execute_tool(name, args, ADMIN, db)


class TestWaivers:
    @pytest.mark.asyncio
    async def test_a_new_waiver_stores_its_creator_by_id_and_answers_with_the_name(self, db):
        created = await waivers.create_waiver(
            WaiverCreate(package_name="requests", reason="vendored"), BackgroundTasks(), db, ADMIN
        )

        assert (await db.waivers.find_one({"_id": created["id"]}))["created_by"] == ADMIN.id
        assert created["created_by"] == ADMIN.username

    @pytest.mark.asyncio
    async def test_the_list_names_each_creator(self, db):
        page = await waivers.list_waivers(db=db, current_user=ADMIN, project_id=PROJECT)

        assert {item["id"]: item["created_by"] for item in page["items"]} == SHOWN

    @pytest.mark.asyncio
    @pytest.mark.parametrize("waiver_id", list(SHOWN))
    async def test_a_single_waiver_names_its_creator(self, db, waiver_id):
        read = await waivers.get_waiver(waiver_id, db, ADMIN)
        updated = await waivers.update_waiver(waiver_id, WaiverUpdate(reason="revisited"), BackgroundTasks(), db, ADMIN)

        assert read["created_by"] == updated["created_by"] == SHOWN[waiver_id]
        assert (await db.waivers.find_one({"_id": waiver_id}))["created_by"] == CREATORS[waiver_id]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("order", "expected"), [("asc", ["w-ada", "w-legacy", "w-gone"]), ("desc", ["w-gone", "w-legacy", "w-ada"])]
    )
    async def test_sorting_by_creator_follows_the_names_shown(self, db, order, expected):
        page = await waivers.list_waivers(
            db=db, current_user=ADMIN, project_id=PROJECT, sort_by="created_by", sort_order=order
        )

        assert [item["id"] for item in page["items"]] == expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("tool", "args"),
        [("list_project_waivers", {"project_id": PROJECT}), ("list_global_waivers", {})],
        ids=["project", "global"],
    )
    async def test_the_chat_waiver_lists_name_each_creator(self, db, tool, args):
        result = await _tool(db, tool, **args)

        assert {w["id"].removeprefix("g-"): w["created_by"] for w in result["waivers"]} == SHOWN

    @pytest.mark.asyncio
    @pytest.mark.parametrize("lapsed", [False, True], ids=["active", "expired"])
    async def test_the_chat_waiver_status_names_the_creator(self, db, lapsed):
        expiry = NOW + timedelta(days=-1 if lapsed else 1)
        await db.waivers.update_one({"_id": "w-ada"}, {"$set": {"expiration_date": expiry}})

        result = await _tool(db, "get_waiver_status", project_id=PROJECT, finding_id="QUALITY:w-ada:1.0")

        assert result["expired_waiver" if lapsed else "waiver"]["created_by"] == "ada.lovelace"


class TestInvitations:
    @pytest.mark.asyncio
    async def test_an_invitation_stores_its_inviter_by_id(self, db):
        await invitations.create_system_invitation(BackgroundTasks(), db, ADMIN, "nora@corp.com")

        assert (await db.system_invitations.find_one({"email": "nora@corp.com"}))["invited_by"] == ADMIN.id

    @pytest.mark.asyncio
    async def test_pending_invitations_name_each_inviter(self, db):
        expires = NOW + timedelta(days=1)
        for key, invited_by in CREATORS.items():
            await db.system_invitations.insert_one(
                {
                    "_id": key,
                    "email": f"{key}@corp.com",
                    "token": key,
                    "invited_by": invited_by,
                    "expires_at": expires,
                    "is_used": False,
                }
            )

        pending = await invitations.read_system_invitations(db, ADMIN)

        assert {i["_id"]: i["invited_by"] for i in pending} == SHOWN
