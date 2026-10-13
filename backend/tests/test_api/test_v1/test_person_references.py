"""A stored reference to a person is the account's id, and every read names the account by its current
username; a value that names no account, like a username stored before the ids, reads as stored."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi import BackgroundTasks

from app.api.v1.endpoints import invitations, policy_audit, waivers
from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.policy_audit_entry import PolicyAuditEntry
from app.schemas.policy_audit import PolicyAuditAction
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


# Each entry keeps the actor's name from the time of the change next to the actor's id.
AUDIT_ACTORS = {3: ("u-ada", "ada"), 2: ("u-gone", "gone.user"), 1: (None, None)}
AUDIT_SHOWN = [(3, "ada.lovelace"), (2, "gone.user"), (1, None)]
AUDITED_POLICIES = {
    "system-crypto": ("system", None, "crypto"),
    "project-crypto": ("project", PROJECT, "crypto"),
    "project-license": ("project", PROJECT, "license"),
}
LIST_AUDIT = {
    "system-crypto": lambda db: policy_audit.list_system_audit(ADMIN, db, skip=0, limit=50),
    "project-crypto": lambda db: policy_audit.list_project_audit(PROJECT, ADMIN, db, skip=0, limit=50),
    "project-license": lambda db: policy_audit.list_project_license_audit(PROJECT, ADMIN, db, skip=0, limit=50),
}
GET_AUDIT = {
    "system-crypto": lambda db, version: policy_audit.get_system_audit_entry(version, ADMIN, db),
    "project-crypto": lambda db, version: policy_audit.get_project_audit_entry(PROJECT, version, ADMIN, db),
    "project-license": lambda db, version: policy_audit.get_project_license_audit_entry(PROJECT, version, ADMIN, db),
}


@pytest_asyncio.fixture
async def audited(db):
    for policy_scope, project_id, policy_type in AUDITED_POLICIES.values():
        for version, (actor_user_id, actor_display_name) in AUDIT_ACTORS.items():
            entry = PolicyAuditEntry(
                policy_type=policy_type,
                policy_scope=policy_scope,
                project_id=project_id,
                version=version,
                action=PolicyAuditAction.SEED if actor_user_id is None else PolicyAuditAction.UPDATE,
                actor_user_id=actor_user_id,
                actor_display_name=actor_display_name,
                timestamp=NOW + timedelta(minutes=version),
                snapshot={"rules": []},
                change_summary=f"v{version}",
            )
            await db.crypto_policy_history.insert_one(entry.model_dump(by_alias=True))
    return db


class TestPolicyAudit:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("policy", list(LIST_AUDIT))
    async def test_the_history_names_each_actor_as_they_are_named_now(self, audited, policy):
        result = await LIST_AUDIT[policy](audited)

        assert [(e["version"], e["actor_display_name"]) for e in result["entries"]] == AUDIT_SHOWN

    @pytest.mark.asyncio
    @pytest.mark.parametrize("policy", list(GET_AUDIT))
    async def test_one_entry_names_its_actor_as_they_are_named_now(self, audited, policy):
        shown = [(version, (await GET_AUDIT[policy](audited, version))["actor_display_name"]) for version in (3, 2, 1)]

        assert shown == AUDIT_SHOWN

    @pytest.mark.asyncio
    @pytest.mark.parametrize("policy", list(AUDITED_POLICIES))
    async def test_the_chat_history_names_each_actor_as_they_are_named_now(self, audited, policy):
        policy_scope, project_id, policy_type = AUDITED_POLICIES[policy]
        args = {
            "policy_scope": policy_scope,
            "policy_type": policy_type,
            **({"project_id": project_id} if project_id else {}),
        }

        result = await _tool(audited, "list_policy_audit_entries", **args)

        assert [(e["version"], e["actor_display_name"]) for e in result["entries"]] == AUDIT_SHOWN
