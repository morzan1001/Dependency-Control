"""get_project_details answers with the retention, rescan and license policy the system applies."""

import pytest

from app.core.constants import (
    RETENTION_ACTION_ARCHIVE,
    RETENTION_ACTION_DELETE,
    SETTINGS_MODE_GLOBAL,
    SETTINGS_MODE_PROJECT,
)
from app.models.user import User
from app.schemas.project import LicensePolicySchema
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT = "p-1"


def _seeded(project: dict, system: dict) -> FakeDatabase:
    db = FakeDatabase()
    db.projects._docs[_PROJECT] = {
        "_id": _PROJECT,
        "name": "checkout",
        "members": [{"user_id": "u-1", "role": "admin", "notification_preferences": {"scan": ["email"]}}],
        **project,
    }
    db.system_settings._docs["current"] = {"_id": "current", **system}
    return db


async def _details(db: FakeDatabase) -> dict:
    admin = User(id="u-admin", username="admin", email="admin@test.com", permissions=PRESET_ADMIN)
    result = await ChatToolRegistry().execute_tool("get_project_details", {"project_id": _PROJECT}, admin, db)
    return result["project"]


@pytest.mark.asyncio
async def test_global_retention_mode_reports_the_global_policy_housekeeping_applies():
    db = _seeded(
        {"retention_days": 90, "retention_action": RETENTION_ACTION_DELETE},
        {
            "retention_mode": SETTINGS_MODE_GLOBAL,
            "global_retention_days": 365,
            "global_retention_action": RETENTION_ACTION_ARCHIVE,
        },
    )

    assert (await _details(db))["retention"] == {"days": 365, "action": RETENTION_ACTION_ARCHIVE, "source": "global"}


@pytest.mark.asyncio
async def test_project_retention_without_an_action_is_deleted_and_without_days_kept():
    db = _seeded({"retention_days": 30}, {"retention_mode": SETTINGS_MODE_PROJECT})
    kept = _seeded({}, {"retention_mode": SETTINGS_MODE_PROJECT})

    assert (await _details(db))["retention"] == {"days": 30, "action": RETENTION_ACTION_DELETE, "source": "project"}
    assert (await _details(kept))["retention"]["days"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("project", "system", "hours"),
    [
        ({"rescan_enabled": None}, {"global_rescan_enabled": True, "global_rescan_interval": 24}, 24),
        ({"rescan_enabled": True, "rescan_interval": 6}, {"global_rescan_enabled": False}, 6),
        (
            {"rescan_enabled": True, "rescan_interval": 6},
            {"rescan_mode": SETTINGS_MODE_GLOBAL, "global_rescan_enabled": False},
            None,
        ),
    ],
    ids=["project-unset-falls-back", "project-decides", "global-mode-overrides"],
)
async def test_the_rescan_interval_is_the_one_the_scheduler_resolves(project, system, hours):
    assert (await _details(_seeded(project, system)))["rescan_interval_hours"] == hours


@pytest.mark.asyncio
async def test_the_license_policy_comes_from_the_license_compliance_settings():
    stored = LicensePolicySchema.model_validate({"distribution_model": "internal_only"}).model_dump(exclude_unset=True)
    db = _seeded({"analyzer_settings": {"license_compliance": stored}}, {})

    policy = (await _details(db))["license_policy"]

    assert policy == LicensePolicySchema(distribution_model="internal_only").model_dump()


@pytest.mark.asyncio
async def test_details_leave_members_to_get_project_members():
    assert "members" not in await _details(_seeded({}, {}))
