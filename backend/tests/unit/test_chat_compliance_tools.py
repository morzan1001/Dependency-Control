"""The chat framework evaluation and policy audit tools, answered from what the producers store."""

import pytest
import pytest_asyncio

from app.models.user import User
from app.schemas.policy_audit import PolicyAuditAction
from app.schemas.project import LicensePolicySchema
from app.services.audit.history import record_license_policy_change
from app.services.chat.tools import ChatToolRegistry
from app.services.crypto_policy.seeder import load_seed_rules, seed_crypto_policies, write_policy
from tests.helpers.permission_presets import PRESET_ADMIN

_PROJECT = "p-audit"


def _admin() -> User:
    return User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))


@pytest_asyncio.fixture
async def audited(db):
    """The system crypto seed, one project crypto override and one project license-policy change."""
    await db.projects.insert_one(
        {"_id": _PROJECT, "name": "P", "default_branch": "main", "deleted_branches": [], "members": []}
    )
    await seed_crypto_policies(db)
    await write_policy(
        db,
        scope="project",
        project_id=_PROJECT,
        rules=list(load_seed_rules()),
        action=PolicyAuditAction.UPDATE,
        actor=_admin(),
    )
    old = LicensePolicySchema().model_dump()
    await record_license_policy_change(
        db,
        project_id=_PROJECT,
        old_policy=old,
        new_policy={**old, "allow_strong_copyleft": True},
        action=PolicyAuditAction.UPDATE,
        actor=_admin(),
    )
    return db


async def _audit(db, **args) -> dict:
    return await ChatToolRegistry().execute_tool("list_policy_audit_entries", args, _admin(), db)


@pytest.mark.asyncio
@pytest.mark.parametrize("framework", ["license-audit", "cve-remediation-sla"])
async def test_every_report_framework_is_evaluated(audited, framework):
    result = await ChatToolRegistry().execute_tool(
        "get_framework_evaluation_summary",
        {"scope": "project", "scope_id": _PROJECT, "framework": framework},
        _admin(),
        audited,
    )

    assert result["framework"] == framework
    assert result["summary"]["total"] > 0


@pytest.mark.asyncio
@pytest.mark.parametrize("framework", ["nist", ""])
async def test_an_unknown_framework_is_refused_with_the_frameworks_that_exist(audited, framework):
    result = await ChatToolRegistry().execute_tool(
        "get_framework_evaluation_summary",
        {"scope": "project", "scope_id": _PROJECT, "framework": framework},
        _admin(),
        audited,
    )

    assert "summary" not in result
    assert "cve-remediation-sla" in result["error"]


@pytest.mark.asyncio
async def test_license_policy_history_is_listed(audited):
    result = await _audit(audited, policy_scope="project", project_id=_PROJECT, policy_type="license")

    assert [(e["policy_type"], e["change_summary"]) for e in result["entries"]] == [
        ("license", "allow_strong_copyleft: False -> True")
    ]


@pytest.mark.asyncio
async def test_crypto_policy_history_is_the_default(audited):
    result = await _audit(audited, policy_scope="project", project_id=_PROJECT)

    assert [e["policy_type"] for e in result["entries"]] == ["crypto"]


@pytest.mark.asyncio
async def test_project_scope_without_a_project_is_refused(audited):
    result = await _audit(audited, policy_scope="project")

    assert "entries" not in result
    assert "project_id" in result["error"]


@pytest.mark.asyncio
async def test_system_scope_lists_the_system_history_whatever_project_is_named(audited):
    result = await _audit(audited, policy_scope="system", project_id=_PROJECT)

    assert [(e["policy_scope"], e["action"]) for e in result["entries"]] == [("system", "seed")]
