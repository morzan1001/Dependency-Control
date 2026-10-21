from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from app.models.compliance_report import ComplianceReport
from app.models.policy_audit_entry import PolicyAuditEntry
from app.models.project import Scan
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.schemas.policy_audit import PolicyAuditAction
from app.schemas.project import LicensePolicySchema
from app.services.audit.history import record_license_policy_change
from app.services.chat.tools import ChatToolRegistry
from app.services.crypto_policy.seeder import load_seed_rules, seed_crypto_policies, write_policy
from tests.helpers.auth import make_admin

_PROJECT = "p-audit"


@pytest_asyncio.fixture
async def audited(db):
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
        actor=make_admin(),
    )
    old = LicensePolicySchema().model_dump()
    await record_license_policy_change(
        db,
        project_id=_PROJECT,
        old_policy=old,
        new_policy={**old, "allow_strong_copyleft": True},
        action=PolicyAuditAction.UPDATE,
        actor=make_admin(),
    )
    return db


async def _audit(db, **args) -> dict:
    return await ChatToolRegistry().execute_tool("list_policy_audit_entries", args, make_admin(), db)


@pytest.mark.asyncio
@pytest.mark.parametrize("framework", ["license-audit", "cve-remediation-sla"])
async def test_every_report_framework_is_evaluated(audited, framework):
    result = await ChatToolRegistry().execute_tool(
        "get_framework_evaluation_summary",
        {"scope": "project", "scope_id": _PROJECT, "framework": framework},
        make_admin(),
        audited,
    )

    assert result["framework"] == framework
    assert result["summary"]["total"] > 0


@pytest.mark.asyncio
async def test_a_project_whose_cbom_listed_no_asset_is_evaluated(audited):
    cbom_scan = Scan(id="s-cbom", project_id=_PROJECT, branch="main", status="completed", scan_type="cbom")
    await audited.scans.insert_one(cbom_scan.model_dump(by_alias=True))

    result = await ChatToolRegistry().execute_tool(
        "get_framework_evaluation_summary",
        {"scope": "project", "scope_id": _PROJECT, "framework": "nist-sp-800-131a"},
        make_admin(),
        audited,
    )

    assert result["summary"]["not_evaluated"] == 0
    assert result["coverage"] == "The verdicts cover the whole scope."


@pytest.mark.asyncio
@pytest.mark.parametrize("framework", ["nist", ""])
async def test_an_unknown_framework_is_refused_with_the_frameworks_that_exist(audited, framework):
    result = await ChatToolRegistry().execute_tool(
        "get_framework_evaluation_summary",
        {"scope": "project", "scope_id": _PROJECT, "framework": framework},
        make_admin(),
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


def _report(index: int) -> dict:
    return ComplianceReport(
        scope="project",
        scope_id=_PROJECT,
        framework=ReportFramework.LICENSE_AUDIT,
        format=ReportFormat.PDF,
        status=ReportStatus.COMPLETED,
        requested_by="admin-1",
        requested_at=datetime(2026, 10, 1, tzinfo=timezone.utc) + timedelta(days=index),
    ).model_dump(by_alias=True)


def _audit_entry(version: int) -> dict:
    return PolicyAuditEntry(
        policy_scope="project",
        project_id=_PROJECT,
        version=version,
        action=PolicyAuditAction.UPDATE,
        # Later than the fixture's own entry, which write_policy stamps now.
        timestamp=datetime.now(timezone.utc) + timedelta(days=version),
        snapshot={"rules": []},
        change_summary=f"v{version}",
    ).model_dump(by_alias=True)


@pytest.mark.asyncio
async def test_a_report_listing_cut_at_its_limit_names_every_report_newest_first(audited):
    await audited.compliance_reports.insert_many([_report(i) for i in range(5)])

    result = await ChatToolRegistry().execute_tool(
        "list_compliance_reports", {"project_id": _PROJECT, "limit": 2}, make_admin(), audited
    )

    assert [r["requested_at"] for r in result["reports"]] == [_report(4)["requested_at"], _report(3)["requested_at"]]
    assert result["reports_total"] == 5
    assert "2 of 5 compliance reports" in result["_bounded_read_note"]


@pytest.mark.asyncio
async def test_a_policy_history_cut_at_its_limit_names_every_entry_newest_first(audited):
    await audited.crypto_policy_history.insert_many([_audit_entry(v) for v in range(2, 6)])
    stored = await audited.crypto_policy_history.count_documents(
        {"policy_scope": "project", "project_id": _PROJECT, "policy_type": "crypto"}
    )

    result = await _audit(audited, policy_scope="project", project_id=_PROJECT, limit=2)

    assert [e["change_summary"] for e in result["entries"]] == ["v5", "v4"]
    assert result["entries_total"] == stored
    assert f"2 of {stored} policy audit entries" in result["_bounded_read_note"]


@pytest_asyncio.fixture
async def one_rule_overridden(db):
    await db.projects.insert_one({"_id": _PROJECT, "name": "P", "default_branch": "main", "members": []})
    await seed_crypto_policies(db)
    rules = list(load_seed_rules())
    # The last rule sits past where a full-row dump would hit the byte cap.
    flipped = rules[-1].model_copy(update={"enabled": not rules[-1].enabled})
    await write_policy(
        db,
        scope="project",
        project_id=_PROJECT,
        rules=[*rules[:-1], flipped],
        action=PolicyAuditAction.UPDATE,
        actor=make_admin(),
    )
    return db, flipped.rule_id


async def _policy(db, **args) -> dict:
    return await ChatToolRegistry().execute_tool(
        "get_project_crypto_policy", {"project_id": _PROJECT, **args}, make_admin(), db
    )


@pytest.mark.asyncio
async def test_the_crypto_policy_lists_every_rule_whole_and_names_the_overridden_one(one_rule_overridden):
    db, flipped = one_rule_overridden

    result = await _policy(db)

    assert "_truncated" not in result
    assert [r["rule_id"] for r in result["rules"]] == [r.rule_id for r in load_seed_rules()]
    assert [r["rule_id"] for r in result["rules"] if r["overridden"]] == [flipped]
    assert set(result["rules"][0]) == {"rule_id", "name", "enabled", "default_severity", "finding_type", "overridden"}


@pytest.mark.asyncio
async def test_one_crypto_rule_is_answered_with_its_description_and_matchers(one_rule_overridden):
    db, flipped = one_rule_overridden
    stored = next(r for r in load_seed_rules() if r.rule_id == flipped)

    result = await _policy(db, rule_id=flipped)

    assert result["rule"] == {**stored.model_dump(), "enabled": not stored.enabled, "overridden": True}


@pytest.mark.asyncio
async def test_an_unknown_crypto_rule_is_refused(one_rule_overridden):
    db, _ = one_rule_overridden

    assert await _policy(db, rule_id="no-such-rule") == {"error": "Rule no-such-rule is not in this project's policy"}
