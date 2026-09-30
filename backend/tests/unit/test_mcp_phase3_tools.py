from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive


@pytest.mark.asyncio
async def test_generate_pqc_migration_plan_returns_response():
    from app.services.analytics.scopes import ResolvedScope
    from app.services.chat.tools import generate_pqc_migration_plan

    db = MagicMock()
    with patch("app.services.chat.tools.PQCMigrationPlanGenerator") as gen_cls:
        gen_cls.return_value = MagicMock(
            generate=AsyncMock(
                return_value=MagicMock(
                    model_dump=lambda: {"scope": "project", "items": []},
                )
            )
        )
        out = await generate_pqc_migration_plan(db, project_id="p1")
    assert out["scope"] == "project"
    assert out["items"] == []
    assert gen_cls.return_value.generate.await_args.kwargs["resolved"] == ResolvedScope(
        scope="project", scope_id="p1", project_ids=["p1"]
    )


@pytest.mark.asyncio
async def test_list_compliance_reports_returns_metadata():
    from app.services.chat.tools import list_compliance_reports

    db = MagicMock()
    with patch("app.services.chat.tools.ComplianceReportRepository") as repo_cls:
        repo_cls.return_value = MagicMock(
            list=AsyncMock(
                return_value=[
                    MagicMock(
                        model_dump=lambda **kw: {"id": "r1", "status": "completed"},
                    )
                ]
            )
        )
        out = await list_compliance_reports(db, visibility={"scope": "project", "scope_id": "p"})
    assert len(out["reports"]) == 1
    assert out["reports"][0]["id"] == "r1"


@pytest.mark.asyncio
async def test_list_policy_audit_entries_returns_timeline():
    from app.services.chat.tools import list_policy_audit_entries

    db = MagicMock()
    with patch("app.services.chat.tools.PolicyAuditRepository") as repo_cls:
        repo_cls.return_value = MagicMock(
            list=AsyncMock(
                return_value=[
                    MagicMock(
                        model_dump=lambda **kw: {"version": 1, "change_summary": "x"},
                    )
                ]
            )
        )
        out = await list_policy_audit_entries(db, policy_scope="system")
    assert out["entries"][0]["version"] == 1


async def _project_with_vulnerabilities_and_one_md5_finding(db):
    from app.models.crypto_asset import CryptoAsset
    from app.models.crypto_policy import CryptoPolicy
    from app.repositories.crypto_policy import CryptoPolicyRepository
    from app.services.analyzers.crypto.base import crypto_findings_for_assets
    from app.services.crypto_policy.seeder import load_seed_rules

    db.projects._docs["p1"] = {"_id": "p1", "name": "p1", "default_branch": "main", "latest_scan_id": None}
    db.scans._docs["s1"] = {
        "_id": "s1",
        "project_id": "p1",
        "branch": "main",
        "status": SCAN_STATUS_COMPLETED,
        "created_at": datetime.now(timezone.utc),
    }
    md5 = CryptoAsset(
        project_id="p1",
        scan_id="s1",
        bom_ref="crypto/algorithm/md5",
        name="MD5",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.HASH,
    )
    db.crypto_assets._docs["a1"] = {
        "_id": "a1",
        "project_id": "p1",
        "scan_id": "s1",
        "bom_ref": md5.bom_ref,
        "name": md5.name,
        "asset_type": CryptoAssetType.ALGORITHM.value,
        "primitive": CryptoPrimitive.HASH.value,
    }
    for finding in crypto_findings_for_assets([md5], load_seed_rules(), scanner="crypto_weak_algorithm"):
        db.findings._docs[finding["id"]] = {**finding, "_id": finding["id"], "scan_id": "s1", "project_id": "p1"}
    for n in range(3):
        db.findings._docs[f"v{n}"] = {"_id": f"v{n}", "type": "vulnerability", "scan_id": "s1", "project_id": "p1"}
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", rules=list(load_seed_rules()), version=1)
    )


async def _chat_summary(db, framework):
    from app.services.analytics.scopes import ResolvedScope
    from app.services.chat.tools import get_framework_evaluation_summary

    resolved = ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"])
    with patch("app.services.chat.tools.ScopeResolver") as scope_cls:
        scope_cls.return_value = MagicMock(resolve=AsyncMock(return_value=resolved))
        return await get_framework_evaluation_summary(
            db, user=MagicMock(), scope="project", scope_id="p1", framework=framework
        )


@pytest.mark.asyncio
async def test_the_chat_summary_reads_the_findings_the_report_reads(db, monkeypatch):
    """Vulnerability findings would fill the findings cap and withhold every absence-backed crypto verdict."""
    await _project_with_vulnerabilities_and_one_md5_finding(db)
    monkeypatch.setattr("app.services.compliance.engine._FINDINGS_LIMIT", 2)

    out = await _chat_summary(db, "nist-sp-800-131a")

    assert out["coverage"] == "Evaluated all 1 findings in scope. Evaluated all 1 crypto assets in scope."
    assert out["summary"]["failed"] >= 1
    assert out["summary"]["not_evaluated"] == 0


@pytest.mark.asyncio
async def test_the_chat_summary_states_the_pqc_plan_items_it_left_out(db):
    from app.schemas.pqc_migration import MigrationPlanResponse, MigrationPlanSummary

    await _project_with_vulnerabilities_and_one_md5_finding(db)
    plan = MigrationPlanResponse(
        scope="project",
        scope_id="p1",
        generated_at=datetime.now(timezone.utc),
        items=[],
        summary=MigrationPlanSummary(total_items=4200, items_returned=1000, status_counts={}, earliest_deadline=None),
        mappings_version=1,
    )
    with patch("app.services.compliance.frameworks.pqc_migration_plan.PQCMigrationPlanGenerator") as gen_cls:
        gen_cls.return_value = MagicMock(generate=AsyncMock(return_value=plan))
        out = await _chat_summary(db, "pqc-migration-plan")

    assert "Evaluated 1000 of 4200 migration plan items in scope" in out["coverage"]
