"""A single-project report judges its controls by the policy the analyzers ran for that project."""

from datetime import datetime, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.crypto_policy import CryptoPolicy
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.compliance import ControlStatus, ReportFramework
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.engine import ComplianceReportEngine
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from app.services.crypto_policy.seeder import load_seed_rules

_MD5_CONTROL = "NIST-131A-nist-131a-md5"


async def _project_with_md5_and_an_override_disabling_its_rule(db):
    db.projects._docs["p1"] = {"_id": "p1", "name": "p1", "default_branch": "main", "latest_scan_id": None}
    db.scans._docs["s1"] = {
        "_id": "s1",
        "project_id": "p1",
        "branch": "main",
        "status": SCAN_STATUS_COMPLETED,
        "created_at": datetime.now(timezone.utc),
    }
    db.crypto_assets._docs["a1"] = {
        "_id": "a1",
        "project_id": "p1",
        "scan_id": "s1",
        "bom_ref": "crypto/algorithm/md5",
        "name": "MD5",
        "asset_type": CryptoAssetType.ALGORITHM.value,
        "primitive": CryptoPrimitive.HASH.value,
    }
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(CryptoPolicy(scope="system", rules=list(load_seed_rules()), version=3))
    md5_rule = next(r for r in load_seed_rules() if r.rule_id == "nist-131a-md5")
    await repo.upsert_project_policy(
        CryptoPolicy(
            scope="project", project_id="p1", rules=[md5_rule.model_copy(update={"enabled": False})], version=2
        )
    )


@pytest.mark.asyncio
async def test_a_rule_the_project_disabled_makes_its_control_not_applicable_rather_than_passed(db):
    await _project_with_md5_and_an_override_disabling_its_rule(db)
    framework = FRAMEWORK_REGISTRY[ReportFramework.NIST_SP_800_131A]

    inputs = await ComplianceReportEngine()._gather_inputs(
        db, ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"]), framework
    )
    statuses = {c.control_id: c.status for c in framework.evaluate(inputs).controls}

    assert statuses[_MD5_CONTROL] == ControlStatus.NOT_APPLICABLE
    assert (inputs.policy_version, inputs.override_version) == (3, 2)


@pytest.mark.asyncio
async def test_a_team_report_keeps_judging_by_the_system_rules(db):
    await _project_with_md5_and_an_override_disabling_its_rule(db)
    framework = FRAMEWORK_REGISTRY[ReportFramework.NIST_SP_800_131A]

    inputs = await ComplianceReportEngine()._gather_inputs(
        db, ResolvedScope(scope="team", scope_id="t1", project_ids=["p1"]), framework
    )

    assert next(r for r in inputs.policy_rules if r.rule_id == "nist-131a-md5").enabled
    assert (inputs.policy_version, inputs.override_version) == (3, None)
