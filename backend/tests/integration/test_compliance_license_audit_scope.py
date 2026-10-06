"""A team license audit honours each project's own policy through the severity its scan recorded."""

from datetime import datetime, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.core.init_db import create_indexes
from app.models.project import Project, Scan
from app.repositories.findings import FindingRepository
from app.repositories.scans import ScanRepository
from app.schemas.compliance import ControlStatus, ReportFramework
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import _persist_findings_and_waivers, _prepare_finding_records
from app.services.analytics.scopes import ResolvedScope
from app.services.analyzers.license_compliance import LicenseAnalyzer
from app.services.compliance.engine import ComplianceReportEngine
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from app.services.crypto_policy.seeder import seed_crypto_policies
from app.services.normalizers.license import normalize_license
from tests.helpers.analyzers import analyze_cyclonedx

_GPL_COMPONENT = {
    "type": "library",
    "name": "gpl-lib",
    "version": "1.0.0",
    "licenses": [{"license": {"id": "GPL-3.0-only"}}],
}


async def _scan_project(db, project_id: str, policy: dict) -> list[dict]:
    scan_id = f"{project_id}-scan"
    await db.projects.insert_one(
        Project(
            id=project_id,
            name=project_id,
            team_ids=["team-1"],
            latest_scan_id=scan_id,
            analyzer_settings={"license_compliance": policy},
        ).model_dump(by_alias=True)
    )
    await ScanRepository(db).create(
        Scan(id=scan_id, project_id=project_id, branch="main", status=SCAN_STATUS_COMPLETED)
    )
    result = await analyze_cyclonedx(LicenseAnalyzer(), [_GPL_COMPONENT], policy)
    aggregator = ResultAggregator()
    normalize_license(aggregator, result, source="sbom.json")
    records, _ = _prepare_finding_records(aggregator.get_findings(), scan_id, project_id, datetime.now(timezone.utc))
    await _persist_findings_and_waivers(records, scan_id, project_id, FindingRepository(db), db)
    return await db.findings.find({"scan_id": scan_id}).to_list(None)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_team_audit_fails_only_the_project_whose_policy_forbids_gpl(db):
    await create_indexes(db)
    await seed_crypto_policies(db)
    await _scan_project(db, "internal-tool", {"distribution_model": "internal_only"})
    [shipped] = await _scan_project(db, "shipped-app", {})
    resolved = ResolvedScope(scope="team", scope_id="team-1", project_ids=["internal-tool", "shipped-app"])

    _, evaluation = await ComplianceReportEngine().evaluate(
        db, resolved, FRAMEWORK_REGISTRY[ReportFramework.LICENSE_AUDIT]
    )

    strong = next(c for c in evaluation.controls if c.control_id == "LICENSE-AUDIT-STRONG-COPYLEFT")
    assert strong.status == ControlStatus.FAILED.value
    assert strong.evidence_finding_ids == [shipped["_id"]]
