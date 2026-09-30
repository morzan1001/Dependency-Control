"""A compliance report evaluates every finding its framework reads, however many the scope holds."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.core.init_db import create_indexes
from app.models.compliance_report import ComplianceReport
from app.models.project import Project, Scan
from app.repositories.findings import FindingRepository
from app.repositories.scans import ScanRepository
from app.schemas.compliance import ControlStatus, ReportFormat, ReportFramework, ReportStatus
from app.services.analysis.engine import _persist_findings_and_waivers, _prepare_finding_records
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.engine import ComplianceReportEngine
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from app.services.compliance.renderers.base import coverage_statement
from app.services.compliance.renderers.json_renderer import JsonRenderer
from app.services.crypto_policy.seeder import seed_crypto_policies
from tests.helpers.findings import grype_findings

_PROJECT = "sla-project"
_SCAN = "sla-scan"
# One past the 20,000 findings a report used to read.
_OVERDUE = 20_001


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_cve_sla_report_evaluates_every_overdue_finding(db):
    await create_indexes(db)
    await seed_crypto_policies(db)
    await db.projects.insert_one(Project(id=_PROJECT, name="sla", latest_scan_id=_SCAN).model_dump(by_alias=True))
    await ScanRepository(db).create(Scan(id=_SCAN, project_id=_PROJECT, branch="main", status=SCAN_STATUS_COMPLETED))
    findings = grype_findings(
        ((f"brace-expansion-{i:06d}", "2.0.1", None) for i in range(_OVERDUE)), severity="Critical"
    )
    records, _ = _prepare_finding_records(findings, _SCAN, _PROJECT, datetime.now(timezone.utc) - timedelta(days=400))
    await _persist_findings_and_waivers(records, _SCAN, _PROJECT, FindingRepository(db), db)
    resolved = ResolvedScope(scope="project", scope_id=_PROJECT, project_ids=[_PROJECT])

    inputs, evaluation = await ComplianceReportEngine().evaluate(
        db, resolved, FRAMEWORK_REGISTRY[ReportFramework.CVE_REMEDIATION_SLA]
    )

    assert len(inputs.findings) == _OVERDUE
    critical = next(c for c in evaluation.controls if c.control_id == "CVE-SLA-CRITICAL")
    assert critical.status == ControlStatus.FAILED.value
    assert len(critical.evidence_finding_ids) == _OVERDUE
    assert evaluation.coverage.complete
    assert "in scope" not in coverage_statement(evaluation.coverage)
    report = ComplianceReport(
        scope="project",
        scope_id=_PROJECT,
        framework=ReportFramework.CVE_REMEDIATION_SLA,
        format=ReportFormat.JSON,
        status=ReportStatus.COMPLETED,
        requested_by="u",
        requested_at=datetime.now(timezone.utc),
    )
    body, _, _ = JsonRenderer().render(evaluation, report)
    assert "findings" not in json.loads(body)["coverage"]
