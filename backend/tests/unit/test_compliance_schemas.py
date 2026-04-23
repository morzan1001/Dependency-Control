from datetime import datetime, timezone

import pytest

from app.models.finding import FindingType, Severity
from app.schemas.compliance import (
    ControlDefinition,
    ControlResult,
    ControlStatus,
    FrameworkEvaluation,
    ReportFormat,
    ReportFramework,
    ReportStatus,
    ResidualRisk,
)


def test_control_definition_minimal():
    cd = ControlDefinition(
        control_id="NIST-131A-01",
        title="MD5 disallowed",
        description="...",
        severity=Severity.HIGH,
        remediation="Replace MD5 with SHA-256.",
        maps_to_rule_ids=["nist-131a-md5"],
        maps_to_finding_types=[FindingType.CRYPTO_WEAK_ALGORITHM],
    )
    assert cd.control_id == "NIST-131A-01"
    assert cd.custom_evaluator is None


def test_control_result_shape():
    cr = ControlResult(
        control_id="NIST-131A-01",
        title="MD5",
        description="...",
        status=ControlStatus.FAILED,
        severity=Severity.HIGH,
        evidence_finding_ids=["f1", "f2"],
        evidence_asset_bom_refs=["a1"],
        waiver_reasons=[],
        remediation="...",
    )
    assert cr.status == ControlStatus.FAILED


def test_framework_evaluation_shape():
    fe = FrameworkEvaluation(
        framework_key=ReportFramework.NIST_SP_800_131A,
        framework_name="NIST SP 800-131A",
        framework_version="Rev.3",
        generated_at=datetime.now(timezone.utc),
        scope_description="project 'X'",
        controls=[],
        summary={"passed": 0, "failed": 0, "waived": 0, "not_applicable": 0, "total": 0},
        residual_risks=[],
        inputs_fingerprint="sha256:abc",
    )
    assert fe.framework_key == ReportFramework.NIST_SP_800_131A
    assert fe.summary["total"] == 0


def test_enums():
    assert ReportFormat.PDF.value == "pdf"
    assert ReportFormat.CSV.value == "csv"
    assert ReportFormat.JSON.value == "json"
    assert ReportFormat.SARIF.value == "sarif"
    assert ReportStatus.COMPLETED.value == "completed"
    assert ControlStatus.PASSED.value == "passed"
