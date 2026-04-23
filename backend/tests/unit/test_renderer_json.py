import json
from datetime import datetime, timezone

import pytest

from app.models.compliance_report import ComplianceReport
from app.models.finding import Severity
from app.schemas.compliance import (
    ControlResult,
    ControlStatus,
    FrameworkEvaluation,
    ReportFormat,
    ReportFramework,
    ReportStatus,
)
from app.services.compliance.renderers.json_renderer import JsonRenderer


def _evaluation():
    return FrameworkEvaluation(
        framework_key=ReportFramework.NIST_SP_800_131A,
        framework_name="NIST SP 800-131A",
        framework_version="Rev.3",
        generated_at=datetime(2026, 4, 20, tzinfo=timezone.utc),
        scope_description="project 'x'",
        controls=[
            ControlResult(
                control_id="NIST-131A-01",
                title="MD5 disallowed",
                description="...",
                status=ControlStatus.FAILED,
                severity=Severity.HIGH,
                evidence_finding_ids=["f1"],
                evidence_asset_bom_refs=["a1"],
                waiver_reasons=[],
                remediation="Replace MD5 with SHA-256.",
            ),
        ],
        summary={"passed": 0, "failed": 1, "waived": 0, "not_applicable": 0, "total": 1},
        residual_risks=[],
        inputs_fingerprint="sha256:abc",
    )


def _report():
    return ComplianceReport(
        scope="project",
        scope_id="p1",
        framework=ReportFramework.NIST_SP_800_131A,
        format=ReportFormat.JSON,
        status=ReportStatus.GENERATING,
        requested_by="u1",
        requested_at=datetime(2026, 4, 20, tzinfo=timezone.utc),
    )


def test_json_renderer_outputs_valid_json():
    r = JsonRenderer()
    eval_ = _evaluation()
    rep = _report()
    out, filename, mime = r.render(eval_, rep)
    assert mime == "application/json"
    assert filename.endswith(".json")
    data = json.loads(out)
    assert data["framework"] == "nist-sp-800-131a"
    assert data["summary"]["failed"] == 1
    assert len(data["controls"]) == 1
    assert data["controls"][0]["control_id"] == "NIST-131A-01"
    assert "inputs_fingerprint" in data


def test_json_renderer_disclaimer_included_if_present():
    r = JsonRenderer()
    eval_ = _evaluation()
    eval_disclaimer = "test disclaimer"
    rep = _report()
    out, _, _ = r.render(eval_, rep, disclaimer=eval_disclaimer)
    data = json.loads(out)
    assert data["disclaimer"] == "test disclaimer"
