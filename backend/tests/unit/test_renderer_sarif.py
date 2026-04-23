import json

import pytest

from app.services.compliance.renderers.sarif_renderer import SarifRenderer
from tests.unit.test_renderer_json import _evaluation, _report


def test_sarif_renderer_outputs_sarif_2_1_0():
    r = SarifRenderer()
    out, filename, mime = r.render(_evaluation(), _report())
    assert mime == "application/sarif+json"
    assert filename.endswith(".sarif.json") or filename.endswith(".sarif")
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    assert data["$schema"].endswith("sarif-schema-2.1.0.json")
    runs = data["runs"]
    assert len(runs) == 1
    driver = runs[0]["tool"]["driver"]
    assert driver["name"] == "DependencyControl Compliance"
    assert len(driver["rules"]) == 1
    results = runs[0]["results"]
    assert len(results) >= 1
    assert results[0]["ruleId"] == "NIST-131A-01"


def test_sarif_passed_control_emits_pass_result():
    from datetime import datetime, timezone
    from app.models.finding import Severity
    from app.schemas.compliance import (
        ControlResult,
        ControlStatus,
        FrameworkEvaluation,
        ReportFramework,
    )

    eval_ = FrameworkEvaluation(
        framework_key=ReportFramework.BSI_TR_02102,
        framework_name="BSI TR-02102",
        framework_version="2024",
        generated_at=datetime.now(timezone.utc),
        scope_description="x",
        controls=[
            ControlResult(
                control_id="BSI-02102-X",
                title="X",
                description="d",
                status=ControlStatus.PASSED,
                severity=Severity.LOW,
                evidence_finding_ids=[],
                evidence_asset_bom_refs=[],
                waiver_reasons=[],
                remediation="n/a",
            ),
        ],
        summary={"passed": 1, "failed": 0, "waived": 0, "not_applicable": 0, "total": 1},
        residual_risks=[],
        inputs_fingerprint="sha256:z",
    )
    r = SarifRenderer()
    out, _, _ = r.render(eval_, _report())
    data = json.loads(out)
    results = data["runs"][0]["results"]
    assert results[0]["kind"] == "pass"
