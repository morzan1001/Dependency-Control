"""JSON renderer — machine-readable structured output."""

import json

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import FrameworkEvaluation
from app.services.compliance.renderers.base import coverage_statement


class JsonRenderer:
    mime_type = "application/json"
    extension = "json"

    def render(
        self,
        evaluation: FrameworkEvaluation,
        report: ComplianceReport,
        *,
        disclaimer: str | None = None,
    ) -> bytes:
        payload: dict = {
            "framework": evaluation.framework_key,
            "framework_name": evaluation.framework_name,
            "framework_version": evaluation.framework_version,
            "generated_at": evaluation.generated_at.isoformat(),
            "scope": {"kind": report.scope, "id": report.scope_id},
            "scope_description": evaluation.scope_description,
            "summary": evaluation.summary,
            "controls": [c.model_dump() for c in evaluation.controls],
            "residual_risks": [r.model_dump() for r in evaluation.residual_risks],
            "inputs_fingerprint": evaluation.inputs_fingerprint,
            "coverage": {
                **evaluation.coverage.model_dump(),
                "complete": evaluation.coverage.complete,
                "statement": coverage_statement(evaluation.coverage),
            },
        }
        if disclaimer:
            payload["disclaimer"] = disclaimer
        return json.dumps(payload, indent=2, default=str).encode("utf-8")
