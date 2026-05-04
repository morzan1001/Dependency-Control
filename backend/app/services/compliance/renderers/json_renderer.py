"""JSON renderer — machine-readable structured output."""

import json
from typing import Optional, Tuple

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import FrameworkEvaluation, ReportFormat
from app.services.compliance.renderers.base import build_filename


class JsonRenderer:
    format = ReportFormat.JSON
    mime_type = "application/json"
    extension = "json"

    def render(
        self,
        evaluation: FrameworkEvaluation,
        report: ComplianceReport,
        *,
        disclaimer: Optional[str] = None,
    ) -> Tuple[bytes, str, str]:
        framework_key_str = (
            evaluation.framework_key if isinstance(evaluation.framework_key, str) else evaluation.framework_key.value
        )
        payload: dict = {
            "framework": framework_key_str,
            "framework_name": evaluation.framework_name,
            "framework_version": evaluation.framework_version,
            "generated_at": evaluation.generated_at.isoformat(),
            "scope": {"kind": report.scope, "id": report.scope_id},
            "scope_description": evaluation.scope_description,
            "summary": evaluation.summary,
            "controls": [c.model_dump() for c in evaluation.controls],
            "residual_risks": [r.model_dump() for r in evaluation.residual_risks],
            "inputs_fingerprint": evaluation.inputs_fingerprint,
        }
        if disclaimer:
            payload["disclaimer"] = disclaimer
        body = json.dumps(payload, indent=2, default=str).encode("utf-8")
        filename = build_filename(
            framework_key_str,
            report.scope,
            report.scope_id,
            report.requested_at,
            self.extension,
        )
        return body, filename, self.mime_type
