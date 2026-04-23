"""
SARIF 2.1.0 renderer.

Each ControlDefinition maps to a SARIF rule; each ControlResult maps to a
result. FAILED → result with `level`=error/warning based on severity;
PASSED → `kind="pass"`; WAIVED → `kind="pass"` + `baselineState="unchanged"`;
NOT_APPLICABLE → `kind="notApplicable"`.
"""

import json
from typing import Optional, Tuple

from app.models.compliance_report import ComplianceReport
from app.models.finding import Severity
from app.schemas.compliance import (
    ControlStatus,
    FrameworkEvaluation,
    ReportFormat,
)
from app.services.compliance.renderers.base import build_filename

_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL.value: "error",
    Severity.HIGH.value: "error",
    Severity.MEDIUM.value: "warning",
    Severity.LOW.value: "note",
    Severity.NEGLIGIBLE.value: "note",
    Severity.INFO.value: "note",
    Severity.UNKNOWN.value: "warning",
}


class SarifRenderer:
    format = ReportFormat.SARIF
    mime_type = "application/sarif+json"
    extension = "sarif.json"

    def render(
        self,
        evaluation: FrameworkEvaluation,
        report: ComplianceReport,
        *,
        disclaimer: Optional[str] = None,
    ) -> Tuple[bytes, str, str]:
        rules = []
        results = []

        for ctrl in evaluation.controls:
            sev_val = ctrl.severity if isinstance(ctrl.severity, str) else ctrl.severity.value
            rules.append(
                {
                    "id": ctrl.control_id,
                    "name": ctrl.title,
                    "shortDescription": {"text": ctrl.title},
                    "fullDescription": {"text": ctrl.description},
                    "help": {"text": ctrl.remediation},
                    "properties": {
                        "severity": sev_val,
                        "framework": evaluation.framework_key
                        if isinstance(evaluation.framework_key, str)
                        else evaluation.framework_key.value,
                    },
                }
            )

            status_val = ctrl.status if isinstance(ctrl.status, str) else ctrl.status.value
            result_entry = {
                "ruleId": ctrl.control_id,
                "message": {"text": ctrl.description},
            }
            if status_val == "failed":
                result_entry["level"] = _SEVERITY_TO_LEVEL.get(sev_val, "warning")
            elif status_val == "passed":
                result_entry["kind"] = "pass"
            elif status_val == "waived":
                result_entry["kind"] = "pass"
                result_entry["baselineState"] = "unchanged"
            elif status_val == "not_applicable":
                result_entry["kind"] = "notApplicable"
            results.append(result_entry)

        fw_name = evaluation.framework_name
        sarif_doc = {
            "version": "2.1.0",
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "DependencyControl Compliance",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://github.com/morzan1001/Dependency-Control",
                            "rules": rules,
                            "properties": {
                                "framework": fw_name,
                                "framework_version": evaluation.framework_version,
                                "inputs_fingerprint": evaluation.inputs_fingerprint,
                                **({"disclaimer": disclaimer} if disclaimer else {}),
                            },
                        },
                    },
                    "results": results,
                    "properties": {
                        "generated_at": evaluation.generated_at.isoformat(),
                        "scope_description": evaluation.scope_description,
                    },
                },
            ],
        }
        body = json.dumps(sarif_doc, indent=2, default=str).encode("utf-8")
        fw_key = (
            evaluation.framework_key if isinstance(evaluation.framework_key, str) else evaluation.framework_key.value
        )
        filename = build_filename(
            fw_key,
            report.scope,
            report.scope_id,
            report.requested_at,
            self.extension,
        )
        return body, filename, self.mime_type
