"""SARIF 2.1.0 renderer: each control maps to a rule and a result."""

import json

from app.models.compliance_report import ComplianceReport
from app.models.finding import Severity
from app.schemas.compliance import (
    ControlStatus,
    FrameworkEvaluation,
    ReportFormat,
)
from app.services.compliance.renderers.base import build_filename, coverage_statement

_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL.value: "error",
    Severity.HIGH.value: "error",
    Severity.MEDIUM.value: "warning",
    Severity.LOW.value: "note",
    Severity.NEGLIGIBLE.value: "note",
    Severity.INFO.value: "note",
    Severity.UNKNOWN.value: "warning",
}

# SARIF result properties per non-failing control status. "open" is SARIF's kind for a rule that
# was evaluated with insufficient information to decide whether a problem exists.
_STATUS_TO_RESULT: dict[str, dict[str, str]] = {
    ControlStatus.PASSED.value: {"kind": "pass"},
    ControlStatus.WAIVED.value: {"kind": "pass", "baselineState": "unchanged"},
    ControlStatus.NOT_APPLICABLE.value: {"kind": "notApplicable"},
    ControlStatus.NOT_EVALUATED.value: {"kind": "open"},
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
        disclaimer: str | None = None,
    ) -> tuple[bytes, str, str]:
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
            message = ctrl.description if not ctrl.status_reason else f"{ctrl.description} {ctrl.status_reason}"
            result_entry = {
                "ruleId": ctrl.control_id,
                "message": {"text": message},
            }
            if status_val == "failed":
                result_entry["level"] = _SEVERITY_TO_LEVEL.get(sev_val, "warning")
            else:
                result_entry.update(_STATUS_TO_RESULT.get(status_val, {}))
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
                        **(
                            {"coverage": coverage_statement(evaluation.coverage)}
                            if evaluation.coverage is not None
                            else {}
                        ),
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
