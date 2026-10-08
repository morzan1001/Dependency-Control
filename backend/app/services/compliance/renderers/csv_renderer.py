"""CSV renderer — one row per control."""

import csv
import io
from typing import ClassVar

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import ControlStatus, FrameworkEvaluation
from app.services.compliance.renderers.base import coverage_statement


class CsvRenderer:
    mime_type = "text/csv"
    extension = "csv"

    FIELDS: ClassVar[list[str]] = [
        "control_id",
        "title",
        "status",
        "severity",
        "evidence_count",
        "waived",
        "status_reason",
        "remediation",
    ]

    def render(
        self,
        evaluation: FrameworkEvaluation,
        report: ComplianceReport,
        *,
        disclaimer: str | None = None,
    ) -> bytes:
        buf = io.StringIO()
        # Prepend disclaimers as '#' comment lines so a bare CSV export cannot be mistaken for a full pass.
        if disclaimer:
            buf.write(f"# Disclaimer: {disclaimer}\n")
            buf.write(f"# Framework: {evaluation.framework_name} ({evaluation.framework_version})\n")
            buf.write(f"# Generated: {evaluation.generated_at.isoformat()}\n")
        buf.write(f"# Coverage: {coverage_statement(evaluation.coverage)}\n")
        writer = csv.DictWriter(buf, fieldnames=self.FIELDS)
        writer.writeheader()
        for c in evaluation.controls:
            writer.writerow(
                {
                    "control_id": c.control_id,
                    "title": c.title,
                    "status": c.status,
                    "severity": c.severity,
                    # Evidence may land in either list depending on the evaluator.
                    "evidence_count": (len(c.evidence_finding_ids) + len(c.evidence_asset_bom_refs)),
                    "waived": "true" if c.status == ControlStatus.WAIVED else "false",
                    "status_reason": c.status_reason or "",
                    "remediation": c.remediation,
                }
            )
        return buf.getvalue().encode("utf-8")
