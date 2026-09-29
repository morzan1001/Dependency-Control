"""CSV renderer — one row per control."""

import csv
import io
from typing import ClassVar

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import ControlStatus, FrameworkEvaluation, ReportFormat
from app.services.compliance.renderers.base import build_filename, coverage_statement


class CsvRenderer:
    format = ReportFormat.CSV
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

    @staticmethod
    def _framework_header(evaluation: FrameworkEvaluation) -> str:
        name = evaluation.framework_name or ""
        version = evaluation.framework_version or ""
        if name and version:
            return f"{name} ({version})"
        return name or version

    def render(
        self,
        evaluation: FrameworkEvaluation,
        report: ComplianceReport,
        *,
        disclaimer: str | None = None,
    ) -> tuple[bytes, str, str]:
        buf = io.StringIO()
        # Prepend disclaimers as '#' comment lines so a bare CSV export cannot be mistaken for a full pass.
        if disclaimer:
            buf.write(f"# Disclaimer: {disclaimer}\n")
            fw_header = self._framework_header(evaluation)
            if fw_header:
                buf.write(f"# Framework: {fw_header}\n")
            buf.write(f"# Generated: {evaluation.generated_at.isoformat()}\n")
        coverage = coverage_statement(evaluation.coverage)
        if coverage:
            buf.write(f"# Coverage: {coverage}\n")
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
        body = buf.getvalue().encode("utf-8")
        filename = build_filename(
            evaluation.framework_key,
            report.scope,
            report.scope_id,
            report.requested_at,
            self.extension,
        )
        return body, filename, self.mime_type
