import csv
import io
from typing import ClassVar

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import ControlStatus, FrameworkEvaluation
from app.services.compliance.renderers.base import coverage_statement
from app.services.inventory.csv_stream import UTF8_BOM, format_cell


class CsvRenderer:
    mime_type = "text/csv; charset=utf-8"
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
        writer = csv.writer(buf)
        notes = [f"Disclaimer: {disclaimer}"] if disclaimer else []
        notes += [
            f"Framework: {evaluation.framework_name} ({evaluation.framework_version})",
            f"Generated: {evaluation.generated_at.isoformat()}",
            f"Scope: {evaluation.scope_description}",
            f"Fingerprint: {evaluation.inputs_fingerprint}",
            f"Coverage: {coverage_statement(evaluation.coverage)}",
        ]
        # One quoted cell per note, so a comma in a project or team name cannot start a formula cell.
        writer.writerows([f"# {note}"] for note in notes)
        writer.writerow(self.FIELDS)
        for c in evaluation.controls:
            cells = (
                c.control_id,
                c.title,
                c.status,
                c.severity,
                c.evidence_count,
                c.status == ControlStatus.WAIVED,
                c.status_reason,
                c.remediation,
            )
            writer.writerow([format_cell(cell) for cell in cells])
        return (UTF8_BOM + buf.getvalue()).encode("utf-8")
