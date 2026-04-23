"""CSV renderer — one row per control."""

import csv
import io
from typing import Optional, Tuple

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import FrameworkEvaluation, ReportFormat
from app.services.compliance.renderers.base import build_filename


class CsvRenderer:
    format = ReportFormat.CSV
    mime_type = "text/csv"
    extension = "csv"

    FIELDS = [
        "control_id",
        "title",
        "status",
        "severity",
        "evidence_count",
        "waived",
        "remediation",
    ]

    def render(
        self,
        evaluation: FrameworkEvaluation,
        report: ComplianceReport,
        *,
        disclaimer: Optional[str] = None,
    ) -> Tuple[bytes, str, str]:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=self.FIELDS)
        writer.writeheader()
        for c in evaluation.controls:
            status_val = c.status if isinstance(c.status, str) else c.status.value
            sev_val = c.severity if isinstance(c.severity, str) else c.severity.value
            writer.writerow(
                {
                    "control_id": c.control_id,
                    "title": c.title,
                    "status": status_val,
                    "severity": sev_val,
                    # Sum both evidence lists: default evaluator populates
                    # evidence_finding_ids; custom evaluators (e.g. FIPS disallowed
                    # categories) emit evidence only in evidence_asset_bom_refs.
                    "evidence_count": (len(c.evidence_finding_ids) + len(c.evidence_asset_bom_refs)),
                    "waived": "true" if status_val == "waived" else "false",
                    "remediation": c.remediation,
                }
            )
        body = buf.getvalue().encode("utf-8")
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
