"""
PDF renderer using WeasyPrint.

Loads a Jinja2 template + CSS, substitutes evaluation data, calls WeasyPrint
to produce A4 PDF bytes. Template path is relative to the file so it works
the same way inside Docker and locally.
"""

from pathlib import Path
from typing import Optional, Tuple

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import FrameworkEvaluation, ReportFormat
from app.services.compliance.renderers.base import build_filename

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


class PdfRenderer:
    format = ReportFormat.PDF
    mime_type = "application/pdf"
    extension = "pdf"

    def render(
        self,
        evaluation: FrameworkEvaluation,
        report: ComplianceReport,
        *,
        disclaimer: Optional[str] = None,
    ) -> Tuple[bytes, str, str]:
        # Lazy imports so module import never fails on missing native libs.
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        from weasyprint import CSS, HTML

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        tpl = env.get_template("base_report.html")
        fw_key = (
            evaluation.framework_key if isinstance(evaluation.framework_key, str) else evaluation.framework_key.value
        )
        context = {
            "framework_key": fw_key,
            "framework_name": evaluation.framework_name,
            "framework_version": evaluation.framework_version,
            "generated_at": evaluation.generated_at.isoformat(),
            "scope_description": evaluation.scope_description,
            "inputs_fingerprint": evaluation.inputs_fingerprint,
            "requested_by": report.requested_by,
            "disclaimer": disclaimer,
            "summary": evaluation.summary,
            "controls": [
                {
                    "control_id": c.control_id,
                    "title": c.title,
                    "description": c.description,
                    "status": c.status if isinstance(c.status, str) else c.status.value,
                    "severity": c.severity if isinstance(c.severity, str) else c.severity.value,
                    "evidence_finding_ids": c.evidence_finding_ids,
                    "evidence_asset_bom_refs": c.evidence_asset_bom_refs,
                    "waiver_reasons": c.waiver_reasons,
                    "remediation": c.remediation,
                }
                for c in evaluation.controls
            ],
            "residual_risks": [
                {
                    "control_id": r.control_id,
                    "title": r.title,
                    "severity": r.severity if isinstance(r.severity, str) else r.severity.value,
                }
                for r in evaluation.residual_risks
            ],
        }
        html = tpl.render(**context)
        stylesheets = [CSS(filename=str(_TEMPLATE_DIR / "styles.css"))]
        pdf_bytes = HTML(
            string=html,
            base_url=str(_TEMPLATE_DIR),
        ).write_pdf(stylesheets=stylesheets)
        filename = build_filename(
            fw_key,
            report.scope,
            report.scope_id,
            report.requested_at,
            self.extension,
        )
        return pdf_bytes, filename, self.mime_type
