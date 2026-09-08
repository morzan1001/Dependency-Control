"""PDF renderer: renders a Jinja2 template with evaluation data to PDF bytes via WeasyPrint."""

from pathlib import Path
from typing import Any

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import FrameworkEvaluation, ReportFormat
from app.services.compliance.renderers.base import build_filename, coverage_statement

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def _enum_value(value: Any) -> Any:
    return value if isinstance(value, str) else value.value


def build_template_context(
    evaluation: FrameworkEvaluation,
    report: ComplianceReport,
    disclaimer: str | None = None,
) -> dict[str, Any]:
    """Every name `base_report.html` reads. Importable without WeasyPrint's native stack, so a
    test can render the page the renderer renders instead of a hand-built stand-in that drifts."""
    return {
        "framework_key": _enum_value(evaluation.framework_key),
        "framework_name": evaluation.framework_name,
        "framework_version": evaluation.framework_version,
        "generated_at": evaluation.generated_at.isoformat(),
        "scope_description": evaluation.scope_description,
        "inputs_fingerprint": evaluation.inputs_fingerprint,
        "requested_by": report.requested_by,
        "disclaimer": disclaimer,
        "coverage_statement": coverage_statement(evaluation.coverage),
        "coverage_complete": evaluation.coverage is None or evaluation.coverage.complete,
        "summary": evaluation.summary,
        "controls": [
            {
                "control_id": c.control_id,
                "title": c.title,
                "description": c.description,
                "status": _enum_value(c.status),
                "severity": _enum_value(c.severity),
                "evidence_finding_ids": c.evidence_finding_ids,
                "evidence_asset_bom_refs": c.evidence_asset_bom_refs,
                "waiver_reasons": c.waiver_reasons,
                "remediation": c.remediation,
                "status_reason": c.status_reason,
            }
            for c in evaluation.controls
        ],
        "residual_risks": [
            {
                "control_id": r.control_id,
                "title": r.title,
                "severity": _enum_value(r.severity),
            }
            for r in evaluation.residual_risks
        ],
    }


class PdfRenderer:
    format = ReportFormat.PDF
    mime_type = "application/pdf"
    extension = "pdf"

    def render(
        self,
        evaluation: FrameworkEvaluation,
        report: ComplianceReport,
        *,
        disclaimer: str | None = None,
    ) -> tuple[bytes, str, str]:
        # Lazy imports so module import never fails on missing native libs.
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        from weasyprint import CSS, HTML

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        tpl = env.get_template("base_report.html")
        html = tpl.render(**build_template_context(evaluation, report, disclaimer))
        stylesheets = [CSS(filename=str(_TEMPLATE_DIR / "styles.css"))]
        pdf_bytes = HTML(
            string=html,
            base_url=str(_TEMPLATE_DIR),
        ).write_pdf(stylesheets=stylesheets)
        filename = build_filename(
            _enum_value(evaluation.framework_key),
            report.scope,
            report.scope_id,
            report.requested_at,
            self.extension,
        )
        return pdf_bytes, filename, self.mime_type
