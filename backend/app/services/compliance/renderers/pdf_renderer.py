"""PDF renderer: renders a Jinja2 template with evaluation data to PDF bytes via WeasyPrint."""

from pathlib import Path
from typing import Any

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import FrameworkEvaluation
from app.services.compliance.renderers.base import coverage_statement

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def build_template_context(
    evaluation: FrameworkEvaluation,
    report: ComplianceReport,
    disclaimer: str | None = None,
) -> dict[str, Any]:
    """Every name `base_report.html` reads. Importable without WeasyPrint's native stack, so a
    test can render the page the renderer renders instead of a hand-built stand-in that drifts."""
    return {
        "framework_name": evaluation.framework_name,
        "framework_version": evaluation.framework_version,
        "generated_at": evaluation.generated_at.isoformat(),
        "scope_description": evaluation.scope_description,
        "inputs_fingerprint": evaluation.inputs_fingerprint,
        "requested_by": report.requested_by,
        "disclaimer": disclaimer,
        "coverage_statement": coverage_statement(evaluation.coverage),
        "coverage_complete": evaluation.coverage.complete,
        "summary": evaluation.summary,
        "controls": evaluation.controls,
        "residual_risks": evaluation.residual_risks,
    }


class PdfRenderer:
    mime_type = "application/pdf"
    extension = "pdf"

    def render(
        self,
        evaluation: FrameworkEvaluation,
        report: ComplianceReport,
        *,
        disclaimer: str | None = None,
    ) -> bytes:
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
        pdf_bytes: bytes = HTML(string=html, base_url=str(_TEMPLATE_DIR)).write_pdf(stylesheets=stylesheets)
        return pdf_bytes
