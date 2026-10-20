from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import FrameworkEvaluation
from app.services.compliance.renderers.base import coverage_statement

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
_ENV = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True, undefined=StrictUndefined)


def build_template_context(
    evaluation: FrameworkEvaluation,
    report: ComplianceReport,
    disclaimer: str | None = None,
) -> dict[str, Any]:
    """Must stay importable without WeasyPrint's native stack so tests render this exact context."""
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


def report_html(evaluation: FrameworkEvaluation, report: ComplianceReport, disclaimer: str | None = None) -> str:
    return _ENV.get_template("base_report.html").render(**build_template_context(evaluation, report, disclaimer))


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
        # Lazy import so module import never fails on missing native libs.
        from weasyprint import CSS, HTML

        html = report_html(evaluation, report, disclaimer)
        stylesheets = [CSS(filename=str(_TEMPLATE_DIR / "styles.css"))]
        pdf_bytes: bytes = HTML(string=html, base_url=str(_TEMPLATE_DIR)).write_pdf(stylesheets=stylesheets)
        return pdf_bytes
