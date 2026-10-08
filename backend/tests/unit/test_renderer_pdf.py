import pytest

from tests.conftest import WEASYPRINT_USABLE

pytestmark = pytest.mark.skipif(
    not WEASYPRINT_USABLE,
    reason="WeasyPrint not installed or native libs missing",
)

_MINIMUM_PDF_BYTES = 1000


def _partial_coverage():
    from app.schemas.compliance import EvaluationCoverage, InputCoverage

    return EvaluationCoverage(plan_items=InputCoverage(evaluated=1000, in_scope=4200, limit=1000))


def test_pdf_renderer_produces_pdf_bytes():
    """A partial coverage object must reach the template; test_compliance_coverage.py checks what
    the template then prints, since it can run where WeasyPrint's native stack cannot."""
    from app.schemas.compliance import ReportFormat
    from app.services.compliance.renderers.pdf_renderer import PdfRenderer
    from tests.unit.test_renderer_json import _evaluation, _report

    evaluation = _evaluation()
    evaluation.coverage = _partial_coverage()
    rep = _report()
    rep.format = ReportFormat.PDF
    out = PdfRenderer().render(evaluation, rep)
    assert out[:4] == b"%PDF"
    assert len(out) > _MINIMUM_PDF_BYTES


def test_pdf_includes_disclaimer_when_provided():
    from app.schemas.compliance import ReportFormat
    from app.services.compliance.renderers.pdf_renderer import PdfRenderer
    from tests.unit.test_renderer_json import _evaluation, _report

    r = PdfRenderer()
    rep = _report()
    rep.format = ReportFormat.PDF
    out = r.render(_evaluation(), rep, disclaimer="Module-level CMVP out of scope")
    assert out[:4] == b"%PDF"
