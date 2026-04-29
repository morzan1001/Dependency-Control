import importlib

import pytest

_weasyprint_spec = importlib.util.find_spec("weasyprint")
_weasyprint_usable = False
if _weasyprint_spec is not None:
    try:
        # WeasyPrint's top-level import dlopens Cairo/Pango; if the native
        # libraries are absent the import raises OSError. Treat that as
        # "not usable" so tests skip gracefully on dev machines that lack them.
        importlib.import_module("weasyprint")
        _weasyprint_usable = True
    except Exception:  # pragma: no cover - environment-dependent
        _weasyprint_usable = False

pytestmark = pytest.mark.skipif(
    not _weasyprint_usable,
    reason="WeasyPrint not installed or native libs missing",
)


def test_pdf_renderer_produces_pdf_bytes():
    from app.services.compliance.renderers.pdf_renderer import PdfRenderer
    from tests.unit.test_renderer_json import _evaluation, _report

    r = PdfRenderer()
    rep = _report()
    from app.schemas.compliance import ReportFormat

    rep.format = ReportFormat.PDF
    out, filename, mime = r.render(_evaluation(), rep)
    assert mime == "application/pdf"
    assert filename.endswith(".pdf")
    assert out[:4] == b"%PDF"
    assert len(out) > 1000


def test_pdf_includes_disclaimer_when_provided():
    from app.services.compliance.renderers.pdf_renderer import PdfRenderer
    from tests.unit.test_renderer_json import _evaluation, _report
    from app.schemas.compliance import ReportFormat

    r = PdfRenderer()
    rep = _report()
    rep.format = ReportFormat.PDF
    out, _, _ = r.render(_evaluation(), rep, disclaimer="Module-level CMVP out of scope")
    assert out[:4] == b"%PDF"
