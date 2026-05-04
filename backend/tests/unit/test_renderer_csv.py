import csv
import io

from app.schemas.compliance import ReportFormat
from app.services.compliance.renderers.csv_renderer import CsvRenderer
from tests.unit.test_renderer_json import _evaluation, _report


def test_csv_renderer_outputs_rows_per_control():
    r = CsvRenderer()
    rep = _report()
    rep.format = ReportFormat.CSV
    out, filename, mime = r.render(_evaluation(), rep)
    assert mime == "text/csv"
    assert filename.endswith(".csv")
    reader = csv.DictReader(io.StringIO(out.decode("utf-8")))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["control_id"] == "NIST-131A-01"
    assert rows[0]["status"] == "failed"
    assert rows[0]["severity"] == "HIGH"
    # Fixture has evidence_finding_ids=["f1"] + evidence_asset_bom_refs=["a1"].
    # Custom evaluators (e.g. FIPS disallowed categories) emit evidence only
    # in evidence_asset_bom_refs — the CSV renderer must sum both lists so
    # FAILED controls with real evidence don't show as "0".
    assert rows[0]["evidence_count"] == "2"


def test_csv_header_present():
    r = CsvRenderer()
    rep = _report()
    rep.format = ReportFormat.CSV
    out, _, _ = r.render(_evaluation(), rep)
    first_line = out.decode("utf-8").splitlines()[0]
    assert "control_id" in first_line
    assert "title" in first_line
    assert "remediation" in first_line


def test_csv_renderer_includes_disclaimer_comment():
    """FIPS/ISO frameworks carry a disclaimer (e.g. "algorithm-level
    conformance only; module-level CMVP out of scope"). The PDF/JSON/SARIF
    renderers embed it; CSV used to silently drop it, so a bare CSV export
    read like a full certification pass. Now we prepend it as a CSV comment
    line so humans see it at a glance and pandas/Excel skip it by default."""
    r = CsvRenderer()
    rep = _report()
    rep.format = ReportFormat.CSV
    disclaimer = (
        "Algorithm-level conformance only. Module-level CMVP (FIPS 140-3) validation is out of scope of this tool."
    )
    out, _, _ = r.render(_evaluation(), rep, disclaimer=disclaimer)
    text = out.decode("utf-8")
    lines = text.splitlines()
    # Disclaimer must come BEFORE the header row.
    assert lines[0].startswith("# Disclaimer:")
    assert "Algorithm-level conformance only" in lines[0]
    # Framework + generation metadata should also land in the comment block.
    comment_block = [ln for ln in lines if ln.startswith("#")]
    assert any("# Framework:" in ln for ln in comment_block)
    assert any("# Generated:" in ln for ln in comment_block)
    # Header and rows must still be present and parseable after the comments.
    header_idx = next(i for i, ln in enumerate(lines) if ln.startswith("control_id"))
    body = "\n".join(lines[header_idx:])
    reader = csv.DictReader(io.StringIO(body))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["control_id"] == "NIST-131A-01"


def test_csv_renderer_omits_disclaimer_when_none():
    """When no framework disclaimer is supplied the output must remain a
    plain CSV — header on line 1, no leading comment."""
    r = CsvRenderer()
    rep = _report()
    rep.format = ReportFormat.CSV
    out, _, _ = r.render(_evaluation(), rep, disclaimer=None)
    text = out.decode("utf-8")
    assert not text.startswith("#")
    assert text.splitlines()[0].startswith("control_id")
