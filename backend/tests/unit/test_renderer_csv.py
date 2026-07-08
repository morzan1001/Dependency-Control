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
    # evidence_count must sum finding_ids and asset_bom_refs, since some evaluators emit only the latter.
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
    """A framework disclaimer must be prepended as a CSV comment block so the export isn't read as a full certification pass."""
    r = CsvRenderer()
    rep = _report()
    rep.format = ReportFormat.CSV
    disclaimer = (
        "Algorithm-level conformance only. Module-level CMVP (FIPS 140-3) validation is out of scope of this tool."
    )
    out, _, _ = r.render(_evaluation(), rep, disclaimer=disclaimer)
    text = out.decode("utf-8")
    lines = text.splitlines()
    assert lines[0].startswith("# Disclaimer:")
    assert "Algorithm-level conformance only" in lines[0]
    comment_block = [ln for ln in lines if ln.startswith("#")]
    assert any("# Framework:" in ln for ln in comment_block)
    assert any("# Generated:" in ln for ln in comment_block)
    header_idx = next(i for i, ln in enumerate(lines) if ln.startswith("control_id"))
    body = "\n".join(lines[header_idx:])
    reader = csv.DictReader(io.StringIO(body))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["control_id"] == "NIST-131A-01"


def test_csv_renderer_omits_disclaimer_when_none():
    r = CsvRenderer()
    rep = _report()
    rep.format = ReportFormat.CSV
    out, _, _ = r.render(_evaluation(), rep, disclaimer=None)
    text = out.decode("utf-8")
    assert not text.startswith("#")
    assert text.splitlines()[0].startswith("control_id")
