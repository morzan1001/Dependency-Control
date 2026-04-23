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
    assert rows[0]["evidence_count"] == "1"


def test_csv_header_present():
    r = CsvRenderer()
    rep = _report()
    rep.format = ReportFormat.CSV
    out, _, _ = r.render(_evaluation(), rep)
    first_line = out.decode("utf-8").splitlines()[0]
    assert "control_id" in first_line
    assert "title" in first_line
    assert "remediation" in first_line
