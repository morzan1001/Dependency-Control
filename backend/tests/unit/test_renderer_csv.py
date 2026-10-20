import csv
import io

from app.schemas.compliance import ControlStatus, ReportFormat
from app.services.compliance.renderers.csv_renderer import CsvRenderer
from tests.unit.test_renderer_json import _evaluation, _report


def _text(out: bytes) -> str:
    return out.decode("utf-8-sig")


def _table(out: bytes) -> list[str]:
    return [ln for ln in _text(out).splitlines() if not ln.startswith("#")]


def test_csv_renderer_outputs_rows_per_control():
    r = CsvRenderer()
    rep = _report()
    rep.format = ReportFormat.CSV
    rows = list(csv.DictReader(_table(r.render(_evaluation(), rep))))
    assert len(rows) == 1
    assert rows[0]["control_id"] == "NIST-131A-01"
    assert rows[0]["status"] == "failed"
    assert rows[0]["severity"] == "HIGH"
    # f1 is the finding on asset a1, so the two are one piece of evidence.
    assert rows[0]["evidence_count"] == "1"


def test_csv_marks_a_waived_control_in_the_waived_column():
    evaluation = _evaluation()
    waived = evaluation.controls[0].model_copy(
        update={"control_id": "NIST-131A-02", "status": ControlStatus.WAIVED, "waiver_reasons": ["accepted risk"]}
    )
    evaluation.controls = [*evaluation.controls, waived]
    rep = _report()
    rep.format = ReportFormat.CSV
    out = CsvRenderer().render(evaluation, rep)
    rows = list(csv.DictReader(_table(out)))
    assert [r["status"] for r in rows] == ["failed", "waived"]
    assert [r["waived"] for r in rows] == ["false", "true"]


def test_csv_header_present():
    r = CsvRenderer()
    rep = _report()
    rep.format = ReportFormat.CSV
    out = r.render(_evaluation(), rep)
    first_line = _table(out)[0]
    assert "control_id" in first_line
    assert "title" in first_line
    assert "remediation" in first_line


def test_csv_renderer_includes_disclaimer_comment():
    """The disclaimer is prepended as a CSV comment block so the export does not read as a certification pass."""
    r = CsvRenderer()
    rep = _report()
    rep.format = ReportFormat.CSV
    disclaimer = (
        "Algorithm-level conformance only. Module-level CMVP (FIPS 140-3) validation is out of scope of this tool."
    )
    out = r.render(_evaluation(), rep, disclaimer=disclaimer)
    text = _text(out)
    lines = text.splitlines()
    assert lines[0].startswith("# Disclaimer:")
    assert "Algorithm-level conformance only" in lines[0]
    comment_block = [ln for ln in lines if ln.startswith("#")]
    assert any("# Framework:" in ln for ln in comment_block)
    assert any("# Generated:" in ln for ln in comment_block)
    rows = list(csv.DictReader(_table(out)))
    assert len(rows) == 1
    assert rows[0]["control_id"] == "NIST-131A-01"


def test_csv_renderer_omits_disclaimer_when_none():
    r = CsvRenderer()
    rep = _report()
    rep.format = ReportFormat.CSV
    out = r.render(_evaluation(), rep, disclaimer=None)
    assert "# Disclaimer:" not in _text(out)


def test_the_csv_starts_with_the_byte_order_mark_excel_needs_to_read_it_as_utf8():
    out = CsvRenderer().render(_evaluation(), _report())

    assert out.startswith("\ufeff".encode())
    assert CsvRenderer.mime_type == "text/csv; charset=utf-8"


def test_a_cell_a_spreadsheet_would_run_as_a_formula_is_escaped():
    evaluation = _evaluation()
    evaluation.controls = [evaluation.controls[0].model_copy(update={"title": '=HYPERLINK("http://x")'})]

    [row] = list(csv.DictReader(_table(CsvRenderer().render(evaluation, _report()))))

    assert row["title"] == '\'=HYPERLINK("http://x")'


def _notes(out: bytes) -> list[list[str]]:
    return [row for row in csv.reader(io.StringIO(_text(out))) if row and row[0].startswith("#")]


def test_a_framework_without_a_disclaimer_still_names_what_the_export_covers():
    notes = _notes(CsvRenderer().render(_evaluation(), _report(), disclaimer=None))

    assert [note[0].split(":")[0] for note in notes] == [
        "# Framework",
        "# Generated",
        "# Scope",
        "# Fingerprint",
        "# Coverage",
    ]
    assert ["# Scope: project 'x'"] in notes
    assert ["# Fingerprint: sha256:abc"] in notes


def test_a_comma_in_a_scope_name_cannot_split_its_note_into_a_formula_cell():
    evaluation = _evaluation()
    evaluation.scope_description = "project 'a,=1+1'"

    notes = _notes(CsvRenderer().render(evaluation, _report()))

    assert ["# Scope: project 'a,=1+1'"] in notes
