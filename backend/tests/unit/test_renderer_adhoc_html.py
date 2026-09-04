"""The ad-hoc HTML report escapes untrusted SBOM content and hides no input from the reader."""

from markupsafe import escape

from app.schemas.adhoc import AdhocAnalyzeResponse, AnalyzerReport
from app.services.analysis.adhoc import _STAGE_NOTES
from app.services.analysis.adhoc_report import _FINDING_ROW_CAP, render_adhoc_html

_HOSTILE_COMPONENT = "<script>alert('xss')</script>"
_HOSTILE_DESCRIPTION = "<img src=x onerror=alert(1)>"
_HOSTILE_SEVERITY = '" onload="alert(1)'
_UNKNOWN_ANALYZER = "unknown analyzer"
_EMPTY_PAYLOAD = "empty payload"
_FIRST_FAILURE = "SBOM #1: connection reset"
_SECOND_FAILURE = "SBOM #2: 503 from upstream"
_PARSE_FAILURE = "could not be parsed: unsupported document"
_WAIVED_COUNT = 2
_OVER_THE_CAP = _FINDING_ROW_CAP + 1


def _finding(**overrides):
    base = {
        "id": "requests:2.31.0",
        "type": "vulnerability",
        "severity": "CRITICAL",
        "component": "requests",
        "version": "2.31.0",
        "description": "demo advisory",
        "scanners": ["osv"],
        "waived": False,
    }
    base.update(overrides)
    return base


def _result(**overrides):
    base = {
        "findings": [_finding()],
        "analyzers": AnalyzerReport(
            ran=["osv"],
            skipped={"grype": "off by default", "sbomm": _UNKNOWN_ANALYZER, "kics": _EMPTY_PAYLOAD},
            errored={"trivy": [_FIRST_FAILURE, _SECOND_FAILURE]},
        ),
        "waivers_applied": "global",
        "waived_count": _WAIVED_COUNT,
        "truncated": True,
    }
    base.update(overrides)
    return AdhocAnalyzeResponse(**base)


def test_render_produces_a_complete_html_document():
    html = render_adhoc_html(_result())

    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html
    assert "requests" in html
    assert "<style>" in html, "the stylesheet must be inlined, not linked"


def test_every_reason_an_analyzer_failed_for_is_rendered():
    """``errored`` keeps one reason per input; a report showing the last one hides the rest."""
    html = render_adhoc_html(_result())

    assert _FIRST_FAILURE in html
    assert _SECOND_FAILURE in html


def test_skip_reasons_distinguish_an_unknown_analyzer_from_an_empty_payload():
    html = render_adhoc_html(_result())

    assert _UNKNOWN_ANALYZER in html
    assert _EMPTY_PAYLOAD in html


def test_an_input_the_parser_could_not_read_is_visible():
    """An unreadable SBOM absent from the report reads as a clean bill of health for it."""
    result = _result(
        findings=[],
        analyzers=AnalyzerReport(ran=["osv"], skipped_inputs={"sbom#1": _PARSE_FAILURE}),
    )

    html = render_adhoc_html(result)

    assert "sbom#1" in html
    assert _PARSE_FAILURE in html


def test_the_report_says_what_left_the_process_and_which_policy_graded_it():
    """Egress and the grading policy are things the findings themselves cannot show."""
    result = _result(analyzers=AnalyzerReport(ran=list(_STAGE_NOTES), notes=dict(_STAGE_NOTES)))

    html = render_adhoc_html(result)

    for name, note in _STAGE_NOTES.items():
        assert name in html
        assert str(escape(note)) in html


def test_truncation_and_waivers_are_visible():
    html = render_adhoc_html(_result())

    assert "Result truncated:" in html
    assert f"global ({_WAIVED_COUNT} finding(s) waived)" in html


def test_a_findings_table_cut_to_the_row_cap_says_so():
    result = _result(findings=[_finding(id=str(index)) for index in range(_OVER_THE_CAP)])

    html = render_adhoc_html(result)

    assert f"Findings ({_FINDING_ROW_CAP} of {_OVER_THE_CAP})" in html


def test_findings_are_ordered_most_severe_first():
    result = _result(
        findings=[
            _finding(id="low", severity="LOW", component="low-component"),
            _finding(id="critical", severity="CRITICAL", component="critical-component"),
        ]
    )

    html = render_adhoc_html(result)

    assert html.index("critical-component") < html.index("low-component")


def test_sbom_content_is_html_escaped():
    result = _result(
        findings=[_finding(component=_HOSTILE_COMPONENT, description=_HOSTILE_DESCRIPTION, severity="HIGH")]
    )

    html = render_adhoc_html(result)

    assert "<script>alert" not in html
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in html
    # MarkupSafe leaves ``onerror=alert(1)`` alone; the angle brackets are what disarms it.
    assert "<img" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_a_hostile_severity_cannot_escape_its_class_attribute():
    result = _result(findings=[_finding(severity=_HOSTILE_SEVERITY)])

    html = render_adhoc_html(result)

    assert 'onload="alert(1)' not in html
    assert "&#34; onload=&#34;alert(1)" in html


def test_empty_result_renders():
    assert "<!DOCTYPE html>" in render_adhoc_html(AdhocAnalyzeResponse())
