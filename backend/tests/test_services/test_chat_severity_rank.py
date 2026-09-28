"""Chat tools rank severities by the one canonical table."""

from app.services.chat.tools.registry import _rank_findings


def test_negligible_findings_rank_above_info_ones():
    findings = [{"severity": "INFO"}, {"severity": "NEGLIGIBLE"}, {"severity": "CRITICAL"}]

    _rank_findings(findings)

    assert [f["severity"] for f in findings] == ["CRITICAL", "NEGLIGIBLE", "INFO"]
