"""Unit tests for the findings $match builder used by ``read_scan_findings``.

The endpoint composes a long aggregation pipeline; the only piece that varies
per request is the ``$match`` stage. Extracting the query builder lets us
verify the new ``waived`` filter (and the surrounding behaviour) without
spinning up a database or mocking the entire pipeline.
"""

from app.api.v1.endpoints.projects import _build_scan_findings_match


class TestBuildScanFindingsMatch:
    def test_minimal_query_only_filters_by_scan_id(self):
        match = _build_scan_findings_match("scan-1")
        assert match == {"scan_id": "scan-1"}

    def test_waived_true_filters_for_waived_findings(self):
        match = _build_scan_findings_match("scan-1", waived=True)
        assert match["waived"] is True

    def test_waived_false_filters_for_active_findings(self):
        match = _build_scan_findings_match("scan-1", waived=False)
        assert match["waived"] is False

    def test_waived_none_omits_filter_entirely(self):
        match = _build_scan_findings_match("scan-1", waived=None)
        assert "waived" not in match

    def test_other_filters_still_compose(self):
        match = _build_scan_findings_match(
            "scan-1",
            severity="high",
            type="vulnerability",
            waived=False,
        )
        assert match["scan_id"] == "scan-1"
        assert match["severity"] == "HIGH"
        assert match["type"] == "vulnerability"
        assert match["waived"] is False

    def test_hide_info_overrides_severity(self):
        # Pre-existing behaviour: ``hide_info`` is mutually exclusive with an
        # explicit ``severity`` filter and intentionally wins. Locking it in so
        # an unrelated refactor can't silently flip the precedence.
        match = _build_scan_findings_match("scan-1", severity="high", hide_info=True)
        assert match["severity"] == {"$ne": "INFO"}
