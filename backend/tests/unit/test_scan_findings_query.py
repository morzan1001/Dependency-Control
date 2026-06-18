"""Unit tests for the findings $match builder used by ``read_scan_findings``.

The endpoint composes a long aggregation pipeline; the only piece that varies
per request is the ``$match`` stage. Extracting the query builder lets us
verify the new ``waived`` filter (and the surrounding behaviour) without
spinning up a database or mocking the entire pipeline.
"""

from app.api.v1.endpoints.projects import (
    _build_scan_findings_match,
    _scan_findings_sort_stage,
)


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

    def test_hide_info_alone_excludes_info(self):
        match = _build_scan_findings_match("scan-1", hide_info=True)
        assert match["severity"] == {"$ne": "INFO"}

    def test_explicit_severity_wins_over_hide_info(self):
        # An explicit severity filter must not be silently clobbered by
        # hide_info; HIGH already excludes INFO (improvement audit #9).
        match = _build_scan_findings_match("scan-1", severity="high", hide_info=True)
        assert match["severity"] == "HIGH"

    def test_severity_info_with_hide_info_matches_nothing(self):
        # Contradiction: caller asked for INFO but also to hide INFO. Resolve to
        # an empty result rather than letting one option silently override.
        match = _build_scan_findings_match("scan-1", severity="info", hide_info=True)
        assert match["severity"] == {"$in": []}


class TestScanFindingsSortStage:
    """Every sort must carry a unique finding_id tiebreaker so $skip/$limit
    pagination is stable, and UI/legacy sort keys must map to real fields
    (improvement audit #9)."""

    def test_severity_sort_has_tiebreaker(self):
        stage = _scan_findings_sort_stage("severity", "desc")
        assert stage == {"$sort": {"severity_rank": -1, "component": 1, "finding_id": 1}}

    def test_component_sort_has_finding_id_tiebreaker(self):
        stage = _scan_findings_sort_stage("component", "asc")
        assert stage == {"$sort": {"component": 1, "finding_id": 1}}

    def test_legacy_vuln_id_maps_to_finding_id_without_duplicate_tiebreaker(self):
        stage = _scan_findings_sort_stage("vuln_id", "desc")
        assert stage == {"$sort": {"finding_id": -1}}

    def test_scanner_maps_to_first_scanner_scalar(self):
        stage = _scan_findings_sort_stage("scanner", "asc")
        assert stage == {"$sort": {"first_scanner": 1, "finding_id": 1}}

    def test_unknown_sort_by_falls_back_to_severity(self):
        stage = _scan_findings_sort_stage("does_not_exist", "desc")
        assert stage == {"$sort": {"severity_rank": -1, "component": 1, "finding_id": 1}}
