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
    """Every sort must end with the UNIQUE _id as the terminal tiebreaker so
    $skip/$limit pagination is stable. finding_id is NOT unique per scan (one CVE
    across N components), so it cannot be the stabiliser (improvement audit #9 / MF3)."""

    def test_severity_sort_has_unique_tiebreaker(self):
        stage = _scan_findings_sort_stage("severity", "desc")
        assert stage == {"$sort": {"severity_rank": -1, "component": 1, "_id": 1}}

    def test_component_sort_has_unique_tiebreaker(self):
        stage = _scan_findings_sort_stage("component", "asc")
        assert stage == {"$sort": {"component": 1, "_id": 1}}

    def test_legacy_vuln_id_maps_to_finding_id_with_unique_tiebreaker(self):
        stage = _scan_findings_sort_stage("vuln_id", "desc")
        assert stage == {"$sort": {"finding_id": -1, "_id": 1}}

    def test_scanner_maps_to_first_scanner_scalar(self):
        stage = _scan_findings_sort_stage("scanner", "asc")
        assert stage == {"$sort": {"first_scanner": 1, "_id": 1}}

    def test_unknown_sort_by_falls_back_to_severity(self):
        stage = _scan_findings_sort_stage("does_not_exist", "desc")
        assert stage == {"$sort": {"severity_rank": -1, "component": 1, "_id": 1}}


class TestScanFindingsPipelineKeepsId:
    """_id must survive into the $sort so the terminal tiebreaker works, and be
    excluded only from the returned data (MF3)."""

    def test_id_not_dropped_before_sort_and_excluded_from_data(self):
        from app.api.v1.endpoints.projects import _build_scan_findings_pipeline

        pipeline = _build_scan_findings_pipeline({"scan_id": "s"}, sort_by="severity", sort_order="desc", skip=0, limit=50)
        # locate the pre-sort $project and the $sort
        sort_idx = next(i for i, st in enumerate(pipeline) if "$sort" in st)
        pre_sort_projects = [st["$project"] for st in pipeline[:sort_idx] if "$project" in st]
        # no pre-sort projection may drop _id
        assert all(p.get("_id") != 0 for p in pre_sort_projects)
        # the data sub-pipeline of the $facet must exclude _id from the output
        facet = next(st["$facet"] for st in pipeline if "$facet" in st)
        data_stages = facet["data"]
        assert any(st.get("$project", {}).get("_id") == 0 for st in data_stages)
