"""Unit tests for the findings $match/$sort/pipeline builders used by read_scan_findings."""

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
        # An explicit severity filter must not be clobbered by hide_info; HIGH already excludes INFO.
        match = _build_scan_findings_match("scan-1", severity="high", hide_info=True)
        assert match["severity"] == "HIGH"

    def test_severity_info_with_hide_info_matches_nothing(self):
        # Caller asked for INFO but also to hide it: resolve to an empty result rather than silently pick one.
        match = _build_scan_findings_match("scan-1", severity="info", hide_info=True)
        assert match["severity"] == {"$in": []}


class TestScanFindingsSortStage:
    """Every sort must end with the unique _id tiebreaker for stable pagination; finding_id isn't unique per scan (one CVE across N components)."""

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
    """_id must survive into the $sort for the tiebreaker but be excluded from the returned data."""

    def test_id_not_dropped_before_sort_and_excluded_from_data(self):
        from app.api.v1.endpoints.projects import _build_scan_findings_pipeline

        pipeline = _build_scan_findings_pipeline(
            {"scan_id": "s"}, sort_by="severity", sort_order="desc", skip=0, limit=50
        )
        sort_idx = next(i for i, st in enumerate(pipeline) if "$sort" in st)
        pre_sort_projects = [st["$project"] for st in pipeline[:sort_idx] if "$project" in st]
        assert all(p.get("_id") != 0 for p in pre_sort_projects)
        facet = next(st["$facet"] for st in pipeline if "$facet" in st)
        data_stages = facet["data"]
        data_project = next(st["$project"] for st in data_stages if "$project" in st)
        assert data_project.get("_id") == 0
        # first_scanner sort-helper must not leak into the response
        assert data_project.get("first_scanner") == 0


class TestScanFindingsDirectOnly:
    """direct_only drops findings on transitive dependencies but keeps direct and non-dependency findings."""

    def _pipeline(self, direct_only: bool):
        from app.api.v1.endpoints.projects import _build_scan_findings_pipeline

        return _build_scan_findings_pipeline(
            {"scan_id": "s"}, sort_by="severity", sort_order="desc", skip=0, limit=50, direct_only=direct_only
        )

    def test_direct_only_adds_direct_match_after_addfields(self):
        pipeline = self._pipeline(True)
        addfields_idx = next(i for i, st in enumerate(pipeline) if "$addFields" in st)
        direct_matches = [
            i for i, st in enumerate(pipeline) if st.get("$match", {}).get("direct") == {"$ne": False}
        ]
        assert direct_matches, "expected a $match on direct when direct_only is set"
        # Must run after direct is computed and before pagination.
        assert direct_matches[0] > addfields_idx
        facet_idx = next(i for i, st in enumerate(pipeline) if "$facet" in st)
        assert direct_matches[0] < facet_idx

    def test_default_keeps_transitive_findings(self):
        pipeline = self._pipeline(False)
        assert not any(st.get("$match", {}).get("direct") == {"$ne": False} for st in pipeline)
