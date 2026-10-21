import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.v1.helpers.analytics import (
    build_priority_reasons,
    calculate_impact_score,
    impact_pre_score,
    select_impact_candidates,
    severity_counts_from_details,
)
from app.core.constants import (
    BLAST_RADIUS_THRESHOLD,
    EXPLOIT_MATURITY_BOOST,
    IMPACT_AGE_BOOST,
    IMPACT_MAX_SCORE_BOOST,
)
from app.core.permissions import ALL_PERMISSIONS
from app.models.user import User
from app.schemas.analytics import SeverityBreakdown, ThreatIntelFields
from app.schemas.enrichment import VulnerabilityEnrichment
from tests.helpers.analytics_scope import projections

MODULE = "app.api.v1.endpoints.analytics.risk"


def _admin_user() -> User:
    return User(
        id="admin-1",
        username="admin",
        email="admin@test.com",
        permissions=list(ALL_PERMISSIONS),
    )


_ARRAY_ACCUMULATORS = ("$push", "$addToSet")


def _iter_array_accumulators(pipeline: list[dict[str, Any]]):
    """Both operators: risk.py collects with $addToSet only, so a $push-only check would iterate zero times."""
    for stage in pipeline:
        group = stage.get("$group")
        if not group:
            continue
        for acc_name, acc_expr in group.items():
            if not isinstance(acc_expr, dict):
                continue
            for operator in _ARRAY_ACCUMULATORS:
                if operator in acc_expr:
                    yield acc_name, acc_expr[operator]


def _group_stage(pipeline: list[dict[str, Any]]) -> dict[str, Any]:
    for stage in pipeline:
        if "$group" in stage:
            return stage["$group"]
    raise AssertionError("pipeline has no $group stage")


def _assert_counts_come_from_advisories(pipeline: list[dict[str, Any]]) -> None:
    """finding_id is only component:version, so counts derive from details.vulnerabilities in Python, not $group."""
    group = _group_stage(pipeline)
    for sev in ("critical", "high", "medium", "low"):
        assert sev not in group and f"{sev}_ids" not in group, f"{sev} must not be counted in Mongo"
    slim = None
    for stage in pipeline:
        if "$group" in stage:
            break
        proj = stage.get("$project") or {}
        if isinstance(proj.get("details"), dict):
            slim = proj["details"]
    assert slim is not None, "details must be slimmed before $group"
    vmap = slim.get("vulnerabilities", {}).get("$map", {}).get("in", {})
    assert "id" in vmap and "severity" in vmap, "slimmed advisories must keep id + severity"


def _sliced_fields_after_group(pipeline: list[dict[str, Any]]) -> list[str]:
    seen_group = False
    sliced: list[str] = []
    for stage in pipeline:
        if "$group" in stage:
            seen_group = True
            continue
        if not seen_group:
            continue
        project = stage.get("$project")
        if not project:
            continue
        for field, spec in project.items():
            if isinstance(spec, dict) and "$slice" in spec:
                sliced.append(field)
    return sliced


def _details_is_slimmed_before_group(pipeline: list[dict[str, Any]]) -> bool:
    for stage in pipeline:
        if "$group" in stage:
            return False
        project = stage.get("$project")
        if not project:
            continue
        details_spec = project.get("details")
        if isinstance(details_spec, dict):
            keys = set(details_spec.keys())
            if keys and keys <= {"fixed_version", "vulnerabilities"}:
                return True
    return False


def _answer(rows: list[dict[str, Any]], pipeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The counted read gets the counts of `rows`, ranked by pre-score as the impact read sorts; any other gets `rows`."""
    if not any("$unwind" in stage for stage in pipeline):
        return rows
    counted = []
    for row in rows:
        counts = severity_counts_from_details(row["details_list"])
        counted.append(
            {
                **{key: row[key] for key in ("_id", "project_ids", "first_seen")},
                "counts": counts,
                "cve_count": sum(counts.values()),
                "pre_score": impact_pre_score(counts, len(row["project_ids"])),
            }
        )
    return sorted(counted, key=lambda group: -group["pre_score"])


def _run_impact(
    agg_results: list[dict[str, Any]],
    limit: int = 20,
    enrich: Any = None,
    read: int = 0,
) -> tuple[Any, list[dict[str, Any]]]:
    """``read`` picks the findings read returned: 0 ranks the counted groups, 1 fetches the candidates' advisories."""
    from app.api.v1.endpoints.analytics.risk import get_impact_analysis

    user = _admin_user()
    db = MagicMock()
    captured: list[list[dict[str, Any]]] = []

    async def _fake_get_user_projects(_u, _d):
        return projections(["proj-1"])

    async def _fake_get_projects_with_scans(_pids, _d, **_kw):
        return {"proj-1": "Project 1"}, ["scan-latest"]

    async def _fake_aggregate(pipeline, **_kwargs):
        captured.append(pipeline)
        return _answer(agg_results, pipeline)

    mock_finding_repo = MagicMock()
    mock_finding_repo.aggregate = _fake_aggregate

    with (
        patch(f"{MODULE}.get_user_projects", new=_fake_get_user_projects),
        patch(f"{MODULE}.get_projects_with_scans", new=_fake_get_projects_with_scans),
        patch(f"{MODULE}.FindingRepository", return_value=mock_finding_repo),
        patch(f"{MODULE}.vulnerability_enrichment_service.enrich_cves", new=enrich or _no_enrichment),
    ):
        response = asyncio.run(get_impact_analysis(current_user=user, db=db, limit=limit))

    assert len(captured) > read, "the findings read asked for never ran for /impact"
    return response, captured[read]


async def _no_enrichment(_cves: list[str]) -> tuple[dict[str, Any], list[str]]:
    return {}, []


def _run_hotspots(
    agg_results: list[dict[str, Any]],
    limit: int = 20,
    sort_by: str = "risk",
    skip: int = 0,
    enrich: Any = _no_enrichment,
    type_rows: Any = None,
) -> tuple[Any, list[dict[str, Any]]]:
    from app.api.v1.endpoints.analytics.risk import get_vulnerability_hotspots

    user = _admin_user()
    db = MagicMock()
    captured: list[list[dict[str, Any]]] = []

    async def _fake_get_user_projects(_u, _d):
        return projections(["proj-1"])

    async def _fake_get_projects_with_scans(_pids, _d, **_kw):
        return {"proj-1": "Project 1"}, ["scan-latest"]

    async def _fake_finding_aggregate(pipeline, **_kwargs):
        captured.append(pipeline)
        return _answer(agg_results, pipeline)

    mock_finding_repo = MagicMock()
    mock_finding_repo.aggregate = _fake_finding_aggregate

    mock_dep_repo = MagicMock()
    mock_dep_repo.aggregate = type_rows or AsyncMock(return_value=[])

    with (
        patch(f"{MODULE}.get_user_projects", new=_fake_get_user_projects),
        patch(f"{MODULE}.get_projects_with_scans", new=_fake_get_projects_with_scans),
        patch(f"{MODULE}.FindingRepository", return_value=mock_finding_repo),
        patch(f"{MODULE}.DependencyRepository", return_value=mock_dep_repo),
        patch(f"{MODULE}.vulnerability_enrichment_service.enrich_cves", new=enrich),
    ):
        response = asyncio.run(
            get_vulnerability_hotspots(
                current_user=user,
                db=db,
                skip=skip,
                limit=limit,
                sort_by=sort_by,
                sort_order="desc",
            )
        )

    assert captured, "finding aggregate() was never called for /hotspots"
    return response, captured[0]


def _advisory_read_of_impact() -> list[dict[str, Any]]:
    group = {"_id": {"component": "lodash", "version": "4.17.11"}, "project_ids": ["proj-1"], "first_seen": None}
    return _run_impact(agg_results=[{**group, "details_list": [_LODASH_DETAILS]}], read=1)[1]


class TestImpactPipelineBounded:
    def test_the_ranking_read_hands_over_counts_not_advisories(self):
        _, pipeline = _run_impact(agg_results=[])
        assert not any("details_list" in (stage.get("$group") or {}) for stage in pipeline)

    def test_no_full_details_push(self):
        pipeline = _advisory_read_of_impact()
        assert _details_is_slimmed_before_group(pipeline), (
            "details must be $project-slimmed to fix-version fields before $group"
        )

    @pytest.mark.parametrize("read", [0, 1])
    def test_severities_are_not_collected_as_a_raw_array(self, read):
        pipeline = _advisory_read_of_impact() if read else _run_impact(agg_results=[])[1]
        collected = list(_iter_array_accumulators(pipeline))
        assert collected, "no array accumulator in the $group — the check below would inspect nothing"
        for _acc, expr in collected:
            assert expr != "$severity", "raw severity array must not be collected; use scalar counts"

    def test_details_carry_advisories_via_add_to_set(self):
        pipeline = _advisory_read_of_impact()
        group = _group_stage(pipeline)
        assert "details_list" in group, "expected details_list accumulator in $group"
        assert "$addToSet" in group["details_list"], "details_list must use $addToSet, not $push"
        assert "finding_ids" not in group, "finding_id is component:version, not a CVE; must not drive counts"

    def test_no_arbitrary_slice_on_enrichment_arrays(self):
        pipeline = _advisory_read_of_impact()
        sliced = _sliced_fields_after_group(pipeline)
        assert "details_list" not in sliced, "details_list must NOT be $slice-truncated (drops advisories)"


class TestHotspotsPipelineBounded:
    def test_no_full_details_push(self):
        _, pipeline = _run_hotspots(agg_results=[])
        assert _details_is_slimmed_before_group(pipeline), (
            "details must be $project-slimmed to fix-version fields before $group"
        )

    def test_severities_are_not_collected_as_a_raw_array(self):
        _, pipeline = _run_hotspots(agg_results=[])
        collected = list(_iter_array_accumulators(pipeline))
        assert collected, "no array accumulator in the $group — the check below would inspect nothing"
        for _acc, expr in collected:
            assert expr != "$severity", "raw severity array must not be collected; use scalar counts"

    def test_counts_come_from_advisories(self):
        _, pipeline = _run_hotspots(agg_results=[])
        _assert_counts_come_from_advisories(pipeline)

    def test_details_carry_advisories_via_add_to_set(self):
        _, pipeline = _run_hotspots(agg_results=[])
        group = _group_stage(pipeline)
        assert "details_list" in group, "expected details_list accumulator in $group"
        assert "$addToSet" in group["details_list"], "details_list must use $addToSet, not $push"
        assert "finding_ids" not in group, "finding_id is component:version, not a CVE; must not drive counts"

    def test_no_arbitrary_slice_on_enrichment_arrays(self):
        _, pipeline = _run_hotspots(agg_results=[])
        sliced = _sliced_fields_after_group(pipeline)
        assert "details_list" not in sliced, "details_list must NOT be $slice-truncated (drops advisories)"


_LODASH_DETAILS = {
    "fixed_version": "4.17.21",
    "vulnerabilities": [
        {
            "id": "CVE-2021-1",
            "resolved_cve": "CVE-2021-1",
            "aliases": [],
            "severity": "CRITICAL",
            "fixed_version": "4.17.21",
        },
        {
            "id": "CVE-2021-2",
            "resolved_cve": "CVE-2021-2",
            "aliases": [],
            "severity": "HIGH",
            "fixed_version": "4.17.21",
        },
        {
            "id": "CVE-2021-3",
            "resolved_cve": "CVE-2021-3",
            "aliases": [],
            "severity": "HIGH",
            "fixed_version": "4.17.21",
        },
    ],
}


class TestImpactResponseShape:
    def _group_row(self) -> dict[str, Any]:
        return {
            "_id": {"component": "lodash", "version": "4.17.11"},
            "component": "lodash",
            "version": "4.17.11",
            "project_ids": ["proj-1"],
            "first_seen": None,
            "details_list": [_LODASH_DETAILS],
            "affected_projects": 1,
        }

    def test_response_fields_from_advisories(self):
        response, _ = _run_impact(agg_results=[self._group_row()])
        assert len(response) == 1
        item = response[0]
        assert item.component == "lodash"
        assert item.version == "4.17.11"
        assert item.total_findings == 3  # 1 critical + 2 high distinct CVEs
        assert item.affected_projects == 1
        assert item.findings_by_severity.critical == 1
        assert item.findings_by_severity.high == 2
        assert item.findings_by_severity.medium == 0
        assert item.findings_by_severity.low == 0
        assert item.has_fix is True
        assert "4.17.21" in item.fix_versions


class TestHotspotsResponseShape:
    def _group_row(self) -> dict[str, Any]:
        return {
            "_id": {"component": "lodash", "version": "4.17.11"},
            "project_ids": ["proj-1"],
            "first_seen": None,
            "details_list": [_LODASH_DETAILS],
        }

    def test_response_fields_from_advisories(self):
        response, _ = _run_hotspots(agg_results=[self._group_row()])
        assert len(response) == 1
        item = response[0]
        assert item.component == "lodash"
        assert item.version == "4.17.11"
        assert item.finding_count == 3  # 1 critical + 2 high distinct CVEs
        assert item.severity_breakdown.critical == 1
        assert item.severity_breakdown.high == 2
        assert item.has_fix is True
        assert "4.17.21" in item.fix_versions
        assert "CVE-2021-1" in item.top_cves


# A GHSA and its CVE alias count once, under the worst severity, so the buckets sum to the total.


class TestDistinctSeverityCounts:
    def _details(self, *vulns: dict[str, Any]) -> list[dict[str, Any]]:
        return [{"fixed_version": None, "vulnerabilities": list(vulns)}]

    def test_canonical_cve_prefers_cve_over_ghsa(self):
        from app.core.cve import canonical_cve as _canonical_cve

        assert _canonical_cve({"id": "GHSA-x", "resolved_cve": "CVE-1"}) == "CVE-1"
        assert _canonical_cve({"id": "GHSA-x", "aliases": ["CVE-2"]}) == "CVE-2"
        assert _canonical_cve({"id": "CVE-3"}) == "CVE-3"
        assert _canonical_cve({"id": "GHSA-only"}) == "GHSA-only"

    def test_ghsa_and_cve_alias_count_once(self):
        from app.api.v1.helpers.analytics import severity_counts_from_details

        # the same vuln listed as its GHSA and its CVE alias (as prod does) is one critical
        details = self._details(
            {"id": "GHSA-a", "aliases": ["CVE-1"], "severity": "CRITICAL"},
            {"id": "CVE-1", "resolved_cve": "CVE-1", "severity": "CRITICAL"},
        )
        counts = severity_counts_from_details(details)
        assert {k: v for k, v in counts.items() if v} == {"critical": 1}

    def test_a_multi_cve_advisory_credits_its_severity_to_each_cve(self):
        from app.api.v1.helpers.analytics import severity_counts_from_details

        details = self._details(
            {"id": "CVE-1", "aliases": ["ALAS-1", "CVE-2", "CVE-3"], "severity": "HIGH"},
        )
        assert {k: v for k, v in severity_counts_from_details(details).items() if v} == {"high": 3}

    def test_multi_severity_cve_counts_once_at_worst(self):
        from app.api.v1.helpers.analytics import severity_counts_from_details

        # CVE-A is high-then-critical and CVE-B critical-then-high, so a last-wins bug fails either way.
        details = self._details(
            {"id": "CVE-A", "resolved_cve": "CVE-A", "severity": "HIGH"},
            {"id": "CVE-A", "resolved_cve": "CVE-A", "severity": "CRITICAL"},
            {"id": "CVE-B", "resolved_cve": "CVE-B", "severity": "CRITICAL"},
            {"id": "CVE-B", "resolved_cve": "CVE-B", "severity": "HIGH"},
        )
        counts = severity_counts_from_details(details)
        assert counts["critical"] == 2, "each CVE counts once at its worst severity"
        assert counts["high"] == 0, "a CVE must not also be counted at a lower severity"

    def test_counts_reconcile_with_the_cve_total(self):
        from app.api.v1.helpers.analytics import severity_counts_from_details
        from app.services.recommendation.common import live_cves

        details = self._details(
            {"id": "CVE-1", "resolved_cve": "CVE-1", "severity": "CRITICAL"},
            {"id": "CVE-2", "resolved_cve": "CVE-2", "severity": "HIGH"},
            {"id": "CVE-3", "resolved_cve": "CVE-3", "severity": "MEDIUM"},
            {"id": "CVE-4", "resolved_cve": "CVE-4", "severity": None},
            {"id": "CVE-5", "resolved_cve": "CVE-5", "severity": "CRITICAL", "waived": True},
        )
        counts = severity_counts_from_details(details)
        assert {k: v for k, v in counts.items() if v} == {"critical": 1, "high": 1, "medium": 1, "unknown": 1}
        assert sum(counts.values()) == len(live_cves(details)) == 4

    def test_every_canonical_cve_lands_in_exactly_one_bucket(self):
        from app.api.v1.helpers.analytics import severity_counts_from_details
        from app.core.cve import canonical_cves

        details = self._details(
            {"id": "CVE-1", "resolved_cve": "CVE-1", "severity": "CRITICAL"},
            {"id": "CVE-2", "resolved_cve": "CVE-2", "severity": "HIGH"},
            {"id": "CVE-3", "resolved_cve": "CVE-3", "severity": "NEGLIGIBLE"},
            {"id": "CVE-4", "resolved_cve": "CVE-4", "severity": "UNKNOWN"},
            {"id": "CVE-5", "resolved_cve": "CVE-5"},
            {"id": "CVE-4", "resolved_cve": "CVE-4", "severity": "LOW"},
        )
        counts = severity_counts_from_details(details)

        assert SeverityBreakdown.from_counts(counts) == SeverityBreakdown(
            critical=1, high=1, low=1, negligible=1, unknown=1
        )
        assert sum(counts.values()) == len(canonical_cves(details)) == 5

    def test_a_hotspot_counts_every_cve_it_names(self):
        from app.api.v1.endpoints.analytics.risk import _build_hotspot

        group = {
            "_id": {"component": "left-pad", "version": "1.0.0"},
            "details_list": self._details(
                {"id": "CVE-1", "resolved_cve": "CVE-1", "severity": "HIGH"},
                {"id": "CVE-2", "resolved_cve": "CVE-2", "severity": "NEGLIGIBLE"},
                {"id": "CVE-3", "resolved_cve": "CVE-3", "severity": "UNKNOWN"},
            ),
            "project_ids": ["p1"],
            "first_seen": None,
        }
        hotspot = _build_hotspot(group, {}, [], {}, {}, {"p1": "p1"})

        assert hotspot.finding_count == hotspot.cve_count == sum(hotspot.severity_breakdown.model_dump().values()) == 3


class TestUnratedAdvisoriesWeigh:
    """A CVE still awaiting NVD/GHSA scoring is where KEV/EPSS should decide, so it needs a base to boost."""

    def test_an_unrated_cve_has_a_base_score(self):
        assert impact_pre_score({"unknown": 1}, 1) > 0

    def test_an_unrated_broad_fix_is_ranked_among_many_low_ones(self):
        lows = [_impact_row(f"low{i}", ap=1, low=1) for i in range(30)]
        unrated = _impact_row("unrated", ap=5)
        unrated["details_list"] = [
            {
                "fixed_version": None,
                "vulnerabilities": [{"id": "CVE-9", "resolved_cve": "CVE-9", "severity": "UNKNOWN"}],
            }
        ]

        response, _ = _run_impact(agg_results=[*lows, unrated], limit=20)

        top = response[0]
        assert (top.component, top.total_findings, top.findings_by_severity.unknown) == ("unrated", 1, 1)
        assert top.fix_impact_score > 0


# epss/risk come from enrichment, so the endpoint re-sorts in Python and the fetch must not be capped.


def _limit_values_after_group(pipeline: list[dict[str, Any]]) -> list[int]:
    seen_group = False
    limits: list[int] = []
    for stage in pipeline:
        if "$group" in stage:
            seen_group = True
        if seen_group and "$limit" in stage:
            limits.append(stage["$limit"])
    return limits


class TestHotspotsPostSortPagination:
    def test_epss_deep_page_is_not_capped_in_mongo(self):
        # skip=60/limit=20 needs the 80 highest-epss groups, ranked only in Python, so a Mongo cap drops rows.
        _, pipeline = _run_hotspots(agg_results=[], sort_by="epss", skip=60, limit=20)
        assert _limit_values_after_group(pipeline) == []

    def test_risk_deep_page_is_not_capped_in_mongo(self):
        _, pipeline = _run_hotspots(agg_results=[], sort_by="risk", skip=60, limit=20)
        assert _limit_values_after_group(pipeline) == []

    def test_epss_pipeline_has_no_premature_mongo_skip(self):
        # a Mongo $skip would drop rows in finding_count order before the Python epss re-rank
        _, pipeline = _run_hotspots(agg_results=[], sort_by="epss", skip=60, limit=20)
        assert not any("$skip" in stage for stage in pipeline), (
            "post-sort pipeline must not $skip in Mongo; pagination is applied in Python after the epss/risk re-sort"
        )

    def test_finding_count_sort_paginates_in_mongo(self):
        # The counted read ranks the distinct CVEs in Mongo, so it orders and pages before any advisory is read.
        _, pipeline = _run_hotspots(agg_results=[], sort_by="finding_count", skip=40, limit=20)
        assert any(stage.get("$sort", {}).get("cve_count") == -1 for stage in pipeline)
        assert any(stage.get("$skip") == 40 for stage in pipeline), "expected $skip in Mongo pipeline"
        assert any(stage.get("$limit") == 20 for stage in pipeline), "expected $limit in Mongo pipeline"

    def test_component_sort_paginates_in_mongo(self):
        # component is a stored field, so it can be globally ordered and paged in Mongo.
        _, pipeline = _run_hotspots(agg_results=[], sort_by="component", skip=40, limit=20)
        assert any(stage.get("$skip") == 40 for stage in pipeline), "expected $skip in Mongo pipeline"
        assert any(stage.get("$limit") == 20 for stage in pipeline), "expected $limit in Mongo pipeline"


class TestHotspotsBuildOnlyThePage:
    @staticmethod
    def _groups(count: int) -> list[dict[str, Any]]:
        return [
            {
                "_id": {"component": f"lib-{index:03d}", "version": "1.0.0"},
                "project_ids": ["proj-1"],
                "first_seen": None,
                "details_list": [{"vulnerabilities": [{"id": f"CVE-2026-{index:04d}", "severity": "HIGH"}]}],
            }
            for index in range(count)
        ]

    @staticmethod
    def _run(sort_by: str) -> tuple[list[Any], list[str], MagicMock]:
        from app.api.v1.endpoints.analytics import risk

        enriched: list[str] = []

        async def _record(cves: list[str]) -> tuple[dict[str, Any], list[str]]:
            enriched.extend(cves)
            return {}, []

        with patch(f"{MODULE}._build_hotspot", side_effect=risk._build_hotspot) as build:
            response, _ = _run_hotspots(
                agg_results=TestHotspotsBuildOnlyThePage._groups(300), sort_by=sort_by, skip=20, enrich=_record
            )
        return response, enriched, build

    @pytest.mark.parametrize("sort_by", ["risk", "epss"])
    def test_an_enrichment_sort_ranks_every_group_but_builds_only_the_page(self, sort_by):
        response, enriched, build = self._run(sort_by)

        assert len(response) == build.call_count == 20
        assert len(enriched) == 300


# Finding documents carry scan_created_at; created_at never exists on them.


def _projected_fields_before_group(pipeline: list[dict[str, Any]]) -> set[str]:
    fields: set[str] = set()
    for stage in pipeline:
        if "$group" in stage:
            break
        project = stage.get("$project")
        if project:
            fields.update(project.keys())
    return fields


_FIRST_SEEN = {"$min": {"$ifNull": ["$first_seen_at", "$scan_created_at"]}}


class TestFirstSeenPrefersFirstSeenAt:
    def test_impact_first_seen_min_over_first_seen_at(self):
        _, pipeline = _run_impact(agg_results=[])
        assert _group_stage(pipeline)["first_seen"] == _FIRST_SEEN
        assert {"first_seen_at", "scan_created_at"} <= _projected_fields_before_group(pipeline)

    def test_impact_pipeline_never_references_created_at(self):
        _, pipeline = _run_impact(agg_results=[])
        assert "created_at" not in _projected_fields_before_group(pipeline)
        assert "$created_at" not in str(pipeline)

    def test_hotspots_first_seen_min_over_first_seen_at(self):
        _, pipeline = _run_hotspots(agg_results=[])
        assert _group_stage(pipeline)["first_seen"] == _FIRST_SEEN
        assert {"first_seen_at", "scan_created_at"} <= _projected_fields_before_group(pipeline)

    def test_hotspots_pipeline_never_references_created_at(self):
        _, pipeline = _run_hotspots(agg_results=[])
        assert "created_at" not in _projected_fields_before_group(pipeline)
        assert "$created_at" not in str(pipeline)

    def test_impact_days_known_and_overdue_reason_from_first_seen(self):
        row = {
            "_id": {"component": "lodash", "version": "4.17.11"},
            "component": "lodash",
            "version": "4.17.11",
            "project_ids": ["proj-1"],
            "total_findings": 3,
            "critical": 1,
            "high": 2,
            "medium": 0,
            "low": 0,
            "finding_ids": ["CVE-2021-1"],
            "first_seen": datetime.now(timezone.utc) - timedelta(days=120),
            "details_list": [
                {"fixed_version": "4.17.21", "vulnerabilities": [{"id": "CVE-2021-1", "severity": "CRITICAL"}]}
            ],
            "affected_projects": 1,
        }
        response, _ = _run_impact(agg_results=[row])
        item = response[0]
        assert item.days_known is not None and item.days_known >= 119
        assert any(r.startswith("overdue:") for r in item.priority_reasons)

    def test_hotspots_first_seen_rendered(self):
        row = {
            "_id": {"component": "lodash", "version": "4.17.11"},
            "project_ids": ["proj-1"],
            "finding_count": 3,
            "critical": 1,
            "high": 2,
            "medium": 0,
            "low": 0,
            "first_seen": datetime.now(timezone.utc) - timedelta(days=120),
            "finding_ids": ["CVE-2021-1"],
            "details_list": [{"fixed_version": "4.17.21", "vulnerabilities": []}],
        }
        response, _ = _run_hotspots(agg_results=[row])
        item = response[0]
        assert item.first_seen != ""
        assert item.days_known is not None and item.days_known >= 119


# The KEV/EPSS/maturity boosts come from enrichment, so fix_impact_score ranks and cuts in Python.


def _details_from_counts(component: str, critical: int, high: int, medium: int, low: int) -> dict[str, Any]:
    vulns = []
    for sev, n in (("critical", critical), ("high", high), ("medium", medium), ("low", low)):
        for i in range(n):
            cid = f"CVE-{component}-{sev}-{i}"
            vulns.append(
                {"id": cid, "resolved_cve": cid, "aliases": [], "severity": sev.upper(), "fixed_version": None}
            )
    return {"fixed_version": None, "vulnerabilities": vulns}


def _impact_row(
    component: str, ap: int, *, critical: int = 0, high: int = 0, medium: int = 0, low: int = 0
) -> dict[str, Any]:
    return {
        "_id": {"component": component, "version": "1.0.0"},
        "component": component,
        "version": "1.0.0",
        "project_ids": [f"p{i}" for i in range(ap)],
        "first_seen": None,
        "details_list": [_details_from_counts(component, critical, high, medium, low)],
        "affected_projects": ap,
    }


def _scored(rows: list[dict[str, Any]]) -> list[tuple[float, dict[str, Any]]]:
    return [
        (impact_pre_score(severity_counts_from_details(r["details_list"]), r["affected_projects"]), r) for r in rows
    ]


class TestImpactPreScoreIsScoreBase:
    def test_pre_score_equals_unboosted_impact_score(self):
        counts = {"critical": 2, "high": 3, "medium": 1, "low": 4}
        for ap in (0, 1, 5, 10, 50):
            assert impact_pre_score(counts, ap) == calculate_impact_score(
                counts, ap, ThreatIntelFields(), has_fix=False, days_known=None
            ), f"pre-score must equal the un-boosted impact score (ap={ap})"

    def test_the_boost_ceiling_is_the_highest_boost_any_enrichment_reaches(self):
        counts = {"critical": 1}
        due_soon = (datetime.now(timezone.utc) + timedelta(days=5)).date().isoformat()
        kev_states = [
            {},
            {"has_kev": True},
            {"has_kev": True, "days_until_due": 5, "kev_due_date": due_soon},
            {"has_kev": True, "days_until_due": -1},
            {"has_kev": True, "kev_ransomware_use": True},
        ]
        ratios = [
            calculate_impact_score(
                counts,
                1,
                ThreatIntelFields(**kev, max_epss_score=epss, exploit_maturity=maturity),
                has_fix=has_fix,
                days_known=days_known,
            )
            / impact_pre_score(counts, 1)
            for kev in kev_states
            for epss in (None, 0.005, 0.05, 0.2, 0.6)
            for maturity in EXPLOIT_MATURITY_BOOST
            for has_fix in (False, True)
            for days_known in (None, 120)
        ]

        assert max(ratios) == pytest.approx(IMPACT_MAX_SCORE_BOOST)

    def test_reach_is_capped_like_the_score(self):
        counts = {"critical": 1, "high": 0, "medium": 0, "low": 0}
        assert impact_pre_score(counts, 10) == impact_pre_score(counts, 9999)
        assert impact_pre_score(counts, 3) < impact_pre_score(counts, 10)


class TestSelectImpactCandidates:
    def test_returns_all_when_not_over_limit(self):
        rows = [_impact_row("a", 5, low=1), _impact_row("b", 3, high=1)]
        assert len(select_impact_candidates(_scored(rows), limit=20)) == 2

    def test_keeps_narrow_but_severe_contender(self):
        # 24 broad low-severity groups outrank a narrow critical on blast radius...
        broad = [_impact_row(f"broad{i}", ap=50, low=1) for i in range(24)]  # pre = 1*10 = 10
        narrow = _impact_row("narrow", ap=1, critical=3)  # pre = 30*1 = 30
        cands = select_impact_candidates(_scored([*broad, narrow]), limit=20)
        assert any(r["component"] == "narrow" for r in cands), (
            "narrow-but-severe fix must survive candidate selection; its boosted ceiling can top the list"
        )

    def test_drops_only_genuinely_unreachable_groups(self):
        top = [_impact_row(f"t{i}", ap=10, critical=1) for i in range(5)]  # pre = 100 (limit-th)
        reachable = _impact_row("reachable", ap=1, critical=2)  # pre 20; 20*B_MAX=166 > 100
        unreachable = _impact_row("unreachable", ap=1, low=1)  # pre 1; 1*B_MAX=8.3 < 100
        cands = select_impact_candidates(_scored([*top, reachable, unreachable]), limit=5)
        names = {r["component"] for r in cands}
        assert "reachable" in names, "a group whose boosted ceiling clears the limit-th pre-score must be kept"
        assert "unreachable" not in names, "a group that can never reach the top-limit must be dropped"

    def test_threshold_is_limit_pre_score_over_boost_ceiling(self):
        # Exactly at the boundary pre = P_limit / B_MAX must be kept (inclusive).
        top = [_impact_row(f"t{i}", ap=10, critical=1) for i in range(5)]  # P_limit = 100
        boundary_low = round(100 / IMPACT_MAX_SCORE_BOOST) + 1  # low count -> pre just above threshold
        boundary = _impact_row("boundary", ap=1, low=boundary_low)
        cands = select_impact_candidates(_scored([*top, boundary]), limit=5)
        assert any(r["component"] == "boundary" for r in cands)

    def test_the_cut_is_taken_from_the_limit_th_row(self):
        # P_limit = 100 gives threshold 12.03; reading one row further (pre 20) would lower it to 2.4.
        top = [_impact_row(f"t{i}", ap=10, critical=1) for i in range(5)]  # pre 100 each
        sixth = _impact_row("sixth", ap=2, critical=1)  # pre 20, the first row below the cut
        unreachable = _impact_row("unreachable", ap=1, medium=1)  # pre 4: under 12.03, over 2.4
        cands = select_impact_candidates(_scored([*top, sixth, unreachable]), limit=5)
        names = {r["component"] for r in cands}
        assert "sixth" in names
        assert "unreachable" not in names, "the cut must come from the limit-th pre-score"

    def test_a_field_that_scores_zero_throughout_keeps_every_group(self):
        """INFO carries no severity weight, so a page can pre-score zero and an exclusive cut would drop it all."""
        rows = [_impact_row(f"u{i}", ap=5) for i in range(8)]

        assert len(select_impact_candidates(_scored(rows), limit=5)) == len(rows)


class TestPriorityReasons:
    def _reasons(self, affected_projects: int) -> list[str]:
        return build_priority_reasons(
            {"critical": 0, "high": 1, "medium": 0, "low": 0},
            ThreatIntelFields(),
            affected_projects,
            has_fix=False,
            days_known=None,
        )

    @staticmethod
    def _overdue(severity_counts: dict[str, int], days_known: int | None) -> bool:
        reasons = build_priority_reasons(severity_counts, ThreatIntelFields(), 1, has_fix=False, days_known=days_known)
        return any(r.startswith("overdue:") for r in reasons)

    @pytest.mark.parametrize(("severity", "sla_days"), [("critical", 7), ("high", 30), ("medium", 90)])
    def test_overdue_follows_the_remediation_sla_of_the_most_severe_cve(self, severity, sla_days):
        """The CVE-SLA report holds each severity to its own deadline, so the impact analysis must not use one."""
        counts = {"critical": 0, "high": 0, "medium": 1, "low": 3, severity: 1}

        assert (self._overdue(counts, sla_days - 1), self._overdue(counts, sla_days)) == (False, True)

    def test_a_component_with_only_low_cves_has_no_deadline_to_be_overdue_on(self):
        assert not self._overdue({"critical": 0, "high": 0, "medium": 0, "low": 4}, 3650)

    def test_the_age_boost_starts_where_the_sla_ends(self):
        def score(days_known: int | None) -> float:
            return calculate_impact_score({"critical": 1}, 1, ThreatIntelFields(), False, days_known)

        assert (score(6), score(7)) == (score(None), score(None) * IMPACT_AGE_BOOST)

    def test_a_fix_reaching_exactly_the_blast_radius_threshold_is_labelled(self):
        reasons = self._reasons(BLAST_RADIUS_THRESHOLD)

        assert any(r.startswith("blast_radius:") for r in reasons)

    def test_a_fix_one_project_short_of_the_threshold_is_not_labelled(self):
        reasons = self._reasons(BLAST_RADIUS_THRESHOLD - 1)

        assert not any(r.startswith("blast_radius:") for r in reasons)

    def test_a_hotspot_names_the_reasons_the_impact_analysis_names(self):
        from app.api.v1.endpoints.analytics.risk import _build_hotspot

        projects = [f"p{i}" for i in range(BLAST_RADIUS_THRESHOLD)]
        advisory = {"id": "CVE-1", "resolved_cve": "CVE-1", "severity": "CRITICAL", "fixed_version": "1.0.1"}
        group = {
            "_id": {"component": "left-pad", "version": "1.0.0"},
            "details_list": [{"vulnerabilities": [advisory]}],
            "project_ids": projects,
            "first_seen": datetime.now(timezone.utc) - timedelta(days=120),
        }

        hotspot = _build_hotspot(group, {}, [], {}, {}, {})

        assert hotspot.priority_reasons == build_priority_reasons(
            {"critical": 1}, ThreatIntelFields(), len(projects), has_fix=True, days_known=hotspot.days_known
        )


class TestImpactEndpointRanksByScoreNotBlastRadius:
    def test_narrow_critical_beats_broad_low_severity(self):
        # With 24 broad groups a blast-radius cut in Mongo would never score the narrow critical, which ranks first.
        broad = [_impact_row(f"broad{i}", ap=50, low=1) for i in range(24)]  # pre 10, blast radius 50
        narrow = _impact_row("narrow-critical", ap=2, critical=5)  # pre 50*2 = 100
        response, _ = _run_impact(agg_results=[*broad, narrow], limit=5)
        names = [item.component for item in response]
        assert "narrow-critical" in names, "narrow critical must surface by fix_impact_score, not blast radius"
        assert response[0].component == "narrow-critical", "highest fix_impact_score must rank first"

    def test_response_capped_at_limit(self):
        rows = [_impact_row(f"c{i}", ap=i + 1, critical=1) for i in range(30)]
        response, _ = _run_impact(agg_results=rows, limit=5)
        assert len(response) == 5

    def test_pipeline_does_not_mongo_limit_at_user_limit(self):
        # A Mongo $limit at the page size caps by the blast-radius $sort before any scoring.
        _, pipeline = _run_impact(agg_results=[], limit=7)
        limits = [stage["$limit"] for stage in pipeline if "$limit" in stage]
        assert 7 not in limits, "Mongo must not $limit at the user limit; that caps by blast radius before scoring"
        assert all(lim >= 1000 for lim in limits), "any Mongo $limit must be a large safety cap, not a page size"


def _impact_aggregate_calls(*limits: int) -> int:
    from app.api.v1.endpoints.analytics.risk import get_impact_analysis

    user = _admin_user()
    db = MagicMock()
    calls = {"n": 0}

    async def _fake_get_user_projects(_u, _d):
        return projections(["proj-1"])

    async def _fake_get_projects_with_scans(_p, _d, **_kw):
        return {"proj-1": "P1"}, ["scan-latest"]

    async def _fake_aggregate(pipeline, **_kw):
        calls["n"] += 1
        return _answer([_impact_row("a", 3, critical=1)], pipeline)

    repo = MagicMock()
    repo.aggregate = _fake_aggregate

    async def _fake_enrich(_c):
        return {}, []

    with (
        patch(f"{MODULE}.get_user_projects", new=_fake_get_user_projects),
        patch(f"{MODULE}.get_projects_with_scans", new=_fake_get_projects_with_scans),
        patch(f"{MODULE}.FindingRepository", return_value=repo),
        patch(f"{MODULE}.vulnerability_enrichment_service.enrich_cves", new=_fake_enrich),
    ):
        for lim in limits:
            asyncio.run(get_impact_analysis(current_user=user, db=db, limit=lim))
    return calls["n"]


def _hotspots_aggregate_calls(*sort_bys: str) -> int:
    from app.api.v1.endpoints.analytics.risk import get_vulnerability_hotspots

    user = _admin_user()
    db = MagicMock()
    calls = {"n": 0}

    async def _fake_get_user_projects(_u, _d):
        return projections(["proj-1"])

    async def _fake_get_projects_with_scans(_p, _d, **_kw):
        return {"proj-1": "P1"}, ["scan-latest"]

    async def _fake_aggregate(_pipeline, **_kw):
        calls["n"] += 1
        return []

    repo = MagicMock()
    repo.aggregate = _fake_aggregate
    dep_repo = MagicMock()
    dep_repo.aggregate = AsyncMock(return_value=[])

    async def _fake_enrich(_c):
        return {}, []

    with (
        patch(f"{MODULE}.get_user_projects", new=_fake_get_user_projects),
        patch(f"{MODULE}.get_projects_with_scans", new=_fake_get_projects_with_scans),
        patch(f"{MODULE}.FindingRepository", return_value=repo),
        patch(f"{MODULE}.DependencyRepository", return_value=dep_repo),
        patch(f"{MODULE}.vulnerability_enrichment_service.enrich_cves", new=_fake_enrich),
    ):
        for sb in sort_bys:
            asyncio.run(
                get_vulnerability_hotspots(current_user=user, db=db, skip=0, limit=20, sort_by=sb, sort_order="desc")
            )
    return calls["n"]


class TestAnalyticsResultCache:
    # An uncached /impact reads twice: the counted groups, then the candidates' advisories.
    def test_impact_repeat_call_hits_cache(self):
        assert _impact_aggregate_calls(20, 20) == 2, "identical /impact request must be served from cache"

    def test_impact_distinct_limit_misses_cache(self):
        assert _impact_aggregate_calls(20, 10) == 4, "a different limit must not reuse a cached result"

    def test_hotspots_repeat_call_hits_cache(self):
        assert _hotspots_aggregate_calls("finding_count", "finding_count") == 1

    def test_hotspots_distinct_sort_misses_cache(self):
        assert _hotspots_aggregate_calls("finding_count", "epss") == 2

    def test_impact_cached_response_matches_fresh(self):
        from app.api.v1.endpoints.analytics.risk import get_impact_analysis

        user = _admin_user()
        db = MagicMock()

        async def _fake_get_user_projects(_u, _d):
            return projections(["proj-1"])

        async def _fake_get_projects_with_scans(_p, _d, **_kw):
            return {"proj-1": "P1"}, ["scan-latest"]

        async def _fake_aggregate(pipeline, **_kw):
            return _answer([_impact_row("lodash", 3, critical=2, high=1)], pipeline)

        repo = MagicMock()
        repo.aggregate = _fake_aggregate

        async def _fake_enrich(_c):
            return {}, []

        with (
            patch(f"{MODULE}.get_user_projects", new=_fake_get_user_projects),
            patch(f"{MODULE}.get_projects_with_scans", new=_fake_get_projects_with_scans),
            patch(f"{MODULE}.FindingRepository", return_value=repo),
            patch(f"{MODULE}.vulnerability_enrichment_service.enrich_cves", new=_fake_enrich),
        ):
            fresh = asyncio.run(get_impact_analysis(current_user=user, db=db, limit=20))
            cached = asyncio.run(get_impact_analysis(current_user=user, db=db, limit=20))

        assert [r.model_dump() for r in fresh] == [r.model_dump() for r in cached]


# "Vulns" counts canonical CVEs from details.vulnerabilities, not finding documents or raw advisory rows.


def _row_with_advisories(component: str, vulns: list[dict[str, Any]], ap: int = 1) -> dict[str, Any]:
    return {
        "_id": {"component": component, "version": "1.0.0"},
        "component": component,
        "version": "1.0.0",
        "project_ids": [f"p{i}" for i in range(ap)],
        "first_seen": None,
        "details_list": [{"fixed_version": None, "vulnerabilities": vulns}],
        "affected_projects": ap,
    }


# 3 distinct vulns: CVE-1 (critical, listed as GHSA + its CVE alias), CVE-2 & CVE-3 (high).
_MIXED_VULNS = [
    {"id": "GHSA-a", "aliases": ["CVE-1"], "severity": "CRITICAL"},
    {"id": "CVE-1", "resolved_cve": "CVE-1", "severity": "CRITICAL"},
    {"id": "CVE-2", "resolved_cve": "CVE-2", "severity": "HIGH"},
    {"id": "CVE-3", "resolved_cve": "CVE-3", "severity": "HIGH"},
]


class TestDistinctVulnCount:
    def test_impact_total_findings_is_distinct_cves(self):
        response, _ = _run_impact(agg_results=[_row_with_advisories("lodash", _MIXED_VULNS)])
        item = response[0]
        assert item.total_findings == 3, "GHSA+CVE alias collapse; 3 distinct CVEs, not 4 rows"
        assert item.findings_by_severity.critical == 1
        assert item.findings_by_severity.high == 2

    def test_hotspots_finding_count_is_distinct_cves(self):
        response, _ = _run_hotspots(agg_results=[_row_with_advisories("lodash", _MIXED_VULNS)])
        item = response[0]
        assert item.finding_count == 3
        assert item.severity_breakdown.critical == 1
        assert item.severity_breakdown.high == 2

    def test_finding_count_reconciles_with_severity_breakdown(self):
        response, _ = _run_hotspots(agg_results=[_row_with_advisories("lodash", _MIXED_VULNS)])
        b = response[0].severity_breakdown
        assert response[0].finding_count == b.critical + b.high + b.medium + b.low


_ONE_GROUP = [
    {
        "_id": {"component": "log4j-core", "version": "2.14.1"},
        "project_ids": ["proj-1"],
        "first_seen": None,
        "details_list": [{"vulnerabilities": [{"id": "CVE-2021-44228", "severity": "CRITICAL"}]}],
    }
]


async def _kev_down(cves: list[str]) -> tuple[dict[str, Any], list[str]]:
    return {cve: VulnerabilityEnrichment(cve=cve, epss_score=0.9, risk_score=60.0) for cve in cves}, ["KEV"]


async def _feeds_down(_cves: list[str]) -> tuple[dict[str, Any], list[str]]:
    raise RuntimeError("feeds down")


class TestThreatIntelOutage:
    def test_impact_rows_name_the_source_that_was_unavailable(self):
        [row], _ = _run_impact(agg_results=_ONE_GROUP, enrich=_kev_down)
        assert row.threat_intel_unavailable == ["KEV"]
        assert row.max_epss_score == 0.9, "the source that answered still counts"

    def test_hotspots_name_the_source_that_was_unavailable(self):
        [row], _ = _run_hotspots(agg_results=_ONE_GROUP, enrich=_kev_down)
        assert row.threat_intel_unavailable == ["KEV"]

    def test_a_failed_enrichment_names_both_sources(self):
        [impact], _ = _run_impact(agg_results=_ONE_GROUP, enrich=_feeds_down)
        [hotspot], _ = _run_hotspots(agg_results=_ONE_GROUP, enrich=_feeds_down)
        assert impact.threat_intel_unavailable == hotspot.threat_intel_unavailable == ["KEV", "EPSS"]

    def test_a_complete_enrichment_names_none(self):
        [impact], _ = _run_impact(agg_results=_ONE_GROUP)
        [hotspot], _ = _run_hotspots(agg_results=_ONE_GROUP)
        assert impact.threat_intel_unavailable == hotspot.threat_intel_unavailable == []


class TestHotspotReadsOverlap:
    @staticmethod
    def _first_two_events(sort_by: str) -> set[str]:
        events: list[str] = []

        async def _slow_enrich(_cves):
            events.append("enrichment started")
            await asyncio.sleep(0.02)
            return {}, []

        async def _slow_type_rows(_pipeline):
            events.append("type read started")
            await asyncio.sleep(0.02)
            events.append("type read done")
            return []

        _run_hotspots(agg_results=_ONE_GROUP, sort_by=sort_by, enrich=_slow_enrich, type_rows=_slow_type_rows)
        return set(events[:2])

    def test_the_type_read_runs_beside_the_enrichment_of_the_page(self):
        assert self._first_two_events("finding_count") == {"type read started", "enrichment started"}

    def test_the_type_read_runs_beside_the_enrichment_an_epss_sort_ranks_by(self):
        assert self._first_two_events("epss") == {"type read started", "enrichment started"}
