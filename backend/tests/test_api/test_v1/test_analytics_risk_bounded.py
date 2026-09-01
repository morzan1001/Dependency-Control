"""Tests that /impact and /hotspots analytics aggregations stay bounded: details slimmed before $group, scalar severity counts, id/detail sets deduped via $addToSet (not $slice-capped), and allow_disk_use threaded through."""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from app.api.v1.helpers.analytics import (
    calculate_impact_score,
    count_severities,
    impact_pre_score,
    select_impact_candidates,
)
from app.core.constants import IMPACT_MAX_SCORE_BOOST
from app.core.permissions import ALL_PERMISSIONS
from app.models.user import User
from app.schemas.analytics import CVEEnrichmentResult
from tests.mocks.fake_mongo import FakeCollection

MODULE = "app.api.v1.endpoints.analytics.risk"


def _admin_user() -> User:
    return User(
        id="admin-1",
        username="admin",
        email="admin@test.com",
        permissions=list(ALL_PERMISSIONS),
    )


def _iter_push_exprs(pipeline: list[dict[str, Any]]):
    """Yield every ``$push`` accumulator expression in any ``$group`` stage."""
    for stage in pipeline:
        group = stage.get("$group")
        if not group:
            continue
        for acc_name, acc_expr in group.items():
            if isinstance(acc_expr, dict) and "$push" in acc_expr:
                yield acc_name, acc_expr["$push"]


def _iter_add_to_set_exprs(pipeline: list[dict[str, Any]]):
    """Yield every ``$addToSet`` accumulator expression in any ``$group`` stage."""
    for stage in pipeline:
        group = stage.get("$group")
        if not group:
            continue
        for acc_name, acc_expr in group.items():
            if isinstance(acc_expr, dict) and "$addToSet" in acc_expr:
                yield acc_name, acc_expr["$addToSet"]


def _group_stage(pipeline: list[dict[str, Any]]) -> dict[str, Any]:
    for stage in pipeline:
        if "$group" in stage:
            return stage["$group"]
    raise AssertionError("pipeline has no $group stage")


def _sliced_fields_after_group(pipeline: list[dict[str, Any]]) -> list[str]:
    """Names of fields $slice-capped in a $project after the $group."""
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
    """True if a $project slims ``details`` to fix-version fields before the first $group."""
    for stage in pipeline:
        if "$group" in stage:
            return False
        project = stage.get("$project")
        if not project:
            continue
        details_spec = project.get("details")
        # slimming projection maps details to a fix-version-keyed dict, not a passthrough
        if isinstance(details_spec, dict):
            keys = set(details_spec.keys())
            if keys and keys <= {"fixed_version", "vulnerabilities"}:
                return True
    return False


# ---------------------------------------------------------------------------
# Endpoint runners (patch helpers + repos, capture aggregate kwargs)
# ---------------------------------------------------------------------------


def _run_impact(
    agg_results: list[dict[str, Any]],
    limit: int = 20,
) -> tuple[Any, list[dict[str, Any]], list[dict[str, Any]]]:
    """Run /impact with patched helpers. Returns (response, pipeline, agg_kwargs)."""
    from app.api.v1.endpoints.analytics.risk import get_impact_analysis

    user = _admin_user()
    db = MagicMock()
    captured: list[list[dict[str, Any]]] = []
    captured_kwargs: list[dict[str, Any]] = []

    async def _fake_get_user_project_ids(_u, _d):
        return ["proj-1"]

    async def _fake_get_projects_with_scans(_pids, _d):
        return {"proj-1": "Project 1"}, ["scan-latest"]

    async def _fake_aggregate(pipeline, **kwargs):
        captured.append(pipeline)
        captured_kwargs.append(kwargs)
        return agg_results

    mock_finding_repo = MagicMock()
    mock_finding_repo.aggregate = _fake_aggregate

    async def _fake_enrich(_cves):
        return {}

    with (
        patch(f"{MODULE}.get_user_project_ids", new=_fake_get_user_project_ids),
        patch(f"{MODULE}.get_projects_with_scans", new=_fake_get_projects_with_scans),
        patch(f"{MODULE}.FindingRepository", return_value=mock_finding_repo),
        patch(f"{MODULE}.get_cve_enrichment", new=_fake_enrich),
    ):
        response = asyncio.run(get_impact_analysis(current_user=user, db=db, limit=limit))

    assert captured, "aggregate() was never called for /impact"
    return response, captured[0], captured_kwargs[0]


def _run_hotspots(
    agg_results: list[dict[str, Any]],
    limit: int = 20,
    sort_by: str = "finding_count",
    skip: int = 0,
) -> tuple[Any, list[dict[str, Any]], list[dict[str, Any]]]:
    """Run /hotspots with patched helpers. Returns (response, finding_pipeline, agg_kwargs)."""
    from app.api.v1.endpoints.analytics.risk import get_vulnerability_hotspots

    user = _admin_user()
    db = MagicMock()
    captured: list[list[dict[str, Any]]] = []
    captured_kwargs: list[dict[str, Any]] = []

    async def _fake_get_user_project_ids(_u, _d):
        return ["proj-1"]

    async def _fake_get_projects_with_scans(_pids, _d):
        return {"proj-1": "Project 1"}, ["scan-latest"]

    async def _fake_finding_aggregate(pipeline, **kwargs):
        captured.append(pipeline)
        captured_kwargs.append(kwargs)
        return agg_results

    mock_finding_repo = MagicMock()
    mock_finding_repo.aggregate = _fake_finding_aggregate

    mock_dep_repo = MagicMock()
    mock_dep_repo.aggregate = AsyncMock(return_value=[])

    async def _fake_enrich(_cves):
        return {}

    with (
        patch(f"{MODULE}.get_user_project_ids", new=_fake_get_user_project_ids),
        patch(f"{MODULE}.get_projects_with_scans", new=_fake_get_projects_with_scans),
        patch(f"{MODULE}.FindingRepository", return_value=mock_finding_repo),
        patch(f"{MODULE}.DependencyRepository", return_value=mock_dep_repo),
        patch(f"{MODULE}.get_cve_enrichment", new=_fake_enrich),
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
    return response, captured[0], captured_kwargs[0]


# ---------------------------------------------------------------------------
# Structural tests — /impact
# ---------------------------------------------------------------------------


class TestImpactPipelineBounded:
    def test_no_full_details_push(self):
        _, pipeline, _ = _run_impact(agg_results=[])
        assert _details_is_slimmed_before_group(pipeline), (
            "details must be $project-slimmed to fix-version fields before $group"
        )

    def test_severities_not_pushed_raw(self):
        _, pipeline, _ = _run_impact(agg_results=[])
        for _acc, push_expr in _iter_push_exprs(pipeline):
            assert push_expr != "$severity", "raw severity array must not be pushed; use scalar counts"

    def test_severity_scalar_counts_present(self):
        _, pipeline, _ = _run_impact(agg_results=[])
        group = _group_stage(pipeline)
        for sev in ("critical", "high", "medium", "low"):
            assert sev in group, f"expected scalar severity accumulator '{sev}' in $group"

    def test_finding_ids_deduped_with_add_to_set(self):
        _, pipeline, _ = _run_impact(agg_results=[])
        group = _group_stage(pipeline)
        assert "finding_ids" in group, "expected finding_ids accumulator in $group"
        assert "$addToSet" in group["finding_ids"], "finding_ids must use $addToSet (dedupe), not $push"
        assert "$push" not in group["finding_ids"]
        for _acc, push_expr in _iter_push_exprs(pipeline):
            assert push_expr != "$finding_id", "finding_id must not be $push-ed; use $addToSet to dedupe"

    def test_details_not_pushed_and_not_sliced(self):
        _, pipeline, _ = _run_impact(agg_results=[])
        group = _group_stage(pipeline)
        assert "details_list" in group, "expected details_list accumulator in $group"
        assert "$addToSet" in group["details_list"], "details_list must use $addToSet, not $push"

    def test_no_arbitrary_slice_on_enrichment_arrays(self):
        _, pipeline, _ = _run_impact(agg_results=[])
        sliced = _sliced_fields_after_group(pipeline)
        assert "finding_ids" not in sliced, "finding_ids must NOT be $slice-truncated (drops CVEs in match order)"
        assert "details_list" not in sliced, "details_list must NOT be $slice-truncated (drops fix versions)"

    def test_allow_disk_use_threaded(self):
        _, _, kwargs = _run_impact(agg_results=[])
        assert kwargs.get("allow_disk_use") is True, "allow_disk_use=True must be passed for /impact aggregation"


# ---------------------------------------------------------------------------
# Structural tests — /hotspots
# ---------------------------------------------------------------------------


class TestHotspotsPipelineBounded:
    def test_no_full_details_push(self):
        _, pipeline, _ = _run_hotspots(agg_results=[])
        assert _details_is_slimmed_before_group(pipeline), (
            "details must be $project-slimmed to fix-version fields before $group"
        )

    def test_severities_not_pushed_raw(self):
        _, pipeline, _ = _run_hotspots(agg_results=[])
        for _acc, push_expr in _iter_push_exprs(pipeline):
            assert push_expr != "$severity", "raw severity array must not be pushed; use scalar counts"

    def test_severity_scalar_counts_present(self):
        _, pipeline, _ = _run_hotspots(agg_results=[])
        group = _group_stage(pipeline)
        for sev in ("critical", "high", "medium", "low"):
            assert sev in group, f"expected scalar severity accumulator '{sev}' in $group"

    def test_finding_ids_deduped_with_add_to_set(self):
        _, pipeline, _ = _run_hotspots(agg_results=[])
        group = _group_stage(pipeline)
        assert "finding_ids" in group, "expected finding_ids accumulator in $group"
        assert "$addToSet" in group["finding_ids"], "finding_ids must use $addToSet (dedupe), not $push"
        assert "$push" not in group["finding_ids"]
        for _acc, push_expr in _iter_push_exprs(pipeline):
            assert push_expr != "$finding_id", "finding_id must not be $push-ed; use $addToSet to dedupe"

    def test_details_not_pushed_and_not_sliced(self):
        _, pipeline, _ = _run_hotspots(agg_results=[])
        group = _group_stage(pipeline)
        assert "details_list" in group, "expected details_list accumulator in $group"
        assert "$addToSet" in group["details_list"], "details_list must use $addToSet, not $push"

    def test_no_arbitrary_slice_on_enrichment_arrays(self):
        _, pipeline, _ = _run_hotspots(agg_results=[])
        sliced = _sliced_fields_after_group(pipeline)
        assert "finding_ids" not in sliced, "finding_ids must NOT be $slice-truncated (drops CVEs in match order)"
        assert "details_list" not in sliced, "details_list must NOT be $slice-truncated (drops fix versions)"

    def test_allow_disk_use_threaded(self):
        _, _, kwargs = _run_hotspots(agg_results=[])
        assert kwargs.get("allow_disk_use") is True, "allow_disk_use=True must be passed for /hotspots aggregation"


# ---------------------------------------------------------------------------
# Response-shape equivalence — /impact (built from scalar group output)
# ---------------------------------------------------------------------------


class TestImpactResponseShape:
    def _group_row(self) -> dict[str, Any]:
        """A group row matching the bounded pipeline output shape."""
        return {
            "_id": {"component": "lodash", "version": "4.17.11"},
            "component": "lodash",
            "version": "4.17.11",
            "project_ids": ["proj-1"],
            "total_findings": 3,
            "critical": 1,
            "high": 2,
            "medium": 0,
            "low": 0,
            "finding_ids": ["CVE-2021-1", "CVE-2021-2"],
            "first_seen": None,
            "details_list": [{"fixed_version": "4.17.21", "vulnerabilities": []}],
            "affected_projects": 1,
        }

    def test_response_fields_from_scalar_counts(self):
        response, _, _ = _run_impact(agg_results=[self._group_row()])
        assert len(response) == 1
        item = response[0]
        assert item.component == "lodash"
        assert item.version == "4.17.11"
        assert item.total_findings == 3
        assert item.affected_projects == 1
        assert item.findings_by_severity.critical == 1
        assert item.findings_by_severity.high == 2
        assert item.findings_by_severity.medium == 0
        assert item.findings_by_severity.low == 0
        assert item.has_fix is True
        assert "4.17.21" in item.fix_versions


# ---------------------------------------------------------------------------
# Response-shape equivalence — /hotspots
# ---------------------------------------------------------------------------


class TestHotspotsResponseShape:
    def _group_row(self) -> dict[str, Any]:
        return {
            "_id": {"component": "lodash", "version": "4.17.11"},
            "project_ids": ["proj-1"],
            "finding_count": 3,
            "critical": 1,
            "high": 2,
            "medium": 0,
            "low": 0,
            "first_seen": None,
            "finding_ids": ["CVE-2021-1", "CVE-2021-2"],
            "details_list": [{"fixed_version": "4.17.21", "vulnerabilities": []}],
        }

    def test_response_fields_from_scalar_counts(self):
        response, _, _ = _run_hotspots(agg_results=[self._group_row()])
        assert len(response) == 1
        item = response[0]
        assert item.component == "lodash"
        assert item.version == "4.17.11"
        assert item.finding_count == 3
        assert item.severity_breakdown.critical == 1
        assert item.severity_breakdown.high == 2
        assert item.has_fix is True
        assert "4.17.21" in item.fix_versions
        assert "CVE-2021-1" in item.top_cves


# Run real $group accumulators through FakeCollection: scalar counts must equal count_severities() and $addToSet must dedupe CVEs.


class TestSeverityCountAccumulatorsExecuted:
    def _findings(self) -> list[dict[str, Any]]:
        # same CVE repeated across three projects so $addToSet must collapse it
        return [
            {
                "_id": "f1",
                "component": "lodash",
                "version": "4.17.11",
                "project_id": "p1",
                "severity": "CRITICAL",
                "finding_id": "CVE-2021-1",
            },
            {
                "_id": "f2",
                "component": "lodash",
                "version": "4.17.11",
                "project_id": "p2",
                "severity": "critical",
                "finding_id": "CVE-2021-1",
            },  # dup CVE, diff project
            {
                "_id": "f3",
                "component": "lodash",
                "version": "4.17.11",
                "project_id": "p3",
                "severity": "High",
                "finding_id": "CVE-2021-2",
            },
            {
                "_id": "f4",
                "component": "lodash",
                "version": "4.17.11",
                "project_id": "p1",
                "severity": "medium",
                "finding_id": "CVE-2021-3",
            },
            {
                "_id": "f5",
                "component": "lodash",
                "version": "4.17.11",
                "project_id": "p1",
                "severity": "low",
                "finding_id": None,
            },  # non-CVE / no id
        ]

    def _group_spec(self) -> dict[str, Any]:
        # accumulators imported from the production module, not copied
        from app.api.v1.endpoints.analytics.risk import _severity_count_accumulators

        return {
            "_id": {"component": "$component", "version": "$version"},
            "total_findings": {"$sum": 1},
            **_severity_count_accumulators(),
            "finding_ids": {"$addToSet": "$finding_id"},
        }

    def test_scalar_counts_equal_count_severities(self):
        findings = self._findings()
        col = FakeCollection()
        col._docs = {d["_id"]: d for d in findings}

        rows = asyncio.run(col.aggregate([{"$group": self._group_spec()}]).to_list())
        assert len(rows) == 1
        row = rows[0]

        expected = count_severities([f["severity"] for f in findings])
        for sev in ("critical", "high", "medium", "low"):
            assert row[sev] == expected[sev], f"{sev}: {row[sev]} != {expected[sev]}"

        assert row["total_findings"] == len(findings)

    def test_add_to_set_collapses_repeated_cves(self):
        findings = self._findings()
        col = FakeCollection()
        col._docs = {d["_id"]: d for d in findings}

        rows = asyncio.run(col.aggregate([{"$group": self._group_spec()}]).to_list())
        finding_ids = rows[0]["finding_ids"]

        # the CVE in three projects collapses to one entry; bounded by distinct ids
        cve_ids = sorted(fid for fid in finding_ids if fid and fid.startswith("CVE-"))
        assert cve_ids == ["CVE-2021-1", "CVE-2021-2", "CVE-2021-3"]


# epss/risk come from enrichment, not Mongo, so the endpoint re-sorts in Python; the pipeline must not cap the fetch below skip+limit.


def _limit_values_after_group(pipeline: list[dict[str, Any]]) -> list[int]:
    """Return every ``$limit`` value in a stage at/after the first ``$group``."""
    seen_group = False
    limits: list[int] = []
    for stage in pipeline:
        if "$group" in stage:
            seen_group = True
        if seen_group and "$limit" in stage:
            limits.append(stage["$limit"])
    return limits


class TestHotspotsPostSortPagination:
    def test_epss_deep_page_pipeline_not_truncated(self):
        # skip=60/limit=20 needs the first 80 epss-ranked groups; fetch must not cap below skip+limit
        _, pipeline, _ = _run_hotspots(agg_results=[], sort_by="epss", skip=60, limit=20)
        for lim in _limit_values_after_group(pipeline):
            assert lim >= 60 + 20, (
                f"post-sort pipeline caps fetch at {lim}, dropping rows needed for "
                "skip=60/limit=20 (needs >= 80 or no cap)"
            )

    def test_risk_deep_page_pipeline_not_truncated(self):
        _, pipeline, _ = _run_hotspots(agg_results=[], sort_by="risk", skip=60, limit=20)
        for lim in _limit_values_after_group(pipeline):
            assert lim >= 60 + 20, (
                f"post-sort pipeline caps fetch at {lim}, dropping rows needed for "
                "skip=60/limit=20 (needs >= 80 or no cap)"
            )

    def test_epss_pipeline_has_no_premature_mongo_skip(self):
        # a Mongo $skip would drop rows in finding_count order before the Python epss re-rank
        _, pipeline, _ = _run_hotspots(agg_results=[], sort_by="epss", skip=60, limit=20)
        assert not any("$skip" in stage for stage in pipeline), (
            "post-sort pipeline must not $skip in Mongo; pagination is applied in Python after the epss/risk re-sort"
        )

    def test_finding_count_sort_still_paginates_in_mongo(self):
        # the finding_count path is globally ordered in Mongo, so $skip/$limit stay in the pipeline
        _, pipeline, _ = _run_hotspots(agg_results=[], sort_by="finding_count", skip=40, limit=20)
        assert any(stage.get("$skip") == 40 for stage in pipeline), "expected $skip in Mongo pipeline"
        assert any(stage.get("$limit") == 20 for stage in pipeline), "expected $limit in Mongo pipeline"


# Finding documents carry scan_created_at (engine._prepare_finding_records); created_at never exists on them.


def _projected_fields_before_group(pipeline: list[dict[str, Any]]) -> set[str]:
    fields: set[str] = set()
    for stage in pipeline:
        if "$group" in stage:
            break
        project = stage.get("$project")
        if project:
            fields.update(project.keys())
    return fields


class TestFirstSeenUsesScanCreatedAt:
    def test_impact_first_seen_min_over_scan_created_at(self):
        _, pipeline, _ = _run_impact(agg_results=[])
        group = _group_stage(pipeline)
        assert group["first_seen"] == {"$min": "$scan_created_at"}
        assert "scan_created_at" in _projected_fields_before_group(pipeline)

    def test_impact_pipeline_never_references_created_at(self):
        _, pipeline, _ = _run_impact(agg_results=[])
        assert "created_at" not in _projected_fields_before_group(pipeline)
        assert "$created_at" not in str(pipeline)

    def test_hotspots_first_seen_min_over_scan_created_at(self):
        _, pipeline, _ = _run_hotspots(agg_results=[])
        group = _group_stage(pipeline)
        assert group["first_seen"] == {"$min": "$scan_created_at"}
        assert "scan_created_at" in _projected_fields_before_group(pipeline)

    def test_hotspots_pipeline_never_references_created_at(self):
        _, pipeline, _ = _run_hotspots(agg_results=[])
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
            "details_list": [{"fixed_version": "4.17.21", "vulnerabilities": []}],
            "affected_projects": 1,
        }
        response, _, _ = _run_impact(agg_results=[row])
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
        response, _, _ = _run_hotspots(agg_results=[row])
        item = response[0]
        assert item.first_seen != ""
        assert item.days_known is not None and item.days_known >= 119


# fix_impact_score, not blast radius, decides the /impact ranking and the top-`limit` cut.
# The KEV/EPSS/maturity boosts come from enrichment, so scoring happens in Python; a Mongo
# blast-radius $limit used to drop severe-but-narrow fixes before they were ever scored.


def _impact_row(
    component: str, ap: int, *, critical: int = 0, high: int = 0, medium: int = 0, low: int = 0
) -> dict[str, Any]:
    return {
        "_id": {"component": component, "version": "1.0.0"},
        "component": component,
        "version": "1.0.0",
        "project_ids": [f"p{i}" for i in range(ap)],
        "total_findings": critical + high + medium + low,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "finding_ids": [f"CVE-{component}"],
        "first_seen": None,
        "details_list": [],
        "affected_projects": ap,
    }


class TestImpactPreScoreIsScoreBase:
    def test_pre_score_equals_unboosted_impact_score(self):
        counts = {"critical": 2, "high": 3, "medium": 1, "low": 4}
        for ap in (0, 1, 5, 10, 50):
            assert impact_pre_score(counts, ap) == calculate_impact_score(
                counts, ap, CVEEnrichmentResult(), has_fix=False, days_known=None
            ), f"pre-score must equal the un-boosted impact score (ap={ap})"

    def test_reach_is_capped_like_the_score(self):
        counts = {"critical": 1, "high": 0, "medium": 0, "low": 0}
        assert impact_pre_score(counts, 10) == impact_pre_score(counts, 9999)
        assert impact_pre_score(counts, 3) < impact_pre_score(counts, 10)


class TestSelectImpactCandidates:
    def test_returns_all_when_not_over_limit(self):
        rows = [_impact_row("a", 5, low=1), _impact_row("b", 3, high=1)]
        assert len(select_impact_candidates(rows, limit=20)) == 2

    def test_keeps_narrow_but_severe_contender(self):
        # 24 broad low-severity groups outrank a narrow critical on blast radius...
        broad = [_impact_row(f"broad{i}", ap=50, low=1) for i in range(24)]  # pre = 1*10 = 10
        narrow = _impact_row("narrow", ap=1, critical=3)  # pre = 30*1 = 30
        cands = select_impact_candidates(broad + [narrow], limit=20)
        assert any(r["component"] == "narrow" for r in cands), (
            "narrow-but-severe fix must survive candidate selection; its boosted ceiling can top the list"
        )

    def test_drops_only_genuinely_unreachable_groups(self):
        top = [_impact_row(f"t{i}", ap=10, critical=1) for i in range(5)]  # pre = 100 (limit-th)
        reachable = _impact_row("reachable", ap=1, critical=2)  # pre 20; 20*B_MAX=166 > 100
        unreachable = _impact_row("unreachable", ap=1, low=1)  # pre 1; 1*B_MAX=8.3 < 100
        cands = select_impact_candidates(top + [reachable, unreachable], limit=5)
        names = {r["component"] for r in cands}
        assert "reachable" in names, "a group whose boosted ceiling clears the limit-th pre-score must be kept"
        assert "unreachable" not in names, "a group that can never reach the top-limit must be dropped"

    def test_threshold_is_limit_pre_score_over_boost_ceiling(self):
        # Exactly at the boundary pre = P_limit / B_MAX must be kept (inclusive).
        top = [_impact_row(f"t{i}", ap=10, critical=1) for i in range(5)]  # P_limit = 100
        boundary_low = round(100 / IMPACT_MAX_SCORE_BOOST) + 1  # low count -> pre just above threshold
        boundary = _impact_row("boundary", ap=1, low=boundary_low)
        cands = select_impact_candidates(top + [boundary], limit=5)
        assert any(r["component"] == "boundary" for r in cands)


class TestImpactEndpointRanksByScoreNotBlastRadius:
    def test_narrow_critical_beats_broad_low_severity(self):
        # Old code $sorted+$limited by blast radius in Mongo: with 24 broad groups the narrow
        # critical never entered the top-5 and was never scored. It must now rank first.
        broad = [_impact_row(f"broad{i}", ap=50, low=1) for i in range(24)]  # pre 10, blast radius 50
        narrow = _impact_row("narrow-critical", ap=2, critical=5)  # pre 50*2 = 100
        response, _, _ = _run_impact(agg_results=broad + [narrow], limit=5)
        names = [item.component for item in response]
        assert "narrow-critical" in names, "narrow critical must surface by fix_impact_score, not blast radius"
        assert response[0].component == "narrow-critical", "highest fix_impact_score must rank first"

    def test_response_capped_at_limit(self):
        rows = [_impact_row(f"c{i}", ap=i + 1, critical=1) for i in range(30)]
        response, _, _ = _run_impact(agg_results=rows, limit=5)
        assert len(response) == 5

    def test_pipeline_does_not_mongo_limit_at_user_limit(self):
        # A Mongo $limit at the page size caps by the blast-radius $sort before any scoring.
        _, pipeline, _ = _run_impact(agg_results=[], limit=7)
        limits = [stage["$limit"] for stage in pipeline if "$limit" in stage]
        assert 7 not in limits, "Mongo must not $limit at the user limit; that caps by blast radius before scoring"
        assert all(lim >= 1000 for lim in limits), "any Mongo $limit must be a large safety cap, not a page size"


def _impact_aggregate_calls(*limits: int) -> int:
    """Run /impact once per given limit (sharing the cache) and count aggregate() calls."""
    from app.api.v1.endpoints.analytics.risk import get_impact_analysis

    user = _admin_user()
    db = MagicMock()
    calls = {"n": 0}

    async def _fake_get_user_project_ids(_u, _d):
        return ["proj-1"]

    async def _fake_get_projects_with_scans(_p, _d):
        return {"proj-1": "P1"}, ["scan-latest"]

    async def _fake_aggregate(_pipeline, **_kw):
        calls["n"] += 1
        return [_impact_row("a", 3, critical=1)]

    repo = MagicMock()
    repo.aggregate = _fake_aggregate

    async def _fake_enrich(_c):
        return {}

    with (
        patch(f"{MODULE}.get_user_project_ids", new=_fake_get_user_project_ids),
        patch(f"{MODULE}.get_projects_with_scans", new=_fake_get_projects_with_scans),
        patch(f"{MODULE}.FindingRepository", return_value=repo),
        patch(f"{MODULE}.get_cve_enrichment", new=_fake_enrich),
    ):
        for lim in limits:
            asyncio.run(get_impact_analysis(current_user=user, db=db, limit=lim))
    return calls["n"]


def _hotspots_aggregate_calls(*sort_bys: str) -> int:
    from app.api.v1.endpoints.analytics.risk import get_vulnerability_hotspots

    user = _admin_user()
    db = MagicMock()
    calls = {"n": 0}

    async def _fake_get_user_project_ids(_u, _d):
        return ["proj-1"]

    async def _fake_get_projects_with_scans(_p, _d):
        return {"proj-1": "P1"}, ["scan-latest"]

    async def _fake_aggregate(_pipeline, **_kw):
        calls["n"] += 1
        return []

    repo = MagicMock()
    repo.aggregate = _fake_aggregate
    dep_repo = MagicMock()
    dep_repo.aggregate = AsyncMock(return_value=[])

    async def _fake_enrich(_c):
        return {}

    with (
        patch(f"{MODULE}.get_user_project_ids", new=_fake_get_user_project_ids),
        patch(f"{MODULE}.get_projects_with_scans", new=_fake_get_projects_with_scans),
        patch(f"{MODULE}.FindingRepository", return_value=repo),
        patch(f"{MODULE}.DependencyRepository", return_value=dep_repo),
        patch(f"{MODULE}.get_cve_enrichment", new=_fake_enrich),
    ):
        for sb in sort_bys:
            asyncio.run(
                get_vulnerability_hotspots(
                    current_user=user, db=db, skip=0, limit=20, sort_by=sb, sort_order="desc"
                )
            )
    return calls["n"]


class TestAnalyticsResultCache:
    def test_impact_repeat_call_hits_cache(self):
        assert _impact_aggregate_calls(20, 20) == 1, "identical /impact request must be served from cache"

    def test_impact_distinct_limit_misses_cache(self):
        assert _impact_aggregate_calls(20, 10) == 2, "a different limit must not reuse a cached result"

    def test_hotspots_repeat_call_hits_cache(self):
        assert _hotspots_aggregate_calls("finding_count", "finding_count") == 1

    def test_hotspots_distinct_sort_misses_cache(self):
        assert _hotspots_aggregate_calls("finding_count", "epss") == 2

    def test_impact_cached_response_matches_fresh(self):
        from app.api.v1.endpoints.analytics.risk import get_impact_analysis

        user = _admin_user()
        db = MagicMock()

        async def _fake_get_user_project_ids(_u, _d):
            return ["proj-1"]

        async def _fake_get_projects_with_scans(_p, _d):
            return {"proj-1": "P1"}, ["scan-latest"]

        async def _fake_aggregate(_pipeline, **_kw):
            return [_impact_row("lodash", 3, critical=2, high=1)]

        repo = MagicMock()
        repo.aggregate = _fake_aggregate

        async def _fake_enrich(_c):
            return {}

        with (
            patch(f"{MODULE}.get_user_project_ids", new=_fake_get_user_project_ids),
            patch(f"{MODULE}.get_projects_with_scans", new=_fake_get_projects_with_scans),
            patch(f"{MODULE}.FindingRepository", return_value=repo),
            patch(f"{MODULE}.get_cve_enrichment", new=_fake_enrich),
        ):
            fresh = asyncio.run(get_impact_analysis(current_user=user, db=db, limit=20))
            cached = asyncio.run(get_impact_analysis(current_user=user, db=db, limit=20))

        assert [r.model_dump() for r in fresh] == [r.model_dump() for r in cached]
