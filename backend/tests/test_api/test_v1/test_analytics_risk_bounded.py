"""Tests for Task W8: bounding the unbounded analytics aggregations.

Findings 9 & 10 — the /impact and /hotspots pipelines $group over up to
ANALYTICS_MAX_QUERY_LIMIT scans worth of vuln findings and $push the FULL
$details blob (plus raw severities/finding_id arrays) into per-group arrays,
with no allowDiskUse. That working set is unbounded.

The working set is reduced by three legitimate mechanisms (not a post-$group
$slice, which can't shrink an accumulator Mongo has already materialized):
  * the per-finding ``$details`` blob is $project-slimmed to only the
    fix-version fields BEFORE the $group, so the group accumulates the slim
    shape rather than the arbitrary raw analyzer payload,
  * raw per-finding severity arrays are replaced by four scalar $sum/$cond
    severity counts,
  * the surviving arrays (CVE/finding ids, slimmed details) are accumulated
    with ``$addToSet`` rather than ``$push``, so they collapse to the DISTINCT
    set per (component, version). That naturally bounds them by the real number
    of distinct CVEs / fix-version shapes (the same CVEs repeat across projects
    and dedupe) WITHOUT arbitrarily dropping a high-EPSS/KEV CVE past some
    position — which a post-$group ``$slice`` cap would do, in MATCH order, and
    would silently change enrichment output.
  * ``allow_disk_use=True`` is threaded through to ``aggregate`` so genuinely
    pathological groups spill to disk.

These tests assert the above structurally, execute the scalar severity-count
expressions through the in-process FakeCollection to confirm they equal the old
``count_severities`` output, and verify (via a focused unit test) that
``extract_fix_versions`` still reads from the slimmed ``details`` shape.
"""

import asyncio
from typing import Any, Dict, List, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

from app.api.v1.helpers.analytics import count_severities
from app.core.permissions import ALL_PERMISSIONS
from app.models.user import User
from tests.mocks.fake_mongo import FakeCollection

MODULE = "app.api.v1.endpoints.analytics.risk"


def _admin_user() -> User:
    return User(
        id="admin-1",
        username="admin",
        email="admin@test.com",
        permissions=list(ALL_PERMISSIONS),
    )


# ---------------------------------------------------------------------------
# Pipeline introspection helpers
# ---------------------------------------------------------------------------


def _iter_push_exprs(pipeline: List[Dict[str, Any]]):
    """Yield every ``$push`` accumulator expression in any ``$group`` stage."""
    for stage in pipeline:
        group = stage.get("$group")
        if not group:
            continue
        for acc_name, acc_expr in group.items():
            if isinstance(acc_expr, dict) and "$push" in acc_expr:
                yield acc_name, acc_expr["$push"]


def _iter_add_to_set_exprs(pipeline: List[Dict[str, Any]]):
    """Yield every ``$addToSet`` accumulator expression in any ``$group`` stage."""
    for stage in pipeline:
        group = stage.get("$group")
        if not group:
            continue
        for acc_name, acc_expr in group.items():
            if isinstance(acc_expr, dict) and "$addToSet" in acc_expr:
                yield acc_name, acc_expr["$addToSet"]


def _group_stage(pipeline: List[Dict[str, Any]]) -> Dict[str, Any]:
    for stage in pipeline:
        if "$group" in stage:
            return stage["$group"]
    raise AssertionError("pipeline has no $group stage")


def _sliced_fields_after_group(pipeline: List[Dict[str, Any]]) -> List[str]:
    """Return the names of fields $slice-capped in a $project AFTER the $group.

    A post-$group $slice can't shrink an accumulator Mongo has already
    materialized, and (when applied to enrichment-input arrays in MATCH order)
    silently drops CVEs past the cap — changing max_epss/has_kev/etc. We assert
    enrichment-input arrays are NOT among the post-group $slice fields.
    """
    seen_group = False
    sliced: List[str] = []
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


def _details_is_slimmed_before_group(pipeline: List[Dict[str, Any]]) -> bool:
    """True if a $project slims ``details`` (to fix-version fields only) before
    the first $group. That makes any later ``$push: "$details"`` push the slim
    shape, not the arbitrary raw analyzer blob."""
    for stage in pipeline:
        if "$group" in stage:
            # reached the group without finding a slimming projection first
            return False
        project = stage.get("$project")
        if not project:
            continue
        details_spec = project.get("details")
        # A slimming projection maps details to a dict expression keyed on the
        # fix-version fields — NOT a passthrough (``1``/``True``) of the raw blob.
        if isinstance(details_spec, dict):
            keys = set(details_spec.keys())
            if keys and keys <= {"fixed_version", "vulnerabilities"}:
                return True
    return False


# ---------------------------------------------------------------------------
# Endpoint runners (patch helpers + repos, capture aggregate kwargs)
# ---------------------------------------------------------------------------


def _run_impact(
    agg_results: List[Dict[str, Any]],
    limit: int = 20,
) -> Tuple[Any, List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Run /impact with patched helpers. Returns (response, pipeline, agg_kwargs)."""
    from app.api.v1.endpoints.analytics.risk import get_impact_analysis

    user = _admin_user()
    db = MagicMock()
    captured: List[List[Dict[str, Any]]] = []
    captured_kwargs: List[Dict[str, Any]] = []

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
    agg_results: List[Dict[str, Any]],
    limit: int = 20,
    sort_by: str = "finding_count",
    skip: int = 0,
) -> Tuple[Any, List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Run /hotspots with patched helpers. Returns (response, finding_pipeline, agg_kwargs)."""
    from app.api.v1.endpoints.analytics.risk import get_vulnerability_hotspots

    user = _admin_user()
    db = MagicMock()
    captured: List[List[Dict[str, Any]]] = []
    captured_kwargs: List[Dict[str, Any]] = []

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
        # details must be slimmed (to fix-version fields) BEFORE the $group, so
        # the group never accumulates the arbitrary raw analyzer blob.
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
        # CVE/finding ids must be accumulated as a DISTINCT set (bounded by the
        # real number of distinct CVEs), not $push-ed and then $slice-capped.
        assert "finding_ids" in group, "expected finding_ids accumulator in $group"
        assert "$addToSet" in group["finding_ids"], "finding_ids must use $addToSet (dedupe), not $push"
        assert "$push" not in group["finding_ids"]
        for _acc, push_expr in _iter_push_exprs(pipeline):
            assert push_expr != "$finding_id", "finding_id must not be $push-ed; use $addToSet to dedupe"

    def test_details_not_pushed_and_not_sliced(self):
        _, pipeline, _ = _run_impact(agg_results=[])
        group = _group_stage(pipeline)
        # Slimmed details must be deduped too (no $push), so identical fix-version
        # shapes collapse rather than growing one entry per finding.
        assert "details_list" in group, "expected details_list accumulator in $group"
        assert "$addToSet" in group["details_list"], "details_list must use $addToSet, not $push"

    def test_no_arbitrary_slice_on_enrichment_arrays(self):
        _, pipeline, _ = _run_impact(agg_results=[])
        # A post-$group $slice on enrichment-input arrays would drop high-EPSS/KEV
        # CVEs in MATCH order and change enrichment output. Must not happen.
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
    def _group_row(self) -> Dict[str, Any]:
        """A group row matching the NEW (bounded) pipeline output shape."""
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
    def _group_row(self) -> Dict[str, Any]:
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


# ---------------------------------------------------------------------------
# Executed equivalence — run the REAL $group accumulators through the
# in-process FakeCollection over a small seeded dataset and assert:
#   * the scalar $sum/$cond severity counts equal the old count_severities() output,
#   * $addToSet collapses repeated CVEs to the DISTINCT set (the bound that
#     replaces the arbitrary $slice cap).
# ---------------------------------------------------------------------------


class TestSeverityCountAccumulatorsExecuted:
    def _findings(self) -> List[Dict[str, Any]]:
        # One (component, version) group with the SAME CVE repeated across three
        # projects (so $addToSet must collapse it) plus a mix of severities.
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

    def _group_spec(self) -> Dict[str, Any]:
        # The REAL accumulators from the production module — imported, not copied.
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

        # The CVE that appears in three projects collapses to ONE entry; the set
        # is bounded by the number of DISTINCT ids, not the finding count.
        cve_ids = sorted(fid for fid in finding_ids if fid and fid.startswith("CVE-"))
        assert cve_ids == ["CVE-2021-1", "CVE-2021-2", "CVE-2021-3"]


# ---------------------------------------------------------------------------
# Post-sort (epss/risk) pagination — Finding #1
#
# epss/risk are not in Mongo (they come from enrichment), so the endpoint
# re-sorts in Python and slices ``hotspots[skip : skip + limit]``. The Mongo
# pipeline must therefore hand Python EVERY candidate group; if it caps the
# fetch (the old ``$limit: limit * 3`` with no ``$skip``), any page with
# ``skip >= limit * 3`` is served an empty/truncated set and the visible page
# is ranked against a finding_count-truncated subset rather than the true
# epss/risk ordering.
# ---------------------------------------------------------------------------


def _limit_values_after_group(pipeline: List[Dict[str, Any]]) -> List[int]:
    """Return every ``$limit`` value in a stage at/after the first ``$group``."""
    seen_group = False
    limits: List[int] = []
    for stage in pipeline:
        if "$group" in stage:
            seen_group = True
        if seen_group and "$limit" in stage:
            limits.append(stage["$limit"])
    return limits


class TestHotspotsPostSortPagination:
    def test_epss_deep_page_pipeline_not_truncated(self):
        # A deep page: skip=60, limit=20 needs at least the first 80 globally
        # epss-ranked groups available to Python. The pipeline must not cap the
        # fetch below skip + limit (the old code capped at limit*3 = 60 < 80).
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
        # Pagination for post-sort happens in Python (after the re-sort), so the
        # Mongo pipeline must NOT $skip — a Mongo $skip would drop rows in
        # finding_count order before the epss re-ranking runs.
        _, pipeline, _ = _run_hotspots(agg_results=[], sort_by="epss", skip=60, limit=20)
        assert not any("$skip" in stage for stage in pipeline), (
            "post-sort pipeline must not $skip in Mongo; pagination is applied in Python after the epss/risk re-sort"
        )

    def test_finding_count_sort_still_paginates_in_mongo(self):
        # Regression guard: the non-post-sort path keeps pushing $skip/$limit
        # into Mongo (that path IS globally ordered in Mongo).
        _, pipeline, _ = _run_hotspots(agg_results=[], sort_by="finding_count", skip=40, limit=20)
        assert any(stage.get("$skip") == 40 for stage in pipeline), "expected $skip in Mongo pipeline"
        assert any(stage.get("$limit") == 20 for stage in pipeline), "expected $limit in Mongo pipeline"
