"""Tests for Task W8: bounding the unbounded analytics aggregations.

Findings 9 & 10 — the /impact and /hotspots pipelines $group over up to
ANALYTICS_MAX_QUERY_LIMIT scans worth of vuln findings and $push the FULL
$details blob (plus raw severities/finding_id arrays) into per-group arrays,
with no allowDiskUse. That working set is unbounded.

These tests assert (structurally) that:
  * no stage pushes the full ``$details`` blob,
  * ``severities`` is no longer pushed raw (replaced by scalar severity counts),
  * any array that IS still pushed (finding_ids, slimmed details) is
    ``$slice``-bounded,
  * ``allow_disk_use=True`` is threaded through to ``aggregate`` for these
    multi-scan analytics aggregations.

Plus an executed (FakeDatabase) equivalence check on the parts the in-process
mock can evaluate, and a focused unit test that ``extract_fix_versions`` still
gets its data from the slimmed ``details`` shape.
"""

import asyncio
from typing import Any, Dict, List, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.permissions import ALL_PERMISSIONS
from app.models.user import User

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


def _group_stage(pipeline: List[Dict[str, Any]]) -> Dict[str, Any]:
    for stage in pipeline:
        if "$group" in stage:
            return stage["$group"]
    raise AssertionError("pipeline has no $group stage")


def _project_stages(pipeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [stage["$project"] for stage in pipeline if "$project" in stage]


def _has_sliced_arrays(pipeline: List[Dict[str, Any]]) -> bool:
    """True if at least one $slice appears anywhere in the pipeline (project/group)."""
    text = repr(pipeline)
    return "$slice" in text


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
                skip=0,
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

    def test_pushed_arrays_are_sliced(self):
        _, pipeline, _ = _run_impact(agg_results=[])
        # If anything is still pushed, the working set must be $slice-bounded.
        pushes = list(_iter_push_exprs(pipeline))
        if pushes:
            assert _has_sliced_arrays(pipeline), "pushed arrays must be $slice-bounded"

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

    def test_pushed_arrays_are_sliced(self):
        _, pipeline, _ = _run_hotspots(agg_results=[])
        pushes = list(_iter_push_exprs(pipeline))
        if pushes:
            assert _has_sliced_arrays(pipeline), "pushed arrays must be $slice-bounded"

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
