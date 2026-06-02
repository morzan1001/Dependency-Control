"""Tests for analytics search endpoint: /search vuln_status_map scan_id scoping.

Finding 21 — the vuln_status_map pipeline in search_dependencies_advanced
must restrict to the active scan_ids so that a component fixed in the
latest scan is not flagged as vulnerable due to findings in older scans.
"""

import asyncio
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.user import User
from app.core.permissions import ALL_PERMISSIONS

MODULE = "app.api.v1.endpoints.analytics.search"


def _admin_user():
    return User(
        id="admin-1",
        username="admin",
        email="admin@test.com",
        permissions=list(ALL_PERMISSIONS),
    )


def _make_dep(project_id="proj-1", name="lodash", version="4.17.11"):
    """Return a dict-like dep so that get_attr(dep, key) works correctly."""
    return {
        "project_id": project_id,
        "name": name,
        "version": version,
        "type": "npm",
        "license": None,
        "license_url": None,
        "direct": False,
        "purl": None,
        "source_type": None,
        "source_target": None,
        "layer_digest": None,
        "found_by": None,
        "locations": [],
        "cpes": [],
        "description": None,
        "author": None,
        "publisher": None,
        "group": None,
        "homepage": None,
        "repository_url": None,
        "download_url": None,
        "hashes": {},
        "properties": {},
    }


class TestSearchDependenciesVulnScanScope:
    """search_dependencies_advanced vuln_status_map must be scoped to scan_ids."""

    def _run_search(
        self,
        dep_list,
        vuln_agg_results,
        has_vulnerabilities=True,
        q="lodash",
    ):
        """
        Run search_dependencies_advanced with patched helpers and repos.
        Returns (results, captured_vuln_pipelines).
        """
        from app.api.v1.endpoints.analytics.search import search_dependencies_advanced

        user = _admin_user()
        db = MagicMock()
        captured_pipelines: List[List[Dict[str, Any]]] = []

        async def _fake_get_user_project_ids(_u, _d):
            return ["proj-1"]

        async def _fake_get_projects_with_scans(_project_ids, _d):
            return {"proj-1": "Project 1"}, ["scan-latest"]

        mock_dep_repo = MagicMock()
        mock_dep_repo.count = AsyncMock(return_value=len(dep_list))
        mock_dep_repo.find_many = AsyncMock(return_value=dep_list)

        async def _fake_aggregate(pipeline):
            captured_pipelines.append(pipeline)
            return vuln_agg_results

        mock_finding_repo = MagicMock()
        mock_finding_repo.aggregate = _fake_aggregate

        with (
            patch(f"{MODULE}.get_user_project_ids", new=_fake_get_user_project_ids),
            patch(f"{MODULE}.get_projects_with_scans", new=_fake_get_projects_with_scans),
            patch(f"{MODULE}.DependencyRepository", return_value=mock_dep_repo),
            patch(f"{MODULE}.FindingRepository", return_value=mock_finding_repo),
        ):
            response = asyncio.run(
                search_dependencies_advanced(
                    current_user=user,
                    db=db,
                    q=q,
                    version=None,
                    type=None,
                    source_type=None,
                    has_vulnerabilities=has_vulnerabilities,
                    project_ids=None,
                    sort_by="name",
                    sort_order="asc",
                    skip=0,
                    limit=50,
                )
            )

        return response, captured_pipelines

    def test_vuln_pipeline_includes_scan_id(self):
        """When has_vulnerabilities filter is active, pipeline must include scan_id."""
        dep = _make_dep()
        _, pipelines = self._run_search(
            dep_list=[dep],
            vuln_agg_results=[],
            has_vulnerabilities=True,
        )
        assert pipelines, "aggregate() was never called for the vuln_status_map"
        match_stage = pipelines[0][0]["$match"]
        assert "scan_id" in match_stage, "$match must include scan_id"
        assert match_stage["scan_id"] == {"$in": ["scan-latest"]}

    def test_historical_vuln_does_not_mark_component_as_vulnerable(self):
        """Component present only in an old scan's findings must NOT be returned
        when has_vulnerabilities=True (because the vuln aggregate returns empty
        for the latest scan)."""
        dep = _make_dep(name="lodash")
        # Simulates: aggregate for latest scan returns nothing (old finding filtered out)
        response, _ = self._run_search(
            dep_list=[dep],
            vuln_agg_results=[],  # no vulns in latest scan
            has_vulnerabilities=True,
        )
        # No items should pass the has_vulnerabilities=True filter since
        # the vuln_status_map is empty (latest scan has no findings for this component).
        assert response.items == [], (
            "Component with vuln only in an old scan must not appear when "
            "has_vulnerabilities=True and the latest scan has no matching finding"
        )

    def test_active_scan_vuln_marks_component_as_vulnerable(self):
        """Component with vuln in the latest scan IS returned for has_vulnerabilities=True."""
        dep = _make_dep(name="lodash", project_id="proj-1")
        agg_results = [{"_id": {"project_id": "proj-1", "component": "lodash"}}]
        response, _ = self._run_search(
            dep_list=[dep],
            vuln_agg_results=agg_results,
            has_vulnerabilities=True,
        )
        assert len(response.items) == 1
        assert response.items[0].package == "lodash"

    def test_waived_excluded_from_vuln_status_map(self):
        """The vuln_status_map pipeline must exclude waived findings."""
        dep = _make_dep()
        _, pipelines = self._run_search(
            dep_list=[dep],
            vuln_agg_results=[],
            has_vulnerabilities=True,
        )
        assert pipelines
        match_stage = pipelines[0][0]["$match"]
        assert match_stage.get("waived") == {"$ne": True}
