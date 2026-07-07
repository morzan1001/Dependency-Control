"""Regression tests for audit fixes in the chat tool registry.

Covers three findings:

1. Findings must be ranked by NUMERIC severity, not the lexicographic order of
   the severity string (which put MEDIUM/LOW above HIGH/CRITICAL and dropped
   CRITICAL findings past the limit cutoff). Also verifies the
   get_top_priority_findings tiebreak reads ``details.epss_score``.
2. ``list_policy_audit_entries`` with ``policy_scope="system"`` must require
   ``system:manage`` (mirrors the HTTP endpoint's admin gate).
3. ``list_compliance_reports`` without a project_id must apply a visibility
   filter instead of listing every scope's reports org-wide.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.chat.tools import ChatToolRegistry
from app.models.user import User
from tests.helpers.permission_presets import PRESET_ADMIN, PRESET_USER


@pytest.fixture
def admin_user():
    return User(
        id="admin-1",
        username="admin",
        email="admin@test.com",
        permissions=list(PRESET_ADMIN),
    )


@pytest.fixture
def plain_user():
    return User(
        id="u-1",
        username="user",
        email="user@test.com",
        permissions=list(PRESET_USER),
    )


def _seed_project(db, project_id="proj-1", **overrides):
    doc = {"_id": project_id, "name": "P", "team_id": None, "latest_scan_id": "scan-1"}
    doc.update(overrides)
    db.projects._docs[project_id] = doc


def _seed_finding(db, fid, severity, scan_id="scan-1", project_id="proj-1", **details):
    db.findings._docs[fid] = {
        "_id": fid,
        "finding_id": fid,
        "scan_id": scan_id,
        "project_id": project_id,
        "severity": severity,
        "type": "vulnerability",
        "component": "pkg",
        "version": "1.0",
        "details": details,
    }


class TestSeverityRanking:
    @pytest.mark.asyncio
    async def test_critical_not_dropped_below_medium(self, db, admin_user):
        # 12 MEDIUM + 3 CRITICAL; default limit is 10. Lexicographic descending
        # sort ("MEDIUM" > "CRITICAL") would fill all 10 slots with MEDIUM and
        # omit every CRITICAL — the exact bug.
        _seed_project(db)
        for i in range(12):
            _seed_finding(db, f"med-{i}", "MEDIUM")
        for i in range(3):
            _seed_finding(db, f"crit-{i}", "CRITICAL")

        result = await ChatToolRegistry()._dispatch(
            "get_project_findings", {"project_id": "proj-1"}, admin_user, db
        )

        sevs = [f["severity"] for f in result["findings"]]
        assert len(sevs) == 10
        assert sevs.count("CRITICAL") == 3, "all CRITICAL findings must survive the limit"
        assert sevs[:3] == ["CRITICAL", "CRITICAL", "CRITICAL"]

    @pytest.mark.asyncio
    async def test_scan_findings_ranked_numerically(self, db, admin_user):
        _seed_project(db)
        db.scans._docs["scan-1"] = {"_id": "scan-1", "project_id": "proj-1"}
        _seed_finding(db, "low-1", "LOW")
        _seed_finding(db, "high-1", "HIGH")
        _seed_finding(db, "crit-1", "CRITICAL")

        result = await ChatToolRegistry()._dispatch(
            "get_scan_findings",
            {"project_id": "proj-1", "scan_id": "scan-1"},
            admin_user,
            db,
        )
        sevs = [f["severity"] for f in result["findings"]]
        assert sevs == ["CRITICAL", "HIGH", "LOW"]

    @pytest.mark.asyncio
    async def test_top_priority_tiebreak_uses_details_epss(self, db, admin_user):
        _seed_project(db)
        _seed_finding(db, "crit-lo", "CRITICAL", epss_score=0.10)
        _seed_finding(db, "crit-hi", "CRITICAL", epss_score=0.90)
        _seed_finding(db, "high-1", "HIGH", epss_score=0.99)

        result = await ChatToolRegistry()._dispatch(
            "get_top_priority_findings", {"project_id": "proj-1"}, admin_user, db
        )
        ids = [f["finding_id"] for f in result["findings"]]
        # CRITICAL before HIGH; within CRITICAL, higher details.epss_score first.
        assert ids[:3] == ["crit-hi", "crit-lo", "high-1"]


class TestPolicyAuditSystemScopeGate:
    @pytest.mark.asyncio
    async def test_non_admin_denied_system_scope(self, db, plain_user):
        result = await ChatToolRegistry()._dispatch(
            "list_policy_audit_entries", {"policy_scope": "system"}, plain_user, db
        )
        assert result == {"error": "Access denied"}

    @pytest.mark.asyncio
    async def test_admin_allowed_system_scope(self, db, admin_user):
        with patch(
            "app.services.chat.tools.registry.list_policy_audit_entries",
            new=AsyncMock(return_value={"entries": [{"version": 1}]}),
        ) as mock_list:
            result = await ChatToolRegistry()._dispatch(
                "list_policy_audit_entries", {"policy_scope": "system"}, admin_user, db
            )
        assert result == {"entries": [{"version": 1}]}
        mock_list.assert_awaited_once()


class TestComplianceReportsVisibility:
    @pytest.mark.asyncio
    async def test_no_project_applies_visibility_filter(self, db, plain_user):
        # user u-1 is a member of team t-1, which owns project p-1.
        db.teams._docs["t-1"] = {
            "_id": "t-1",
            "name": "team-a",
            "members": [{"user_id": "u-1", "role": "member"}],
        }
        db.projects._docs["p-1"] = {"_id": "p-1", "name": "P1", "team_id": "t-1"}

        repo_instance = MagicMock()
        repo_instance.list = AsyncMock(return_value=[])
        with patch(
            "app.services.chat.tools.ComplianceReportRepository",
            return_value=repo_instance,
        ):
            await ChatToolRegistry()._dispatch(
                "list_compliance_reports", {}, plain_user, db
            )

        repo_instance.list.assert_awaited_once()
        extra_filter = repo_instance.list.await_args.kwargs["extra_filter"]
        branches = extra_filter["$or"]

        assert {"scope": "user", "requested_by": "u-1"} in branches
        assert {"scope": "project", "scope_id": {"$in": ["p-1"]}} in branches
        assert {"scope": "team", "scope_id": {"$in": ["t-1"]}} in branches
        # A non-super / non-analytics:global user must NOT see global reports.
        assert {"scope": "global"} not in branches
