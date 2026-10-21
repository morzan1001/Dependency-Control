from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.compliance_report import ComplianceReport
from app.models.user import User
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools._arguments import checked_arguments
from tests.helpers.permission_presets import PRESET_USER

_NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
_PROJECT = "proj-1"
_BRANCH = "main"
_SCAN = "scan-1"


@pytest.fixture
def plain_user():
    return User(
        id="u-1",
        username="user",
        email="user@test.com",
        permissions=list(PRESET_USER),
    )


def _seed_project(db, project_id=_PROJECT, **overrides):
    doc = {
        "_id": project_id,
        "name": "P",
        "default_branch": _BRANCH,
        "deleted_branches": [],
        "latest_scan_id": _SCAN,
    }
    doc.update(overrides)
    db.projects._docs[project_id] = doc
    db.scans._docs.setdefault(
        _SCAN,
        {
            "_id": _SCAN,
            "project_id": project_id,
            "branch": _BRANCH,
            "status": SCAN_STATUS_COMPLETED,
            "created_at": _NOW,
        },
    )


async def _dispatch(tool: str, args: dict, user: User, db) -> dict:
    return await ChatToolRegistry()._dispatch(tool, checked_arguments(tool, args), user, db)


def _seed_finding(db, fid, severity, scan_id=_SCAN, project_id=_PROJECT, **details):
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
        # 12 MEDIUM + 3 CRITICAL, limit 10: a lexicographic sort would drop every CRITICAL.
        _seed_project(db)
        for i in range(12):
            _seed_finding(db, f"med-{i}", "MEDIUM")
        for i in range(3):
            _seed_finding(db, f"crit-{i}", "CRITICAL")

        result = await _dispatch("get_scan_findings", {"project_id": "proj-1"}, admin_user, db)

        sevs = [f["severity"] for f in result["findings"]]
        assert len(sevs) == 10
        assert sevs.count("CRITICAL") == 3, "all CRITICAL findings must survive the limit"
        assert sevs[:3] == ["CRITICAL", "CRITICAL", "CRITICAL"]

    @pytest.mark.asyncio
    async def test_scan_findings_ranked_numerically(self, db, admin_user):
        _seed_project(db)
        _seed_finding(db, "low-1", "LOW")
        _seed_finding(db, "high-1", "HIGH")
        _seed_finding(db, "crit-1", "CRITICAL")

        result = await _dispatch(
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

        result = await _dispatch("get_top_priority_findings", {"project_id": "proj-1"}, admin_user, db)
        ids = [f["finding_id"] for f in result["findings"]]
        # CRITICAL before HIGH; within CRITICAL, higher details.epss_score first.
        assert ids[:3] == ["crit-hi", "crit-lo", "high-1"]


class TestPolicyAuditSystemScopeGate:
    @pytest.mark.asyncio
    async def test_non_admin_denied_system_scope(self, db, plain_user):
        result = await _dispatch("list_policy_audit_entries", {"policy_scope": "system"}, plain_user, db)
        assert result == {"error": "Access denied"}

    @pytest.mark.asyncio
    async def test_admin_allowed_system_scope(self, db, admin_user):
        with patch(
            "app.services.chat.tools.registry.list_policy_audit_entries",
            new=AsyncMock(return_value={"entries": [{"version": 1}]}),
        ) as mock_list:
            result = await _dispatch("list_policy_audit_entries", {"policy_scope": "system"}, admin_user, db)
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
        db.projects._docs["p-1"] = {"_id": "p-1", "name": "P1", "team_ids": ["t-1"]}
        for report_id, scope, scope_id, requested_by in (
            ("own", "user", None, "u-1"),
            ("their-project", "project", "p-1", "u-2"),
            ("their-team", "team", "t-1", "u-2"),
            ("global", "global", None, "u-2"),
            ("someone-else-s", "user", None, "u-2"),
            ("foreign-project", "project", "p-9", "u-2"),
        ):
            db.compliance_reports._docs[report_id] = ComplianceReport(
                id=report_id,
                scope=scope,
                scope_id=scope_id,
                framework=ReportFramework.LICENSE_AUDIT,
                format=ReportFormat.PDF,
                status=ReportStatus.COMPLETED,
                requested_by=requested_by,
                requested_at=_NOW,
            ).model_dump(by_alias=True)

        result = await _dispatch("list_compliance_reports", {}, plain_user, db)

        assert sorted(r["_id"] for r in result["reports"]) == ["own", "their-project", "their-team"]
