"""Tests for Project, Scan, and AnalysisResult models."""

from datetime import datetime, timezone

from app.core.constants import DEFAULT_ACTIVE_ANALYZERS, PROJECT_ROLE_VIEWER
from app.models.project import AnalysisResult, Project, ProjectMember, Scan


class TestProjectModel:
    def test_defaults(self):
        project = Project(name="test", owner_id="user-1")
        assert project.retention_days == 90
        assert project.active_analyzers == list(DEFAULT_ACTIVE_ANALYZERS)
        assert project.members == []
        assert project.stats is None
        assert project.team_ids == []
        assert project.gitlab_mr_comments_enabled is False


class TestProjectMemberModel:
    def test_default_role_is_viewer(self):
        member = ProjectMember(user_id="user-1")
        assert member.role == PROJECT_ROLE_VIEWER


class TestScanModel:
    def test_defaults(self):
        scan = Scan(project_id="proj-1", branch="main")
        assert scan.status == "pending"
        assert scan.retry_count == 0
        assert scan.is_rescan is False
        assert scan.received_results == []
        assert scan.sbom_refs == []
        assert scan.commit_hash is None

    def test_pinned_defaults_to_false(self):
        scan = Scan(project_id="proj-1", branch="main")
        assert scan.pinned is False

    def test_pinned_survives_hydration_and_serialization(self):
        doc = {"_id": "scan-1", "project_id": "proj-1", "branch": "main", "pinned": True}
        scan = Scan(**doc)
        assert scan.pinned is True
        assert scan.model_dump(by_alias=True)["pinned"] is True

    def test_restored_at_survives_hydration_and_serialization(self):
        restored_at = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        doc = {"_id": "scan-1", "project_id": "proj-1", "branch": "main", "restored_at": restored_at}
        assert Scan(**doc).model_dump(by_alias=True)["restored_at"] == restored_at


class TestAnalysisResultModel:
    def test_minimal_valid(self):
        result = AnalysisResult(scan_id="scan-1", analyzer_name="trivy")
        assert (result.scan_id, result.analyzer_name, result.source) == ("scan-1", "trivy", None)
