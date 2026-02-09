"""Tests for Project, Scan, and AnalysisResult models."""

from app.models.project import Project, Scan, AnalysisResult, ProjectMember
from app.core.constants import PROJECT_ROLE_VIEWER


class TestProjectModel:
    def test_minimal_valid_project(self):
        project = Project(name="my-project", owner_id="user-123")
        assert project.name == "my-project"
        assert project.owner_id == "user-123"

    def test_defaults(self):
        project = Project(name="test", owner_id="user-1")
        assert project.retention_days == 90
        assert project.active_analyzers == ["trivy", "osv", "license_compliance", "end_of_life"]
        assert project.members == []
        assert project.stats is None
        assert project.team_id is None
        assert project.gitlab_mr_comments_enabled is False

    def test_id_auto_generated(self):
        project = Project(name="test", owner_id="user-1")
        assert project.id is not None
        assert len(project.id) > 0


class TestProjectMemberModel:
    def test_default_role_is_viewer(self):
        member = ProjectMember(user_id="user-1")
        assert member.role == PROJECT_ROLE_VIEWER


class TestScanModel:
    def test_minimal_valid_scan(self):
        scan = Scan(project_id="proj-1", branch="main")
        assert scan.project_id == "proj-1"
        assert scan.branch == "main"

    def test_defaults(self):
        scan = Scan(project_id="proj-1", branch="main")
        assert scan.status == "pending"
        assert scan.retry_count == 0
        assert scan.is_rescan is False
        assert scan.received_results == []
        assert scan.sbom_refs == []
        assert scan.commit_hash is None

    def test_id_auto_generated(self):
        scan = Scan(project_id="proj-1", branch="main")
        assert scan.id is not None


class TestAnalysisResultModel:
    def test_minimal_valid(self):
        result = AnalysisResult(
            scan_id="scan-1",
            analyzer_name="trivy",
            result={"vulnerabilities": []},
        )
        assert result.scan_id == "scan-1"
        assert result.analyzer_name == "trivy"
        assert result.result == {"vulnerabilities": []}
