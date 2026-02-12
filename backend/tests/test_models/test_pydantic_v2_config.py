"""
Tests for Pydantic v2 ConfigDict migration.

Verifies that all models and schemas work correctly after migrating
from `class Config:` to `model_config = ConfigDict(...)`.
"""

import pytest
from datetime import datetime, timezone
from pydantic import ValidationError


# ---------------------------------------------------------------------------
# Models: populate_by_name + _id alias round-trip
# ---------------------------------------------------------------------------


class TestModelIdAlias:
    """All MongoDB-backed models must accept _id (validation_alias) and
    serialize it back as _id (serialization_alias)."""

    @pytest.mark.parametrize(
        "model_cls,kwargs",
        [
            pytest.param(
                "app.models.project:Project",
                {"name": "p", "owner_id": "u1"},
                id="Project",
            ),
            pytest.param(
                "app.models.project:Scan",
                {"project_id": "p1", "branch": "main"},
                id="Scan",
            ),
            pytest.param(
                "app.models.project:AnalysisResult",
                {"scan_id": "s1", "analyzer_name": "trivy", "result": {}},
                id="AnalysisResult",
            ),
            pytest.param(
                "app.models.user:User",
                {"username": "u", "email": "u@test.com"},
                id="User",
            ),
            pytest.param(
                "app.models.team:Team",
                {"name": "t"},
                id="Team",
            ),
            pytest.param(
                "app.models.waiver:Waiver",
                {"reason": "ok", "created_by": "admin"},
                id="Waiver",
            ),
            pytest.param(
                "app.models.dependency:Dependency",
                {"project_id": "p1", "scan_id": "s1", "name": "pkg", "version": "1.0"},
                id="Dependency",
            ),
            pytest.param(
                "app.models.webhook:Webhook",
                {"url": "https://example.com/hook", "events": ["scan_completed"]},
                id="Webhook",
            ),
            pytest.param(
                "app.models.broadcast:Broadcast",
                {"type": "general", "target_type": "global", "subject": "s", "message": "m", "created_by": "u1"},
                id="Broadcast",
            ),
            pytest.param(
                "app.models.invitation:ProjectInvitation",
                {"project_id": "p1", "email": "a@b.com", "role": "viewer", "token": "t", "invited_by": "u1", "expires_at": datetime.now(timezone.utc)},
                id="ProjectInvitation",
            ),
            pytest.param(
                "app.models.invitation:SystemInvitation",
                {"email": "a@b.com", "token": "t", "invited_by": "u1", "expires_at": datetime.now(timezone.utc)},
                id="SystemInvitation",
            ),
            pytest.param(
                "app.models.github_instance:GitHubInstance",
                {"name": "GH", "url": "https://token.actions.githubusercontent.com", "created_by": "admin"},
                id="GitHubInstance",
            ),
            pytest.param(
                "app.models.gitlab_instance:GitLabInstance",
                {"name": "GL", "url": "https://gitlab.com", "created_by": "admin"},
                id="GitLabInstance",
            ),
            pytest.param(
                "app.models.callgraph:Callgraph",
                {"project_id": "p1", "language": "python", "tool": "pyan"},
                id="Callgraph",
            ),
        ],
    )
    def test_auto_id_and_alias_roundtrip(self, model_cls: str, kwargs: dict):
        """Model generates an ID, serializes with _id alias, and accepts _id back."""
        module_path, cls_name = model_cls.rsplit(":", 1)
        import importlib

        mod = importlib.import_module(module_path)
        cls = getattr(mod, cls_name)

        # 1) Create with auto-generated ID
        instance = cls(**kwargs)
        assert instance.id is not None
        assert len(instance.id) > 0

        # 2) Serialize with alias -> must contain _id
        dumped = instance.model_dump(by_alias=True)
        assert "_id" in dumped
        assert dumped["_id"] == instance.id

        # 3) Reconstruct from MongoDB-style dict (with _id)
        reconstructed = cls(**dumped)
        assert reconstructed.id == instance.id

    @pytest.mark.parametrize(
        "model_cls,kwargs",
        [
            pytest.param(
                "app.models.project:Project",
                {"_id": "custom-id", "name": "p", "owner_id": "u1"},
                id="Project",
            ),
            pytest.param(
                "app.models.user:User",
                {"_id": "custom-id", "username": "u", "email": "u@test.com"},
                id="User",
            ),
            pytest.param(
                "app.models.team:Team",
                {"_id": "custom-id", "name": "t"},
                id="Team",
            ),
        ],
    )
    def test_accepts_id_from_mongodb(self, model_cls: str, kwargs: dict):
        """Models accept _id from MongoDB documents via validation_alias."""
        module_path, cls_name = model_cls.rsplit(":", 1)
        import importlib

        mod = importlib.import_module(module_path)
        cls = getattr(mod, cls_name)

        instance = cls(**kwargs)
        assert instance.id == "custom-id"


# ---------------------------------------------------------------------------
# Models: use_enum_values
# ---------------------------------------------------------------------------


class TestUseEnumValues:
    """Finding and FindingRecord store enum values as plain strings."""

    def test_finding_stores_string_values(self):
        from app.models.finding import Finding, FindingType, Severity

        finding = Finding(
            id="CVE-1",
            type=FindingType.VULNERABILITY,
            severity=Severity.HIGH,
            component="pkg",
            description="desc",
            scanners=["trivy"],
        )
        # use_enum_values=True -> stored as plain strings
        assert finding.type == "vulnerability"
        assert finding.severity == "HIGH"
        assert isinstance(finding.type, str)
        assert isinstance(finding.severity, str)

    def test_finding_record_inherits_enum_config(self):
        from app.models.finding import FindingType, Severity
        from app.models.finding_record import FindingRecord

        record = FindingRecord(
            id="CVE-1",
            type=FindingType.LICENSE,
            severity=Severity.MEDIUM,
            component="pkg",
            description="desc",
            scanners=["osv"],
            project_id="p1",
            scan_id="s1",
            finding_id="CVE-1",
        )
        assert record.type == "license"
        assert record.severity == "MEDIUM"

    def test_finding_accepts_raw_strings(self):
        from app.models.finding import Finding

        finding = Finding(
            id="test",
            type="vulnerability",
            severity="CRITICAL",
            component="pkg",
            description="desc",
            scanners=["trivy"],
        )
        assert finding.type == "vulnerability"
        assert finding.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# Models: datetime serialization (json_encoders removed)
# ---------------------------------------------------------------------------


class TestDatetimeSerialization:
    """After removing json_encoders, Pydantic v2 should still serialize
    datetimes correctly in JSON mode."""

    def test_broadcast_datetime_json(self):
        from app.models.broadcast import Broadcast

        b = Broadcast(
            type="general",
            target_type="global",
            subject="s",
            message="m",
            created_by="u1",
        )
        data = b.model_dump(mode="json")
        # Pydantic v2 serializes datetime to ISO string in JSON mode
        assert isinstance(data["created_at"], str)
        # Should be parseable back
        datetime.fromisoformat(data["created_at"])

    def test_callgraph_datetime_json(self):
        from app.models.callgraph import Callgraph

        cg = Callgraph(
            project_id="p1",
            language="python",
            tool="pyan",
        )
        data = cg.model_dump(mode="json")
        assert isinstance(data["created_at"], str)
        assert isinstance(data["updated_at"], str)
        datetime.fromisoformat(data["created_at"])
        datetime.fromisoformat(data["updated_at"])

    def test_project_datetime_json(self):
        from app.models.project import Project

        p = Project(name="test", owner_id="u1")
        data = p.model_dump(mode="json")
        assert isinstance(data["created_at"], str)
        datetime.fromisoformat(data["created_at"])


# ---------------------------------------------------------------------------
# Schemas: frozen (immutability)
# ---------------------------------------------------------------------------


class TestFrozenConfig:
    """ScanContext with frozen=True should be immutable."""

    def test_scan_context_is_immutable(self):
        from app.schemas.ingest import ScanContext

        ctx = ScanContext(scan_id="s1", is_new=True, pipeline_url="https://example.com")
        with pytest.raises(ValidationError):
            ctx.scan_id = "s2"

    def test_scan_context_values_accessible(self):
        from app.schemas.ingest import ScanContext

        ctx = ScanContext(scan_id="s1", is_new=False)
        assert ctx.scan_id == "s1"
        assert ctx.is_new is False
        assert ctx.pipeline_url is None


# ---------------------------------------------------------------------------
# Schemas: from_attributes
# ---------------------------------------------------------------------------


class TestFromAttributes:
    """Response schemas with from_attributes=True can parse ORM-like objects."""

    def test_user_schema_from_dict(self):
        from app.schemas.user import User as UserSchema

        user = UserSchema(
            _id="user-1",
            username="test",
            email="test@example.com",
            totp_enabled=False,
            is_verified=False,
        )
        assert user.id == "user-1"
        assert user.username == "test"

    def test_team_response_from_dict(self):
        from app.schemas.team import TeamResponse

        resp = TeamResponse(
            _id="team-1",
            name="DevOps",
            members=[{"user_id": "u1", "role": "admin"}],
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        assert resp.id == "team-1"
        assert resp.name == "DevOps"
        assert len(resp.members) == 1

    def test_waiver_response_from_dict(self):
        from app.schemas.waiver import WaiverResponse

        resp = WaiverResponse(
            _id="w-1",
            reason="False positive",
            status="accepted_risk",
            created_by="admin",
            created_at=datetime.now(timezone.utc),
        )
        assert resp.id == "w-1"
        assert resp.reason == "False positive"

    def test_webhook_response_from_dict(self):
        from app.schemas.webhook import WebhookResponse

        resp = WebhookResponse(
            id="wh-1",
            url="https://example.com/hook",
            events=["scan_completed"],
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        assert resp.id == "wh-1"
        assert resp.url == "https://example.com/hook"

    def test_github_instance_response_from_dict(self):
        from app.schemas.github_instance import GitHubInstanceResponse

        resp = GitHubInstanceResponse(
            id="gh-1",
            name="GitHub.com",
            url="https://token.actions.githubusercontent.com",
            created_at=datetime.now(timezone.utc),
            created_by="admin",
        )
        assert resp.id == "gh-1"

    def test_gitlab_instance_response_from_dict(self):
        from app.schemas.gitlab_instance import GitLabInstanceResponse

        resp = GitLabInstanceResponse(
            id="gl-1",
            name="GitLab.com",
            url="https://gitlab.com",
            created_at=datetime.now(timezone.utc),
            created_by="admin",
        )
        assert resp.id == "gl-1"


# ---------------------------------------------------------------------------
# Schemas: projections with populate_by_name
# ---------------------------------------------------------------------------


class TestProjectionSchemas:
    """Projection schemas used for MongoDB performance queries."""

    def test_project_minimal_from_mongo(self):
        from app.schemas.projections import ProjectMinimal

        p = ProjectMinimal(_id="p-1", name="Test Project")
        assert p.id == "p-1"
        assert p.name == "Test Project"

        dumped = p.model_dump(by_alias=True)
        assert dumped["_id"] == "p-1"

    def test_project_with_scan_id(self):
        from app.schemas.projections import ProjectWithScanId

        p = ProjectWithScanId(_id="p-1", name="Test", latest_scan_id="s-1")
        assert p.id == "p-1"
        assert p.latest_scan_id == "s-1"

    def test_scan_with_stats(self):
        from app.schemas.projections import ScanWithStats

        s = ScanWithStats(_id="s-1", stats=None)
        assert s.id == "s-1"
        assert s.stats is None

    def test_scan_minimal(self):
        from app.schemas.projections import ScanMinimal

        s = ScanMinimal(_id="s-1", pipeline_id=42, status="completed")
        assert s.id == "s-1"
        assert s.pipeline_id == 42
        assert s.status == "completed"

    def test_callgraph_minimal(self):
        from app.schemas.projections import CallgraphMinimal

        cg = CallgraphMinimal(_id="cg-1", language="javascript")
        assert cg.id == "cg-1"
        assert cg.language == "javascript"


# ---------------------------------------------------------------------------
# Schemas: ScanFindingItem use_enum_values
# ---------------------------------------------------------------------------


class TestScanFindingItemEnumValues:
    """ScanFindingItem should store enum values as strings."""

    def test_enum_values_stored_as_strings(self):
        from app.models.finding import FindingType, Severity
        from app.schemas.project import ScanFindingItem

        item = ScanFindingItem(
            id="f1",
            finding_id="CVE-2024-0001",
            type=FindingType.VULNERABILITY,
            severity=Severity.CRITICAL,
            component="requests",
            description="Test vuln",
            project_id="p1",
            scan_id="s1",
        )
        assert item.type == "vulnerability"
        assert item.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# Config: SettingsConfigDict
# ---------------------------------------------------------------------------


class TestSettingsConfig:
    """Settings class uses SettingsConfigDict correctly."""

    def test_settings_loads(self):
        from app.core.config import settings

        assert settings.PROJECT_NAME == "Dependency Control"
        assert settings.API_V1_STR == "/api/v1"
        assert settings.ALGORITHM == "HS256"

    def test_settings_case_sensitive(self):
        """Settings should use case_sensitive=True."""
        from app.core.config import Settings

        config = Settings.model_config
        assert config.get("case_sensitive") is True


# ---------------------------------------------------------------------------
# SystemSettings: populate_by_name
# ---------------------------------------------------------------------------


class TestSystemSettingsConfig:
    """SystemSettings model config works."""

    def test_system_settings_defaults(self):
        from app.models.system import SystemSettings

        s = SystemSettings()
        assert s.id == "current"
        assert s.instance_name == "Dependency Control"
        assert s.default_active_analyzers == ["trivy", "osv", "license_compliance", "end_of_life"]

    def test_system_settings_from_mongo(self):
        from app.models.system import SystemSettings

        doc = {
            "_id": "current",
            "instance_name": "My Instance",
            "enforce_2fa": True,
        }
        s = SystemSettings(**doc)
        assert s.id == "current"
        assert s.instance_name == "My Instance"
        assert s.enforce_2fa is True

    def test_custom_analyzers_roundtrip(self):
        """Custom default_active_analyzers survives model_dump → reconstruct."""
        from app.models.system import SystemSettings

        custom = ["trivy", "osv"]
        s = SystemSettings(default_active_analyzers=custom)
        assert s.default_active_analyzers == custom

        doc = s.model_dump(by_alias=True)
        assert doc["default_active_analyzers"] == custom

        restored = SystemSettings(**doc)
        assert restored.default_active_analyzers == custom

    def test_legacy_mongo_doc_without_analyzers_uses_default(self):
        """MongoDB docs created before the feature get the Pydantic default."""
        from app.models.system import SystemSettings

        legacy_doc = {
            "_id": "current",
            "instance_name": "Old Instance",
        }
        s = SystemSettings(**legacy_doc)
        assert s.default_active_analyzers == ["trivy", "osv", "license_compliance", "end_of_life"]

    def test_empty_analyzers_list_persists(self):
        """An admin can explicitly set no default analyzers."""
        from app.models.system import SystemSettings

        s = SystemSettings(default_active_analyzers=[])
        assert s.default_active_analyzers == []

        doc = s.model_dump(by_alias=True)
        assert doc["default_active_analyzers"] == []

        restored = SystemSettings(**doc)
        assert restored.default_active_analyzers == []


# ---------------------------------------------------------------------------
# Full round-trip: model_dump -> reconstruct (simulating MongoDB)
# ---------------------------------------------------------------------------


class TestMongoRoundTrip:
    """Simulate MongoDB insert (model_dump by_alias) and read (reconstruct from dict)."""

    def test_project_roundtrip(self):
        from app.models.project import Project, ProjectMember

        original = Project(
            name="My App",
            owner_id="u1",
            members=[ProjectMember(user_id="u2", role="developer")],
            active_analyzers=["trivy", "osv"],
            retention_days=30,
        )

        # Simulate insert
        mongo_doc = original.model_dump(by_alias=True)
        assert "_id" in mongo_doc

        # Simulate read
        restored = Project(**mongo_doc)
        assert restored.id == original.id
        assert restored.name == "My App"
        assert restored.members[0].user_id == "u2"
        assert restored.active_analyzers == ["trivy", "osv"]
        assert restored.retention_days == 30

    def test_finding_record_roundtrip(self):
        from app.models.finding_record import FindingRecord

        original = FindingRecord(
            id="CVE-2024-0001",
            type="vulnerability",
            severity="HIGH",
            component="requests",
            description="Test",
            scanners=["trivy"],
            project_id="p1",
            scan_id="s1",
            finding_id="CVE-2024-0001",
        )

        mongo_doc = original.model_dump(by_alias=True)
        assert "_id" in mongo_doc

        restored = FindingRecord(**mongo_doc)
        assert restored.mongo_id == original.mongo_id
        assert restored.finding_id == "CVE-2024-0001"
        assert restored.type == "vulnerability"

    def test_gitlab_instance_roundtrip(self):
        from app.models.gitlab_instance import GitLabInstance

        original = GitLabInstance(
            name="Internal GitLab",
            url="https://gitlab.internal.com",
            access_token="secret-token",
            auto_create_projects=True,
            created_by="admin",
        )

        mongo_doc = original.model_dump(by_alias=True)
        assert "_id" in mongo_doc
        # access_token should be excluded (exclude=True in Field)
        assert "access_token" not in mongo_doc

        # Reconstruct without access_token (as it would come from MongoDB without it)
        restored = GitLabInstance(**mongo_doc, access_token=None)
        assert restored.id == original.id
        assert restored.name == "Internal GitLab"
        assert restored.auto_create_projects is True

    def test_webhook_roundtrip(self):
        from app.models.webhook import Webhook

        original = Webhook(
            url="https://example.com/hook",
            events=["scan_completed"],
            project_id="p1",
            secret="my-secret",
            headers={"X-Token": "abc"},
        )

        mongo_doc = original.model_dump(by_alias=True)
        restored = Webhook(**mongo_doc)
        assert restored.id == original.id
        assert restored.url == "https://example.com/hook"
        assert restored.secret == "my-secret"
        assert restored.headers == {"X-Token": "abc"}


# ---------------------------------------------------------------------------
# Bug fixes
# ---------------------------------------------------------------------------


class TestGitLabInstanceAccessTokenPersistence:
    """Verify that access_token is properly handled for MongoDB storage.

    access_token has exclude=True so it's omitted from API responses,
    but the repository must explicitly include it when saving to MongoDB.
    """

    def test_model_dump_excludes_access_token(self):
        """model_dump() should NOT include access_token (for API responses)."""
        from app.models.gitlab_instance import GitLabInstance

        instance = GitLabInstance(
            name="GL",
            url="https://gitlab.com",
            access_token="secret-token",
            created_by="admin",
        )
        dumped = instance.model_dump(by_alias=True)
        assert "access_token" not in dumped

    def test_access_token_accessible_on_instance(self):
        """access_token should still be accessible as an attribute."""
        from app.models.gitlab_instance import GitLabInstance

        instance = GitLabInstance(
            name="GL",
            url="https://gitlab.com",
            access_token="my-secret-token",
            created_by="admin",
        )
        assert instance.access_token == "my-secret-token"

    def test_repository_create_includes_access_token(self):
        """GitLabInstanceRepository.create() must store access_token in MongoDB."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        from app.models.gitlab_instance import GitLabInstance
        from app.repositories.gitlab_instances import GitLabInstanceRepository

        mock_collection = MagicMock()
        mock_collection.insert_one = AsyncMock()
        mock_db = MagicMock()
        mock_db.gitlab_instances = mock_collection

        repo = GitLabInstanceRepository(mock_db)
        instance = GitLabInstance(
            name="GL",
            url="https://gitlab.com",
            access_token="secret-token-123",
            created_by="admin",
        )

        asyncio.run(repo.create(instance))

        # Verify insert_one was called
        mock_collection.insert_one.assert_called_once()
        inserted_doc = mock_collection.insert_one.call_args[0][0]

        # The critical assertion: access_token MUST be in the MongoDB document
        assert "access_token" in inserted_doc
        assert inserted_doc["access_token"] == "secret-token-123"

    def test_repository_create_without_token(self):
        """When no access_token is provided, it should not be in the doc."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        from app.models.gitlab_instance import GitLabInstance
        from app.repositories.gitlab_instances import GitLabInstanceRepository

        mock_collection = MagicMock()
        mock_collection.insert_one = AsyncMock()
        mock_db = MagicMock()
        mock_db.gitlab_instances = mock_collection

        repo = GitLabInstanceRepository(mock_db)
        instance = GitLabInstance(
            name="GL",
            url="https://gitlab.com",
            created_by="admin",
        )

        asyncio.run(repo.create(instance))

        inserted_doc = mock_collection.insert_one.call_args[0][0]
        assert "access_token" not in inserted_doc


class TestProjectApiKeyHashExclusion:
    """Project.api_key_hash has exclude=True — verify it behaves correctly.

    api_key_hash is excluded from model_dump() so it never leaks into API
    responses. Manual project creation uses create_raw() with explicit injection.
    Auto-create never sets it (hash is added later via rotate-key endpoint).
    """

    def test_model_dump_excludes_api_key_hash(self):
        from app.models.project import Project

        p = Project(name="test", owner_id="u1", api_key_hash="hashed-secret")
        dumped = p.model_dump(by_alias=True)
        assert "api_key_hash" not in dumped

    def test_api_key_hash_accessible_on_instance(self):
        from app.models.project import Project

        p = Project(name="test", owner_id="u1", api_key_hash="hashed-secret")
        assert p.api_key_hash == "hashed-secret"

    def test_repository_create_excludes_api_key_hash(self):
        """ProjectRepository.create() uses model_dump which excludes api_key_hash.

        This is by design: api_key_hash is only set later via $set update
        when the user generates/rotates the key. Auto-created projects have
        api_key_hash=None.
        """
        from app.models.project import Project

        project = Project(name="test", owner_id="u1")
        dumped = project.model_dump(by_alias=True)

        # api_key_hash must NOT be in the document sent to MongoDB
        assert "api_key_hash" not in dumped
        # _id must be present for MongoDB
        assert "_id" in dumped
        assert dumped["_id"] == project.id


class TestAutoCreateUsesSystemAnalyzers:
    """Verify that auto-created projects inherit default_active_analyzers
    from SystemSettings, not from the hardcoded Project model default."""

    def test_gitlab_auto_create_uses_custom_analyzers(self):
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch

        from app.api.deps import get_project_for_ingest
        from app.models.system import SystemSettings

        instance_doc = {
            "_id": "inst-x",
            "name": "GL",
            "url": "https://gitlab.example.com",
            "access_token": "tok",
            "is_active": True,
            "created_by": "admin",
            "auto_create_projects": True,
            "sync_teams": False,
        }
        admin_doc = {"_id": "admin-id", "username": "admin", "is_superuser": True}

        from tests.mocks.gitlab import make_oidc_payload
        from tests.mocks.mongodb import create_mock_collection, create_mock_db

        gitlab_instances_coll = create_mock_collection(find_one=instance_doc)
        projects_coll = create_mock_collection(find_one=None)
        projects_coll.insert_one = AsyncMock()
        users_coll = create_mock_collection(find_one=admin_doc)
        db = create_mock_db(
            {
                "gitlab_instances": gitlab_instances_coll,
                "projects": projects_coll,
                "users": users_coll,
            }
        )

        custom_analyzers = ["trivy", "osv"]
        settings = SystemSettings(
            gitlab_integration_enabled=True,
            default_active_analyzers=custom_analyzers,
        )

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://gitlab.example.com"}

            with patch("app.api.deps.GitLabService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(
                    return_value=make_oidc_payload(
                        project_id="42",
                        project_path="group/project",
                        user_email="dev@test.com",
                    )
                )
                MockService.return_value = mock_svc

                result = asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                        settings=settings,
                    )
                )

        assert result.active_analyzers == custom_analyzers

    def test_github_auto_create_uses_custom_analyzers(self):
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch

        from app.api.deps import get_project_for_ingest
        from app.models.system import SystemSettings

        github_instance_doc = {
            "_id": "gh-inst-x",
            "name": "GitHub",
            "url": "https://token.actions.githubusercontent.com",
            "is_active": True,
            "created_by": "admin",
            "auto_create_projects": True,
        }
        admin_doc = {"_id": "admin-id", "username": "admin", "is_superuser": True}

        from tests.mocks.github import make_github_oidc_payload
        from tests.mocks.mongodb import create_mock_collection, create_mock_db

        gitlab_instances_coll = create_mock_collection(find_one=None)
        github_instances_coll = create_mock_collection(find_one=github_instance_doc)
        projects_coll = create_mock_collection(find_one=None)
        projects_coll.insert_one = AsyncMock()
        users_coll = create_mock_collection(find_one=admin_doc)
        db = create_mock_db(
            {
                "gitlab_instances": gitlab_instances_coll,
                "github_instances": github_instances_coll,
                "projects": projects_coll,
                "users": users_coll,
            }
        )

        custom_analyzers = ["end_of_life"]
        settings = SystemSettings(
            gitlab_integration_enabled=True,
            default_active_analyzers=custom_analyzers,
        )

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://token.actions.githubusercontent.com"}

            with patch("app.services.github.GitHubService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(
                    return_value=make_github_oidc_payload(
                        repository_id="789",
                        repository="org/repo",
                        actor="dev",
                    )
                )
                MockService.return_value = mock_svc

                result = asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                        settings=settings,
                    )
                )

        assert result.active_analyzers == custom_analyzers


class TestCallgraphCleanup:
    """Callgraph model: json_encoders removed, to_dict() removed."""

    def test_reachability_result_uses_model_dump(self):
        """ReachabilityResult should use model_dump() instead of to_dict()."""
        from app.models.callgraph import ReachabilityResult

        result = ReachabilityResult(
            status="reachable",
            confidence="high",
            analysis_type="callgraph",
            import_paths=["/app/main.py"],
            used_symbols=["get", "post"],
            vulnerable_symbols=["get"],
            vulnerable_symbols_used=["get"],
            message="Vulnerable function is directly called",
        )

        dumped = result.model_dump()
        assert dumped["status"] == "reachable"
        assert dumped["confidence"] == "high"
        assert dumped["import_paths"] == ["/app/main.py"]
        assert dumped["vulnerable_symbols_used"] == ["get"]
        assert dumped["message"] == "Vulnerable function is directly called"

    def test_reachability_result_no_to_dict(self):
        """to_dict() should no longer exist on ReachabilityResult."""
        from app.models.callgraph import ReachabilityResult

        result = ReachabilityResult()
        assert not hasattr(result, "to_dict")
