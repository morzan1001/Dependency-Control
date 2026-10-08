"""Tests for Pydantic v2 ConfigDict migration."""

from datetime import datetime, timezone
from typing import ClassVar

import pytest


class TestUseEnumValues:
    """Finding and FindingRecord store enum values as plain strings."""

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


class TestDatetimeSerialization:
    """Pydantic v2 serializes datetimes to ISO strings in JSON mode."""

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
        assert isinstance(data["created_at"], str)
        datetime.fromisoformat(data["created_at"])

    def test_callgraph_datetime_json(self):
        from app.models.callgraph import Callgraph

        cg = Callgraph(
            project_id="p1",
            language="python",
            tool="ast-scan",
        )
        data = cg.model_dump(mode="json")
        assert isinstance(data["created_at"], str)
        datetime.fromisoformat(data["created_at"])

    def test_project_datetime_json(self):
        from app.models.project import Project

        p = Project(name="test")
        data = p.model_dump(mode="json")
        assert isinstance(data["created_at"], str)
        datetime.fromisoformat(data["created_at"])


class TestFromAttributes:
    """Response schemas with from_attributes=True can parse ORM-like objects."""

    def test_user_schema_from_dict(self):
        from app.schemas.user import UserResponse

        user = UserResponse(
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
            webhook_type="generic",
        )
        assert resp.id == "wh-1"
        assert resp.url == "https://example.com/hook"
        assert resp.webhook_type == "generic"


class TestProjectionSchemas:
    """Projection schemas used for MongoDB performance queries."""

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


class TestScanFindingItemEnumValues:
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


class TestSettingsConfig:
    def test_settings_loads(self):
        from app.core.config import settings

        assert settings.PROJECT_NAME == "Dependency Control"
        assert settings.API_V1_STR == "/api/v1"
        assert settings.ALGORITHM == "HS256"

    def test_settings_case_sensitive(self):
        from app.core.config import Settings

        config = Settings.model_config
        assert config.get("case_sensitive") is True


class TestSystemSettingsConfig:
    def test_empty_analyzers_list_persists(self):
        from app.models.system import SystemSettings

        s = SystemSettings(default_active_analyzers=[])
        assert s.default_active_analyzers == []

        doc = s.model_dump(by_alias=True)
        assert doc["default_active_analyzers"] == []

        restored = SystemSettings(**doc)
        assert restored.default_active_analyzers == []


class TestMongoRoundTrip:
    """Simulate MongoDB insert and read round-trip."""

    def test_project_roundtrip(self):
        from app.models.project import Project, ProjectMember

        original = Project(
            name="My App",
            members=[ProjectMember(user_id="u2", role="editor")],
            active_analyzers=["trivy", "osv"],
            retention_days=30,
        )

        mongo_doc = original.model_dump(by_alias=True)
        assert "_id" in mongo_doc

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
        # access_token is excluded (exclude=True) so it never leaks via model_dump.
        assert "access_token" not in mongo_doc

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


class TestGitLabInstanceAccessTokenPersistence:
    def test_model_dump_excludes_access_token(self):
        # Excluded from model_dump so it never leaks in API responses.
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
        from app.models.gitlab_instance import GitLabInstance

        instance = GitLabInstance(
            name="GL",
            url="https://gitlab.com",
            access_token="my-secret-token",
            created_by="admin",
        )
        assert instance.access_token == "my-secret-token"

    def test_repository_create_includes_access_token(self):
        # create() must persist access_token even though model_dump excludes it.
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        from app.models.gitlab_instance import GitLabInstance
        from app.repositories.gitlab_instances import GitLabInstanceRepository

        mock_collection = MagicMock()
        mock_collection.insert_one = AsyncMock()
        mock_db = MagicMock()
        mock_db.__getitem__.return_value = mock_collection

        repo = GitLabInstanceRepository(mock_db)
        instance = GitLabInstance(
            name="GL",
            url="https://gitlab.com",
            access_token="secret-token-123",
            created_by="admin",
        )

        asyncio.run(repo.create(instance))

        mock_collection.insert_one.assert_called_once()
        inserted_doc = mock_collection.insert_one.call_args[0][0]

        assert "access_token" in inserted_doc
        assert inserted_doc["access_token"] == "secret-token-123"

    def test_repository_create_without_token(self):
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        from app.models.gitlab_instance import GitLabInstance
        from app.repositories.gitlab_instances import GitLabInstanceRepository

        mock_collection = MagicMock()
        mock_collection.insert_one = AsyncMock()
        mock_db = MagicMock()
        mock_db.__getitem__.return_value = mock_collection

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
    def test_model_dump_excludes_api_key_hash(self):
        from app.models.project import Project

        p = Project(name="test", api_key_hash="hashed-secret")
        dumped = p.model_dump(by_alias=True)
        assert "api_key_hash" not in dumped

    def test_api_key_hash_accessible_on_instance(self):
        from app.models.project import Project

        p = Project(name="test", api_key_hash="hashed-secret")
        assert p.api_key_hash == "hashed-secret"

    def test_repository_create_excludes_api_key_hash(self):
        # api_key_hash is set later via a $set update (key generation/rotation), so create() omits it.
        from app.models.project import Project

        project = Project(name="test")
        dumped = project.model_dump(by_alias=True)

        assert "api_key_hash" not in dumped
        assert "_id" in dumped
        assert dumped["_id"] == project.id


class TestMongoDocumentIdConsolidation:
    """Persisted models inherit the uuid ``_id`` field from MongoDocument rather than redeclaring it."""

    _CASES: ClassVar[dict[str, dict[str, object]]] = {
        "app.models.archive:ArchiveMetadata": {
            "project_id": "p1",
            "scan_id": "s1",
            "s3_key": "p1/s1.json.gz",
            "s3_bucket": "bucket",
        },
        "app.models.broadcast:Broadcast": {
            "type": "general",
            "target_type": "global",
            "subject": "s",
            "message": "m",
            "created_by": "u1",
        },
        "app.models.callgraph:Callgraph": {
            "project_id": "p1",
            "language": "python",
            "tool": "ast",
        },
        "app.models.dependency:Dependency": {
            "project_id": "p1",
            "scan_id": "s1",
            "name": "requests",
            "version": "2.31.0",
        },
        "app.models.invitation:SystemInvitation": {
            "email": "a@b.com",
            "token": "t",
            "invited_by": "u1",
            "expires_at": datetime.now(timezone.utc),
        },
        "app.models.gitlab_instance:GitLabInstance": {
            "name": "GL",
            "url": "https://gitlab.com",
            "created_by": "admin",
        },
        "app.models.github_instance:GitHubInstance": {
            "name": "GH",
            "url": "https://token.actions.githubusercontent.com",
            "created_by": "admin",
        },
        "app.models.policy_audit_entry:PolicyAuditEntry": {
            "policy_scope": "system",
            "version": 1,
            "action": "seed",
            "timestamp": datetime.now(timezone.utc),
            "snapshot": {},
            "change_summary": "x",
        },
        "app.models.crypto_asset:CryptoAsset": {
            "project_id": "p1",
            "scan_id": "s1",
            "bom_ref": "c1",
            "name": "SHA-256",
            "asset_type": "algorithm",
            "primitive": "hash",
        },
        "app.models.compliance_report:ComplianceReport": {
            "scope": "user",
            "framework": "bsi-tr-02102",
            "format": "csv",
            "status": "pending",
            "requested_by": "u1",
            "requested_at": datetime.now(timezone.utc),
        },
        "app.models.project:Project": {"name": "p"},
        "app.models.project:Scan": {"project_id": "p1", "branch": "main"},
        "app.models.project:AnalysisResult": {
            "scan_id": "s1",
            "analyzer_name": "trivy",
            "result": {},
        },
        "app.models.team:Team": {"name": "DevOps"},
        "app.models.user:User": {"username": "alice", "email": "alice@example.com"},
        "app.models.webhook:Webhook": {
            "url": "https://example.com/hook",
            "events": ["scan_completed"],
        },
    }

    def _load(self, dotted: str):
        import importlib

        module_path, cls_name = dotted.rsplit(":", 1)
        return getattr(importlib.import_module(module_path), cls_name)

    @pytest.mark.parametrize("dotted", sorted(_CASES))
    def test_inherits_mongo_document_without_local_id(self, dotted: str):
        from app.models.types import MongoDocument

        cls = self._load(dotted)
        assert issubclass(cls, MongoDocument)
        assert "id" not in getattr(cls, "__annotations__", {})

    @pytest.mark.parametrize("dotted", sorted(_CASES))
    def test_auto_id_and_alias_roundtrip(self, dotted: str):
        cls = self._load(dotted)
        kwargs = self._CASES[dotted]

        instance = cls(**kwargs)
        assert isinstance(instance.id, str) and len(instance.id) > 0
        assert cls(**kwargs).id != instance.id

        dumped = instance.model_dump(by_alias=True)
        assert dumped["_id"] == instance.id
        assert "id" not in dumped
        assert cls(**dumped) == instance
        assert cls(id="x", **kwargs).id == "x"

    def test_explicit_id_via_alias_is_honored(self):
        from app.models.user import User

        u = User(_id="user-fixed-id", username="bob", email="bob@example.com")
        assert u.id == "user-fixed-id"
        assert u.model_dump(by_alias=True)["_id"] == "user-fixed-id"
