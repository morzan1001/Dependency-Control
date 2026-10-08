"""Tests for the Callgraph and ModuleUsage models."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models.callgraph import Callgraph, ModuleUsage


class TestModuleUsage:
    def test_defaults(self):
        usage = ModuleUsage(module="pkg")
        assert usage.import_count == 0
        assert usage.call_count == 0
        assert usage.import_locations == []
        assert usage.used_symbols == []

    def test_fully_populated(self):
        usage = ModuleUsage(
            module="express",
            import_count=5,
            call_count=12,
            import_locations=["src/app.ts", "src/router.ts"],
            used_symbols=["Router", "json"],
        )
        assert usage.import_count == 5
        assert usage.call_count == 12
        assert len(usage.import_locations) == 2


class TestCallgraphModel:
    def _make_callgraph(self, **overrides):
        defaults = {
            "project_id": "proj-1",
            "language": "python",
            "tool": "ast",
        }
        defaults.update(overrides)
        return Callgraph(**defaults)

    def test_optional_fields_default_none(self):
        cg = self._make_callgraph()
        assert cg.pipeline_id is None
        assert cg.branch is None
        assert cg.commit_hash is None
        assert cg.scan_id is None
        assert cg.tool_version is None
        assert cg.analysis_duration_ms is None

    def test_list_and_dict_defaults_empty(self):
        cg = self._make_callgraph()
        assert cg.module_usage == {}
        assert cg.analyzed_modules == []

    def test_numeric_defaults_zero(self):
        cg = self._make_callgraph()
        assert cg.source_files_analyzed == 0
        assert cg.total_imports == 0
        assert cg.total_calls == 0

    def test_timestamps_auto_set(self):
        before = datetime.now(timezone.utc)
        cg = self._make_callgraph()
        after = datetime.now(timezone.utc)
        assert before <= cg.created_at <= after

    def test_with_module_usage_dict(self):
        cg = self._make_callgraph(
            module_usage={
                "requests": ModuleUsage(module="requests", import_count=3),
            },
        )
        assert "requests" in cg.module_usage
        assert cg.module_usage["requests"].import_count == 3

    def test_analyzed_modules_persisted(self):
        cg = self._make_callgraph(analyzed_modules=["requests", "urllib3"])
        assert cg.model_dump(by_alias=True)["analyzed_modules"] == ["requests", "urllib3"]

    def test_missing_required_field_rejected(self):
        with pytest.raises(ValidationError):
            Callgraph(language="python", tool="ast")


class TestCallgraphIdAlias:
    def _make_callgraph(self, **overrides):
        defaults = {
            "project_id": "proj-1",
            "language": "python",
            "tool": "ast",
        }
        defaults.update(overrides)
        return Callgraph(**defaults)

    def test_roundtrip_via_model_dump(self):
        original = self._make_callgraph(
            pipeline_id=42,
            branch="main",
            commit_hash="abc123",
            source_files_analyzed=100,
        )
        dumped = original.model_dump(by_alias=True)
        restored = Callgraph(**dumped)
        assert restored.id == original.id
        assert restored.pipeline_id == 42
        assert restored.branch == "main"
        assert restored.source_files_analyzed == 100
