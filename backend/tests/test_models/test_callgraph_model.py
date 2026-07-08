"""Tests for Callgraph, ImportEntry, CallEdge, and ModuleUsage models."""

import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from app.models.callgraph import (
    Callgraph,
    CallEdge,
    ImportEntry,
    ModuleUsage,
)


class TestImportEntry:
    def test_minimal_valid(self):
        entry = ImportEntry(module="requests", file="app/main.py", line=3)
        assert entry.module == "requests"
        assert entry.file == "app/main.py"
        assert entry.line == 3

    def test_defaults(self):
        entry = ImportEntry(module="os", file="util.py", line=1)
        assert entry.imported_symbols == []
        assert entry.is_dynamic is False

    def test_with_symbols_and_dynamic(self):
        entry = ImportEntry(
            module="lodash",
            file="src/index.js",
            line=5,
            imported_symbols=["get", "set"],
            is_dynamic=True,
        )
        assert entry.imported_symbols == ["get", "set"]
        assert entry.is_dynamic is True

    def test_missing_required_field_rejected(self):
        with pytest.raises(ValidationError):
            ImportEntry(file="a.py", line=1)


class TestCallEdge:
    def test_minimal_valid(self):
        edge = CallEdge(
            caller="app/main.py:main",
            callee="requests:get",
            file="app/main.py",
            line=10,
        )
        assert edge.caller == "app/main.py:main"
        assert edge.callee == "requests:get"
        assert edge.file == "app/main.py"
        assert edge.line == 10

    def test_default_call_type(self):
        edge = CallEdge(caller="a:f", callee="b:g", file="a.py", line=1)
        assert edge.call_type == "direct"

    def test_custom_call_type(self):
        edge = CallEdge(caller="a:f", callee="b:g", file="a.py", line=1, call_type="async")
        assert edge.call_type == "async"


class TestModuleUsage:
    def test_minimal_valid(self):
        usage = ModuleUsage(module="requests")
        assert usage.module == "requests"

    def test_defaults(self):
        usage = ModuleUsage(module="pkg")
        assert usage.import_count == 0
        assert usage.call_count == 0
        assert usage.import_locations == []
        assert usage.used_symbols == []
        assert usage.is_direct_dependency is True

    def test_fully_populated(self):
        usage = ModuleUsage(
            module="express",
            import_count=5,
            call_count=12,
            import_locations=["src/app.ts", "src/router.ts"],
            used_symbols=["Router", "json"],
            is_direct_dependency=False,
        )
        assert usage.import_count == 5
        assert usage.call_count == 12
        assert len(usage.import_locations) == 2
        assert usage.is_direct_dependency is False


class TestCallgraphModel:
    def _make_callgraph(self, **overrides):
        defaults = {
            "project_id": "proj-1",
            "language": "python",
            "tool": "pyan",
        }
        defaults.update(overrides)
        return Callgraph(**defaults)

    def test_minimal_valid(self):
        cg = self._make_callgraph()
        assert cg.project_id == "proj-1"
        assert cg.language == "python"
        assert cg.tool == "pyan"

    def test_id_auto_generated(self):
        a = self._make_callgraph()
        b = self._make_callgraph()
        assert a.id is not None
        assert len(a.id) > 0
        assert a.id != b.id

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
        assert cg.imports == []
        assert cg.calls == []
        assert cg.module_usage == {}

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
        assert before <= cg.updated_at <= after

    def test_with_nested_imports_and_calls(self):
        cg = self._make_callgraph(
            imports=[
                ImportEntry(module="requests", file="main.py", line=1),
            ],
            calls=[
                CallEdge(caller="main.py:run", callee="requests:get", file="main.py", line=5),
            ],
        )
        assert len(cg.imports) == 1
        assert cg.imports[0].module == "requests"
        assert len(cg.calls) == 1
        assert cg.calls[0].callee == "requests:get"

    def test_with_module_usage_dict(self):
        cg = self._make_callgraph(
            module_usage={
                "requests": ModuleUsage(module="requests", import_count=3),
            },
        )
        assert "requests" in cg.module_usage
        assert cg.module_usage["requests"].import_count == 3

    def test_missing_required_field_rejected(self):
        with pytest.raises(ValidationError):
            Callgraph(language="python", tool="pyan")


class TestCallgraphIdAlias:
    def _make_callgraph(self, **overrides):
        defaults = {
            "project_id": "proj-1",
            "language": "python",
            "tool": "pyan",
        }
        defaults.update(overrides)
        return Callgraph(**defaults)

    def test_model_dump_by_alias_contains_id(self):
        cg = self._make_callgraph()
        dumped = cg.model_dump(by_alias=True)
        assert "_id" in dumped
        assert dumped["_id"] == cg.id

    def test_accepts_id_from_mongo(self):
        cg = Callgraph(
            _id="cg-custom-id",
            project_id="p1",
            language="go",
            tool="go-callvis",
        )
        assert cg.id == "cg-custom-id"

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
