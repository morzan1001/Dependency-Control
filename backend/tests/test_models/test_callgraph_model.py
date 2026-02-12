"""Tests for Callgraph, ImportEntry, CallEdge, ModuleUsage, and ReachabilityResult models."""

import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from app.models.callgraph import (
    Callgraph,
    CallEdge,
    ImportEntry,
    ModuleUsage,
    ReachabilityResult,
)


class TestImportEntry:
    """ImportEntry sub-model validation and defaults."""

    def test_minimal_valid(self):
        """ImportEntry requires module, file, and line."""
        entry = ImportEntry(module="requests", file="app/main.py", line=3)
        assert entry.module == "requests"
        assert entry.file == "app/main.py"
        assert entry.line == 3

    def test_defaults(self):
        """imported_symbols defaults to empty list, is_dynamic to False."""
        entry = ImportEntry(module="os", file="util.py", line=1)
        assert entry.imported_symbols == []
        assert entry.is_dynamic is False

    def test_with_symbols_and_dynamic(self):
        """ImportEntry accepts imported_symbols and is_dynamic."""
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
        """Omitting 'module' raises ValidationError."""
        with pytest.raises(ValidationError):
            ImportEntry(file="a.py", line=1)


class TestCallEdge:
    """CallEdge sub-model validation and defaults."""

    def test_minimal_valid(self):
        """CallEdge requires caller, callee, file, and line."""
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
        """call_type defaults to 'direct'."""
        edge = CallEdge(
            caller="a:f", callee="b:g", file="a.py", line=1
        )
        assert edge.call_type == "direct"

    def test_custom_call_type(self):
        """call_type can be set to async, callback, or conditional."""
        edge = CallEdge(
            caller="a:f", callee="b:g", file="a.py", line=1, call_type="async"
        )
        assert edge.call_type == "async"


class TestModuleUsage:
    """ModuleUsage sub-model validation and defaults."""

    def test_minimal_valid(self):
        """ModuleUsage requires only module."""
        usage = ModuleUsage(module="requests")
        assert usage.module == "requests"

    def test_defaults(self):
        """Numeric and list defaults are correct."""
        usage = ModuleUsage(module="pkg")
        assert usage.import_count == 0
        assert usage.call_count == 0
        assert usage.import_locations == []
        assert usage.used_symbols == []
        assert usage.is_direct_dependency is True

    def test_fully_populated(self):
        """All fields can be set."""
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
    """Callgraph model creation, defaults, and required fields."""

    def _make_callgraph(self, **overrides):
        """Factory for a valid Callgraph with minimal required fields."""
        defaults = {
            "project_id": "proj-1",
            "language": "python",
            "tool": "pyan",
        }
        defaults.update(overrides)
        return Callgraph(**defaults)

    def test_minimal_valid(self):
        """Callgraph can be created with only required fields."""
        cg = self._make_callgraph()
        assert cg.project_id == "proj-1"
        assert cg.language == "python"
        assert cg.tool == "pyan"

    def test_id_auto_generated(self):
        """Each Callgraph gets a unique auto-generated id."""
        a = self._make_callgraph()
        b = self._make_callgraph()
        assert a.id is not None
        assert len(a.id) > 0
        assert a.id != b.id

    def test_optional_fields_default_none(self):
        """Optional scalar fields default to None."""
        cg = self._make_callgraph()
        assert cg.pipeline_id is None
        assert cg.branch is None
        assert cg.commit_hash is None
        assert cg.scan_id is None
        assert cg.tool_version is None
        assert cg.analysis_duration_ms is None

    def test_list_and_dict_defaults_empty(self):
        """List and dict fields default to empty."""
        cg = self._make_callgraph()
        assert cg.imports == []
        assert cg.calls == []
        assert cg.module_usage == {}

    def test_numeric_defaults_zero(self):
        """Numeric metadata fields default to zero."""
        cg = self._make_callgraph()
        assert cg.source_files_analyzed == 0
        assert cg.total_imports == 0
        assert cg.total_calls == 0

    def test_timestamps_auto_set(self):
        """created_at and updated_at are set to UTC datetimes by default."""
        before = datetime.now(timezone.utc)
        cg = self._make_callgraph()
        after = datetime.now(timezone.utc)
        assert before <= cg.created_at <= after
        assert before <= cg.updated_at <= after

    def test_with_nested_imports_and_calls(self):
        """Callgraph accepts nested ImportEntry and CallEdge objects."""
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
        """Callgraph accepts module_usage as a dict of ModuleUsage."""
        cg = self._make_callgraph(
            module_usage={
                "requests": ModuleUsage(module="requests", import_count=3),
            },
        )
        assert "requests" in cg.module_usage
        assert cg.module_usage["requests"].import_count == 3

    def test_missing_required_field_rejected(self):
        """Omitting project_id raises ValidationError."""
        with pytest.raises(ValidationError):
            Callgraph(language="python", tool="pyan")


class TestCallgraphIdAlias:
    """Callgraph _id alias round-trip for MongoDB compatibility."""

    def _make_callgraph(self, **overrides):
        """Factory for a valid Callgraph with minimal required fields."""
        defaults = {
            "project_id": "proj-1",
            "language": "python",
            "tool": "pyan",
        }
        defaults.update(overrides)
        return Callgraph(**defaults)

    def test_model_dump_by_alias_contains_id(self):
        """model_dump(by_alias=True) produces '_id' key."""
        cg = self._make_callgraph()
        dumped = cg.model_dump(by_alias=True)
        assert "_id" in dumped
        assert dumped["_id"] == cg.id

    def test_accepts_id_from_mongo(self):
        """Callgraph accepts _id via validation_alias."""
        cg = Callgraph(
            _id="cg-custom-id",
            project_id="p1",
            language="go",
            tool="go-callvis",
        )
        assert cg.id == "cg-custom-id"

    def test_roundtrip_via_model_dump(self):
        """Callgraph survives model_dump -> reconstruct cycle."""
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


class TestReachabilityResult:
    """ReachabilityResult sub-model validation and defaults."""

    def test_all_defaults(self):
        """ReachabilityResult can be created with no arguments."""
        r = ReachabilityResult()
        assert r.status == "unknown"
        assert r.confidence == "low"
        assert r.analysis_type == "none"
        assert r.import_paths == []
        assert r.call_paths == []
        assert r.used_symbols == []
        assert r.vulnerable_symbols == []
        assert r.vulnerable_symbols_used == []
        assert r.message == ""

    def test_fully_populated(self):
        """ReachabilityResult accepts all fields."""
        r = ReachabilityResult(
            status="reachable",
            confidence="high",
            analysis_type="callgraph",
            import_paths=["/app/main.py"],
            call_paths=[["main.py:run", "requests:get"]],
            used_symbols=["get", "post"],
            vulnerable_symbols=["get"],
            vulnerable_symbols_used=["get"],
            message="Vulnerable function is directly called",
        )
        assert r.status == "reachable"
        assert r.confidence == "high"
        assert r.analysis_type == "callgraph"
        assert len(r.import_paths) == 1
        assert len(r.call_paths) == 1
        assert r.vulnerable_symbols_used == ["get"]
        assert r.message == "Vulnerable function is directly called"

    def test_no_to_dict_method(self):
        """ReachabilityResult does not have a legacy to_dict method."""
        r = ReachabilityResult()
        assert not hasattr(r, "to_dict")

    def test_model_dump_produces_dict(self):
        """model_dump() returns a plain dict with correct keys."""
        r = ReachabilityResult(status="not_reachable", confidence="medium")
        dumped = r.model_dump()
        assert isinstance(dumped, dict)
        assert dumped["status"] == "not_reachable"
        assert dumped["confidence"] == "medium"
