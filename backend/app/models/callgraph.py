"""Call graph data uploaded from CI/CD pipelines for reachability analysis."""

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class ImportEntry(BaseModel):
    """Represents an import statement in source code."""

    module: str
    file: str
    line: int
    imported_symbols: list[str] = []  # e.g. ['get', 'set']
    is_dynamic: bool = False  # Dynamic import (require(), import())


class CallEdge(BaseModel):
    """Represents a function call relationship."""

    caller: str  # fully qualified: file:function
    callee: str  # fully qualified: module:function
    file: str
    line: int
    call_type: str = "direct"  # direct, callback, async, conditional


class ModuleUsage(BaseModel):
    """Aggregated usage information for a module/package."""

    module: str
    import_count: int = 0  # number of files importing this module
    call_count: int = 0  # number of calls into this module
    import_locations: list[str] = []
    used_symbols: list[str] = []
    is_direct_dependency: bool = True  # vs transitive


class Callgraph(MongoDocument, CreatedAtModel):
    """Complete call graph data for a project."""

    project_id: str

    # Pipeline context - crucial for matching callgraph to correct scans
    # pipeline_id is the PRIMARY key for matching (unique per CI/CD run)
    pipeline_id: int | None = None  # GitLab CI pipeline ID (unique)
    branch: str | None = None  # for reference/fallback
    commit_hash: str | None = None

    # Link to specific scan if applicable
    scan_id: str | None = None

    # Language and tool info
    language: str  # javascript, typescript, python, go, java, etc.
    tool: str  # madge, pyan, go-callvis, jdeps, etc.
    tool_version: str | None = None

    # Graph data
    imports: list[ImportEntry] = Field(default_factory=list)
    calls: list[CallEdge] = Field(default_factory=list)

    # Aggregated data for quick lookups
    module_usage: dict[str, ModuleUsage] = Field(default_factory=dict)

    # Metadata
    source_files_analyzed: int = 0
    total_imports: int = 0
    total_calls: int = 0
    analysis_duration_ms: int | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
