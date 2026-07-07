"""Call graph data uploaded from CI/CD pipelines for reachability analysis."""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class ImportEntry(BaseModel):
    """Represents an import statement in source code."""

    module: str
    file: str
    line: int
    imported_symbols: List[str] = []  # e.g. ['get', 'set']
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
    import_locations: List[str] = []
    used_symbols: List[str] = []
    is_direct_dependency: bool = True  # vs transitive


class Callgraph(MongoDocument, CreatedAtModel):
    """Complete call graph data for a project."""

    project_id: str

    # Pipeline context - crucial for matching callgraph to correct scans
    # pipeline_id is the PRIMARY key for matching (unique per CI/CD run)
    pipeline_id: Optional[int] = None  # GitLab CI pipeline ID (unique)
    branch: Optional[str] = None  # for reference/fallback
    commit_hash: Optional[str] = None

    # Link to specific scan if applicable
    scan_id: Optional[str] = None

    # Language and tool info
    language: str  # javascript, typescript, python, go, java, etc.
    tool: str  # madge, pyan, go-callvis, jdeps, etc.
    tool_version: Optional[str] = None

    # Graph data
    imports: List[ImportEntry] = []
    calls: List[CallEdge] = []

    # Aggregated data for quick lookups
    module_usage: Dict[str, ModuleUsage] = {}

    # Metadata
    source_files_analyzed: int = 0
    total_imports: int = 0
    total_calls: int = 0
    analysis_duration_ms: Optional[int] = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
