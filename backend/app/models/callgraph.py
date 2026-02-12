"""
Callgraph Model for Reachability Analysis

Stores call graph data uploaded from CI/CD pipelines for analyzing
whether vulnerable code paths are actually reachable in the project.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.types import PyObjectId


class ImportEntry(BaseModel):
    """Represents an import statement in source code."""

    module: str  # The imported module/package name
    file: str  # Source file path
    line: int  # Line number
    imported_symbols: List[str] = []  # Specific symbols imported (e.g., ['get', 'set'])
    is_dynamic: bool = False  # Dynamic import (require(), import())


class CallEdge(BaseModel):
    """Represents a function call relationship."""

    caller: str  # Fully qualified caller name (file:function)
    callee: str  # Fully qualified callee name (module:function)
    file: str  # Source file where call occurs
    line: int  # Line number of the call
    call_type: str = "direct"  # direct, callback, async, conditional


class ModuleUsage(BaseModel):
    """Aggregated usage information for a module/package."""

    module: str  # Package/module name
    import_count: int = 0  # Number of files importing this module
    call_count: int = 0  # Number of function calls into this module
    import_locations: List[str] = []  # Files that import this module
    used_symbols: List[str] = []  # Functions/classes used from this module
    is_direct_dependency: bool = True  # vs transitive


class Callgraph(BaseModel):
    """Complete call graph data for a project."""

    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    project_id: str

    # Pipeline context - crucial for matching callgraph to correct scans
    # pipeline_id is the PRIMARY key for matching (unique per CI/CD run)
    pipeline_id: Optional[int] = None  # GitLab CI pipeline ID (unique)
    branch: Optional[str] = None  # Git branch (for reference/fallback)
    commit_hash: Optional[str] = None  # Specific commit

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

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(populate_by_name=True)


class ReachabilityResult(BaseModel):
    """Result of reachability analysis for a vulnerability."""

    status: str = "unknown"  # unknown, reachable, not_reachable, partially_reachable
    confidence: str = "low"  # low, medium, high
    analysis_type: str = "none"  # none, import, symbol, callgraph

    # Evidence
    import_paths: List[str] = []  # Files that import the vulnerable package
    call_paths: List[List[str]] = []  # Call chains to vulnerable functions
    used_symbols: List[str] = []  # Which symbols from the package are used

    # Vulnerable function info
    vulnerable_symbols: List[str] = []  # Known vulnerable functions
    vulnerable_symbols_used: List[str] = []  # Subset that are actually used

    # Additional context
    message: str = ""  # Human-readable explanation
