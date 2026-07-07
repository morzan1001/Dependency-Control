"""
Callgraph Ingest Schema

Schemas for parsing and validating callgraph data from various tools.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class CallgraphUploadRequest(BaseModel):
    """Request body for callgraph upload endpoint."""

    # Format detection
    format: str = "auto"  # auto, madge, pyan, go-callvis, generic

    # Language (required if format is generic or auto-detection fails)
    language: Optional[str] = None  # javascript, typescript, python, go, java

    # Pipeline context (for exact matching with SBOM scans)
    # pipeline_id is the PRIMARY key - ensures callgraph matches exact CI/CD run
    pipeline_id: Optional[int] = None  # GitLab CI pipeline ID (preferred)
    branch: Optional[str] = None  # Git branch (fallback if no pipeline_id)
    commit_hash: Optional[str] = None  # Specific commit (optional, for traceability)

    # Tool info
    tool: Optional[str] = None
    tool_version: Optional[str] = None

    # The actual callgraph data (format depends on 'format' field)
    data: Dict[str, Any]

    # Optional: link to a specific scan
    scan_id: Optional[str] = None

    # Optional: metadata
    source_files_count: Optional[int] = None
    analysis_duration_ms: Optional[int] = None


class CallgraphUploadResponse(BaseModel):
    """Response from callgraph upload endpoint."""

    success: bool
    message: str
    project_id: str

    # Stats
    imports_parsed: int = 0
    calls_parsed: int = 0
    modules_detected: int = 0

    # Warnings
    warnings: List[str] = []


class ModuleUsageItem(BaseModel):
    """Single module usage entry."""

    name: str
    module: str
    import_count: int = 0
    call_count: int = 0
    import_locations: List[str] = []
    used_symbols: List[str] = []


class ModuleUsageResponse(BaseModel):
    """Response for module usage endpoint."""

    project_id: str
    language: Optional[str] = None
    modules: List[ModuleUsageItem] = []


class CallgraphResponse(BaseModel):
    """Response for get callgraph endpoint."""

    project_id: str
    pipeline_id: Optional[int] = None
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    scan_id: Optional[str] = None
    language: str
    tool: Optional[str] = None
    tool_version: Optional[str] = None
    imports: List[Dict[str, Any]] = []
    calls: List[Dict[str, Any]] = []
    module_usage: Dict[str, Any] = {}
    source_files_analyzed: int = 0
    total_imports: int = 0
    total_calls: int = 0
    analysis_duration_ms: Optional[int] = None


class DeleteCallgraphResponse(BaseModel):
    """Response for delete callgraph endpoint."""

    success: bool
    message: str
