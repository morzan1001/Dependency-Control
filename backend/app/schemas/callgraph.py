"""Schemas for parsing and validating callgraph data from various tools."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class CallgraphUploadRequest(BaseModel):
    """Request body for callgraph upload endpoint."""

    format: str = "auto"  # auto, madge, pyan, go-callvis, generic

    # Required if format is generic or auto-detection fails.
    language: Optional[str] = None  # javascript, typescript, python, go, java

    # pipeline_id is the primary key for matching a callgraph to a CI/CD run.
    pipeline_id: Optional[int] = None
    branch: Optional[str] = None  # fallback when no pipeline_id
    commit_hash: Optional[str] = None

    tool: Optional[str] = None
    tool_version: Optional[str] = None

    data: Dict[str, Any]  # shape depends on the 'format' field

    scan_id: Optional[str] = None

    source_files_count: Optional[int] = None
    analysis_duration_ms: Optional[int] = None


class CallgraphUploadResponse(BaseModel):
    """Response from callgraph upload endpoint."""

    success: bool
    message: str
    project_id: str

    imports_parsed: int = 0
    calls_parsed: int = 0
    modules_detected: int = 0

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
