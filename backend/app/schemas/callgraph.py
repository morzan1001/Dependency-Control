"""Schemas for parsing and validating callgraph data from various tools."""

from typing import Any

from pydantic import BaseModel


class CallgraphUploadRequest(BaseModel):
    """Request body for callgraph upload endpoint."""

    format: str = "auto"  # auto, madge, generic

    # Required if format is generic or auto-detection fails.
    language: str | None = None  # javascript, typescript, python, go, java

    # pipeline_id is the primary key for matching a callgraph to a CI/CD run.
    pipeline_id: int | None = None
    branch: str | None = None  # fallback when no pipeline_id
    commit_hash: str | None = None

    tool: str | None = None
    tool_version: str | None = None

    data: dict[str, Any]  # shape depends on the 'format' field

    scan_id: str | None = None

    source_files_count: int | None = None
    analysis_duration_ms: int | None = None


class CallgraphUploadResponse(BaseModel):
    """Response from callgraph upload endpoint."""

    success: bool
    message: str
    project_id: str

    imports_parsed: int = 0
    calls_parsed: int = 0
    modules_detected: int = 0
    analyzed_modules_count: int = 0

    warnings: list[str] = []


class ModuleUsageItem(BaseModel):
    """Single module usage entry."""

    name: str
    module: str
    import_count: int = 0
    call_count: int = 0
    import_locations: list[str] = []
    used_symbols: list[str] = []


class ModuleUsageResponse(BaseModel):
    """Response for module usage endpoint."""

    project_id: str
    language: str | None = None
    modules: list[ModuleUsageItem] = []


class CallgraphResponse(BaseModel):
    """Response for get callgraph endpoint."""

    project_id: str
    pipeline_id: int | None = None
    branch: str | None = None
    commit_hash: str | None = None
    scan_id: str | None = None
    language: str
    tool: str | None = None
    tool_version: str | None = None
    imports: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    module_usage: dict[str, Any] = {}
    analyzed_modules: list[str] = []
    source_files_analyzed: int = 0
    total_imports: int = 0
    total_calls: int = 0
    analysis_duration_ms: int | None = None


class DeleteCallgraphResponse(BaseModel):
    """Response for delete callgraph endpoint."""

    success: bool
    message: str
