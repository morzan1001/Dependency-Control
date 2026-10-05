"""Schemas for parsing and validating callgraph data from various tools."""

from typing import Any

from pydantic import BaseModel


class CallgraphUploadRequest(BaseModel):
    """Request body for callgraph upload endpoint."""

    format: str = "auto"  # auto, madge, generic

    # Required if format is generic or auto-detection fails.
    language: str | None = None  # javascript, typescript, python, go, java

    # Matched on scan_id (uuid5 of project+pipeline+commit), else on pipeline_id (GitLab pipeline or GitHub run).
    pipeline_id: int | None = None
    branch: str | None = None
    commit_hash: str | None = None

    tool: str | None = None
    tool_version: str | None = None

    data: dict[str, Any]  # shape depends on the 'format' field

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


class DeleteCallgraphResponse(BaseModel):
    """Response for delete callgraph endpoint."""

    success: bool
    message: str
