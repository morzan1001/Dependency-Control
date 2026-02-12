from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class BaseIngest(BaseModel):
    """Base schema for all ingest payloads."""

    pipeline_id: int = Field(..., description="Unique ID of the pipeline run")
    commit_hash: str = Field(..., description="Git commit hash")
    branch: str = Field(..., description="Git branch name")

    pipeline_iid: Optional[int] = Field(None, description="Project-level pipeline ID")
    project_url: Optional[str] = Field(None, description="URL to the project")
    pipeline_url: Optional[str] = Field(None, description="URL to the pipeline")

    job_id: Optional[int] = Field(None, description="CI Job ID")
    job_started_at: Optional[str] = Field(None, description="Job start time")

    project_name: Optional[str] = Field(None, description="Name of the project")
    commit_message: Optional[str] = Field(None, description="Commit message")
    commit_tag: Optional[str] = Field(None, description="Git tag")
    pipeline_user: Optional[str] = Field(None, description="User who triggered the pipeline")


class ScanContext(BaseModel):
    """Context returned after finding or creating a scan."""

    scan_id: str = Field(..., description="Unique identifier of the scan")
    is_new: bool = Field(..., description="Whether this is a newly created scan")
    pipeline_url: Optional[str] = Field(None, description="URL to the pipeline")

    model_config = ConfigDict(frozen=True)


class SBOMIngest(BaseIngest):
    sboms: List[Dict[str, Any]] = Field(default_factory=list, description="List of SBOM JSON contents")


class ScanStatsResponse(BaseModel):
    """Statistics from scan analysis."""

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class FindingsIngestResponse(BaseModel):
    """Response for findings-based ingest endpoints (TruffleHog, OpenGrep, KICS, Bearer)."""

    scan_id: str = Field(..., description="Unique identifier of the scan")
    findings_count: int = Field(..., description="Number of findings processed")
    waived_count: int = Field(0, description="Number of findings waived")
    stats: ScanStatsResponse = Field(default_factory=ScanStatsResponse, description="Statistics breakdown")


class SecretScanResponse(BaseModel):
    """Response for secret scanning (TruffleHog) - includes failure status."""

    status: str = Field(..., description="'failed' if secrets found, 'success' otherwise")
    scan_id: str = Field(..., description="Unique identifier of the scan")
    findings_count: int = Field(..., description="Number of secrets found")
    waived_count: int = Field(0, description="Number of findings waived")
    message: str = Field(..., description="Human-readable summary")


class SBOMIngestResponse(BaseModel):
    """Response for SBOM ingest endpoint."""

    status: str = Field(..., description="'queued' when successfully submitted")
    scan_id: str = Field(..., description="Unique identifier of the scan")
    message: str = Field(..., description="Human-readable status message")
    sboms_processed: int = Field(0, description="Number of SBOMs successfully processed")
    sboms_failed: int = Field(0, description="Number of SBOMs that failed to process")
    dependencies_count: int = Field(0, description="Total dependencies extracted")
    warnings: List[str] = Field(default_factory=list, description="Processing warnings")


class ProjectConfigResponse(BaseModel):
    """Response for project configuration endpoint."""

    active_analyzers: List[str] = Field(default_factory=list, description="List of active analyzer names")
    retention_days: int = Field(90, description="Scan retention period in days")
