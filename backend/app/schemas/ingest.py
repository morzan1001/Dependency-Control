from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT, validate_release_environment

_DESC_SCAN_ID = "Unique identifier of the scan"


class BaseIngest(BaseModel):
    """Base schema for all ingest payloads."""

    pipeline_id: int = Field(..., description="Unique ID of the pipeline run")
    commit_hash: str = Field(..., description="Git commit hash")
    branch: str = Field(..., description="Git branch name")

    pipeline_iid: int | None = Field(None, description="Project-level pipeline ID")
    project_url: str | None = Field(None, description="URL to the project")
    pipeline_url: str | None = Field(None, description="URL to the pipeline")

    job_id: int | None = Field(None, description="CI Job ID")
    job_started_at: str | None = Field(None, description="Job start time")

    project_name: str | None = Field(None, description="Name of the project")
    commit_message: str | None = Field(None, description="Commit message")
    commit_tag: str | None = Field(None, description="Git tag")
    pipeline_user: str | None = Field(None, description="User who triggered the pipeline")

    is_release: bool = Field(False, description="Mark this scan as the released/deployed artefact")
    release_version: str | None = Field(None, description="Release name; falls back to commit_tag")
    release_environment: str | None = Field(None, description=f"Slug; falls back to {DEFAULT_RELEASE_ENVIRONMENT}")

    @field_validator("release_environment")
    @classmethod
    def validate_environment(cls, v: str | None) -> str | None:
        return validate_release_environment(v)

    def release_fields(self, released_at: datetime) -> dict[str, Any]:
        """Emitted only for a release payload: every job of one pipeline writes the same scan
        document, so an unconditional $set would let a later job clear the deploy job's mark."""
        if not self.is_release:
            return {}
        return {
            "is_release": True,
            "release_version": self.release_version or self.commit_tag,
            "release_environment": self.release_environment or DEFAULT_RELEASE_ENVIRONMENT,
            "released_at": released_at,
        }


class ScanContext(BaseModel):
    """Context returned after finding or creating a scan."""

    scan_id: str = Field(..., description=_DESC_SCAN_ID)
    is_new: bool = Field(..., description="Whether this is a newly created scan")
    pipeline_url: str | None = Field(None, description="URL to the pipeline")

    model_config = ConfigDict(frozen=True)


class SBOMIngest(BaseIngest):
    sboms: list[dict[str, Any]] = Field(default_factory=list, description="List of SBOM JSON contents")


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

    scan_id: str = Field(..., description=_DESC_SCAN_ID)
    findings_count: int = Field(..., description="Number of findings processed")
    waived_count: int = Field(0, description="Number of findings waived")
    stats: ScanStatsResponse = Field(default_factory=ScanStatsResponse, description="Statistics breakdown")


class SecretScanResponse(BaseModel):
    """Response for secret scanning (TruffleHog) - includes failure status."""

    status: str = Field(..., description="'failed' if secrets found, 'success' otherwise")
    scan_id: str = Field(..., description=_DESC_SCAN_ID)
    findings_count: int = Field(..., description="Number of secrets found")
    waived_count: int = Field(0, description="Number of findings waived")
    message: str = Field(..., description="Human-readable summary")


class SBOMIngestResponse(BaseModel):
    """Response for SBOM ingest endpoint."""

    status: str = Field(..., description="'queued' when successfully submitted")
    scan_id: str = Field(..., description=_DESC_SCAN_ID)
    message: str = Field(..., description="Human-readable status message")
    sboms_processed: int = Field(0, description="Number of SBOMs successfully processed")
    sboms_failed: int = Field(0, description="Number of SBOMs that failed to process")
    dependencies_count: int = Field(0, description="Total dependencies extracted")
    warnings: list[str] = Field(default_factory=list, description="Processing warnings")


class ProjectConfigResponse(BaseModel):
    """Response for project configuration endpoint."""

    project_id: str = Field(..., description="Identifier of the authenticated project")
    active_analyzers: list[str] = Field(default_factory=list, description="List of active analyzer names")
    retention_days: int = Field(90, description="Scan retention period in days")
