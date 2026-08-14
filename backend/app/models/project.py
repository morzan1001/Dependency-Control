from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import PROJECT_ROLE_VIEWER, PROJECT_ROLES
from app.core.notification_prefs import sanitize_notification_preferences
from app.models.base import CreatedAtModel
from app.models.finding import Finding
from app.models.stats import Stats
from app.models.types import MongoDocument


class ProjectMember(BaseModel):
    user_id: str
    role: str = PROJECT_ROLE_VIEWER
    notification_preferences: dict[str, list[str]] = Field(default_factory=dict)
    username: str | None = None
    inherited_from: str | None = None  # e.g. "Team: DevOps"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in PROJECT_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(PROJECT_ROLES)}")
        return v

    @field_validator("notification_preferences")
    @classmethod
    def validate_notification_preferences(cls, v: Any) -> dict[str, list[str]]:
        return sanitize_notification_preferences(v)


class Project(MongoDocument, CreatedAtModel):
    name: str
    owner_id: str | None = None  # Deprecated: use team/member admins instead
    team_id: str | None = None
    # "manual" team_id assignments are never reverted by GitLab sync;
    # "gitlab"/None may be overwritten by sync.
    team_source: Literal["gitlab", "manual"] | None = None
    members: list[ProjectMember] = Field(default_factory=list)
    api_key_hash: str | None = Field(None, exclude=True)
    active_analyzers: list[str] = Field(default_factory=lambda: ["trivy", "osv", "license_compliance", "end_of_life"])
    stats: Stats | None = None
    last_scan_at: datetime | None = None
    latest_scan_id: str | None = None
    retention_days: int = 90  # Default retention period in days
    retention_action: str = "delete"  # "delete", "archive", or "none"
    default_branch: str | None = None
    enforce_notification_settings: bool = False
    # GitLab Integration (Multi-Instance Support)
    gitlab_instance_id: str | None = Field(
        None, description="Reference to GitLabInstance._id. Required if gitlab_project_id is set."
    )
    gitlab_project_id: int | None = Field(
        None, description="GitLab project numeric ID. Must be combined with gitlab_instance_id."
    )
    gitlab_project_path: str | None = Field(
        None, description="GitLab project path (namespace/project). For display purposes."
    )
    gitlab_mr_comments_enabled: bool = Field(
        False, description="Enable posting scan results as comments on merge requests"
    )
    # GitHub Integration (Multi-Instance Support)
    github_instance_id: str | None = Field(
        None, description="Reference to GitHubInstance._id. Required if github_repository_id is set."
    )
    github_repository_id: str | None = Field(
        None, description="GitHub repository numeric ID. Must be combined with github_instance_id."
    )
    github_repository_path: str | None = Field(
        None, description="GitHub repository path (owner/repo). For display purposes."
    )

    # Deprecated: use analyzer_settings["license_compliance"] instead.
    license_policy: dict[str, Any] | None = Field(
        None,
        description="License compliance policy. Controls severity of copyleft findings based on project context.",
    )

    # Per-analyzer settings: {analyzer_id: {setting_key: value}}
    analyzer_settings: dict[str, dict[str, Any]] | None = Field(
        None,
        description="Per-analyzer configuration overrides keyed by analyzer ID.",
    )

    # Branch Lifecycle
    deleted_branches: list[str] = Field(default_factory=list)
    branches_checked_at: datetime | None = None

    # Periodic Scanning
    rescan_enabled: bool | None = None  # If None, use system default
    rescan_interval: int | None = None  # Hours. If None, use system default

    model_config = ConfigDict(arbitrary_types_allowed=True)


class Scan(MongoDocument, CreatedAtModel):
    project_id: str
    branch: str
    commit_hash: str | None = None

    # Pipeline identification
    pipeline_id: int | None = None
    pipeline_iid: int | None = None

    # CI/CD Context
    project_url: str | None = None
    pipeline_url: str | None = None
    job_id: int | None = None
    job_started_at: str | None = None
    project_name: str | None = None
    commit_message: str | None = None
    commit_tag: str | None = None
    pipeline_user: str | None = None

    # This allows us to keep the Scan document small while preserving the raw data.
    sbom_refs: list[dict[str, Any]] = Field(default_factory=list)

    # Marks scans whose only source is a CBOM (no SBOM); the analysis engine
    # forces crypto analyzers for these even when no SBOM was attached.
    scan_type: str | None = None

    status: str = "pending"
    retry_count: int = 0
    worker_id: str | None = None
    analysis_started_at: datetime | None = None
    error: str | None = None
    # Analyzers that crashed or returned partial coverage in the last run.
    failed_analyzers: list[str] | None = None
    # Post-processor enrichments (EPSS/KEV, reachability) that failed; these do not
    # affect the scan status, so this is the only queryable trace of an outage.
    enrichment_failures: list[str] | None = None
    findings_summary: list[Finding] | None = None
    findings_count: int | None = None
    stats: Stats | None = None
    completed_at: datetime | None = None

    # Reachability enrichment
    reachability_pending: bool | None = None
    reachability_pending_since: datetime | None = None

    # Pinned scans are exempt from retention cleanup (housekeeping filters "pinned": {"$ne": True}).
    pinned: bool = False

    # Re-scan metadata
    is_rescan: bool = False
    original_scan_id: str | None = None
    latest_rescan_id: str | None = None

    # Summary of the latest run (either this scan itself, or the latest re-scan if this is the original)
    latest_run: dict[str, Any] | None = None

    # Pipeline result tracking - prevents premature completion when multiple scanners run
    last_result_at: datetime | None = None  # When the last scanner result was received
    received_results: list[str] = Field(default_factory=list)  # List of analyzer names that have submitted results

    model_config = ConfigDict(arbitrary_types_allowed=True)


class AnalysisResult(MongoDocument, CreatedAtModel):
    scan_id: str
    analyzer_name: str
    result: dict[str, Any]

    model_config = ConfigDict(arbitrary_types_allowed=True)
