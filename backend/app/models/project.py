import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import PROJECT_ROLE_VIEWER, PROJECT_ROLES
from app.core.notification_prefs import sanitize_notification_preferences
from app.models.base import CreatedAtModel
from app.models.finding import Finding
from app.models.stats import Stats
from app.models.types import PyObjectId


class ProjectMember(BaseModel):
    user_id: str
    role: str = PROJECT_ROLE_VIEWER
    notification_preferences: Dict[str, List[str]] = Field(default_factory=dict)
    username: Optional[str] = None
    inherited_from: Optional[str] = None  # e.g. "Team: DevOps"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in PROJECT_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(PROJECT_ROLES)}")
        return v

    @field_validator("notification_preferences")
    @classmethod
    def validate_notification_preferences(cls, v: Any) -> Dict[str, List[str]]:
        return sanitize_notification_preferences(v)


class Project(CreatedAtModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    name: str
    owner_id: Optional[str] = None  # Deprecated: use team/member admins instead
    team_id: Optional[str] = None
    members: List[ProjectMember] = Field(default_factory=list)
    api_key_hash: Optional[str] = Field(None, exclude=True)
    active_analyzers: List[str] = Field(default_factory=lambda: ["trivy", "osv", "license_compliance", "end_of_life"])
    stats: Optional[Stats] = None
    last_scan_at: Optional[datetime] = None
    latest_scan_id: Optional[str] = None
    retention_days: int = 90  # Default retention period in days
    retention_action: str = "delete"  # "delete", "archive", or "none"
    default_branch: Optional[str] = None
    enforce_notification_settings: bool = False
    # GitLab Integration (Multi-Instance Support)
    gitlab_instance_id: Optional[str] = Field(
        None, description="Reference to GitLabInstance._id. Required if gitlab_project_id is set."
    )
    gitlab_project_id: Optional[int] = Field(
        None, description="GitLab project numeric ID. Must be combined with gitlab_instance_id."
    )
    gitlab_project_path: Optional[str] = Field(
        None, description="GitLab project path (namespace/project). For display purposes."
    )
    gitlab_mr_comments_enabled: bool = Field(
        False, description="Enable posting scan results as comments on merge requests"
    )
    # GitHub Integration (Multi-Instance Support)
    github_instance_id: Optional[str] = Field(
        None, description="Reference to GitHubInstance._id. Required if github_repository_id is set."
    )
    github_repository_id: Optional[str] = Field(
        None, description="GitHub repository numeric ID. Must be combined with github_instance_id."
    )
    github_repository_path: Optional[str] = Field(
        None, description="GitHub repository path (owner/repo). For display purposes."
    )

    # License Policy (deprecated — use analyzer_settings["license_compliance"] instead, kept for backward compat)
    license_policy: Optional[Dict[str, Any]] = Field(
        None,
        description="License compliance policy. Controls severity of copyleft findings based on project context.",
    )

    # Per-analyzer settings: {analyzer_id: {setting_key: value}}
    analyzer_settings: Optional[Dict[str, Dict[str, Any]]] = Field(
        None,
        description="Per-analyzer configuration overrides keyed by analyzer ID.",
    )

    # Branch Lifecycle
    deleted_branches: List[str] = Field(default_factory=list)
    branches_checked_at: Optional[datetime] = None

    # Periodic Scanning
    rescan_enabled: Optional[bool] = None  # If None, use system default
    rescan_interval: Optional[int] = None  # Hours. If None, use system default

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)


class Scan(CreatedAtModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    project_id: str
    branch: str
    commit_hash: Optional[str] = None

    # Pipeline identification
    pipeline_id: Optional[int] = None
    pipeline_iid: Optional[int] = None

    # CI/CD Context
    project_url: Optional[str] = None
    pipeline_url: Optional[str] = None
    job_id: Optional[int] = None
    job_started_at: Optional[str] = None
    project_name: Optional[str] = None
    commit_message: Optional[str] = None
    commit_tag: Optional[str] = None
    pipeline_user: Optional[str] = None

    # This allows us to keep the Scan document small while preserving the raw data.
    sbom_refs: List[Dict[str, Any]] = Field(default_factory=list)

    # Marks scans whose only source is a CBOM (no SBOM); the analysis engine
    # forces crypto analyzers for these even when no SBOM was attached.
    scan_type: Optional[str] = None

    status: str = "pending"
    retry_count: int = 0
    worker_id: Optional[str] = None
    analysis_started_at: Optional[datetime] = None
    error: Optional[str] = None
    findings_summary: Optional[List[Finding]] = None
    findings_count: Optional[int] = None
    stats: Optional[Stats] = None
    completed_at: Optional[datetime] = None

    # Reachability enrichment
    reachability_pending: Optional[bool] = None
    reachability_pending_since: Optional[datetime] = None

    # Re-scan metadata
    is_rescan: bool = False
    original_scan_id: Optional[str] = None
    latest_rescan_id: Optional[str] = None

    # Summary of the latest run (either this scan itself, or the latest re-scan if this is the original)
    latest_run: Optional[Dict[str, Any]] = None

    # Pipeline result tracking - prevents premature completion when multiple scanners run
    last_result_at: Optional[datetime] = None  # When the last scanner result was received
    received_results: List[str] = Field(default_factory=list)  # List of analyzer names that have submitted results

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)


class AnalysisResult(CreatedAtModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    scan_id: str
    analyzer_name: str
    result: Dict[str, Any]

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)
