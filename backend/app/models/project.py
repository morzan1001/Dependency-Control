from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.constants import (
    DEFAULT_ACTIVE_ANALYZERS,
    DEFAULT_RETENTION_DAYS,
    PROJECT_ROLE_VIEWER,
    RETENTION_ACTION_DELETE,
    SCAN_STATUS_PENDING,
    ProjectRole,
)
from app.core.notification_prefs import NotificationPreferences
from app.models.base import CreatedAtModel
from app.models.finding import Finding
from app.models.stats import Stats
from app.models.types import MongoDocument


class ProjectMember(BaseModel):
    user_id: str
    role: ProjectRole = PROJECT_ROLE_VIEWER
    notification_preferences: NotificationPreferences = Field(default_factory=dict)
    username: str | None = None
    inherited_from: str | None = None  # e.g. "Team: DevOps"
    # Read-side only: the role check_project_access grants, MAX(direct, owning teams).
    effective_role: ProjectRole | None = None


class Project(MongoDocument, CreatedAtModel):
    name: str
    owner_id: str | None = None  # Deprecated: use team/member admins instead
    # Ownership: stored as written. Nothing derives these from the scalars below, so a document whose
    # scalar was changed without them keeps the owners it was last written with.
    team_ids: list[str] = Field(default_factory=list, description="Every team that owns this project")
    # Provenance per owner: "manual", or "<provider>:<instance id>" naming the sync that established
    # it. A sync only ever replaces the entries naming its own instance, so a hand assignment and
    # another instance's owner both survive it. Any other value belongs to no sync and is therefore
    # retired by none, which is what a document written before the instance ids degrades to.
    # Unconstrained on purpose: rejecting an unmigrated value here would 500 every read of the
    # project rather than leave its owners in place.
    team_sources: dict[str, str] = Field(default_factory=dict)
    # Written until the legacy scalars are removed, so a pod running older code still reads an owner.
    team_id: str | None = None
    team_source: str | None = None
    members: list[ProjectMember] = Field(default_factory=list)
    api_key_hash: str | None = Field(None, exclude=True)
    active_analyzers: list[str] = Field(default_factory=lambda: list(DEFAULT_ACTIVE_ANALYZERS))
    stats: Stats | None = None
    # The last scanner post from any branch; the rescan clock is Scan.last_rescanned_at.
    last_scan_at: datetime | None = None
    latest_scan_id: str | None = None
    retention_days: int = DEFAULT_RETENTION_DAYS
    retention_action: str = RETENTION_ACTION_DELETE
    default_branch: str | None = None
    enforce_notification_settings: bool = False
    # Preferences of users who reach the project only through an owning team, keyed by user id.
    notification_overrides: dict[str, NotificationPreferences] = Field(default_factory=dict)
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
    github_pr_comments_enabled: bool = Field(
        False, description="Enable posting scan results as comments on pull requests"
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
    # Bumped with every SBOM replacement and CBOM post, so a run can tell its inputs were superseded.
    sbom_generation: int | None = None

    # Marks scans whose only source is a CBOM (no SBOM); the analysis engine
    # forces crypto analyzers for these even when no SBOM was attached.
    scan_type: str | None = None

    status: str = SCAN_STATUS_PENDING
    # Engine re-runs and runs that outlived their worker draw on separate budgets.
    retry_count: int = 0
    stuck_retry_count: int = 0
    worker_id: str | None = None
    # The claim's lease: the holding worker renews it, and housekeeping reclaims a scan once it lapses.
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
    # Archive metadata written before this restore is stale: the scan is live again.
    restored_at: datetime | None = None

    # Monotone: ingest only ever promotes it. Where the artefact runs lives in the releases collection.
    is_release: bool = False

    # Re-scan metadata
    is_rescan: bool = False
    original_scan_id: str | None = None
    latest_rescan_id: str | None = None
    # The scheduled-rescan clock. Lives here because project.last_scan_at is bumped by every
    # scanner post, so a project-wide clock never expires while CI is active.
    last_rescanned_at: datetime | None = None

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
