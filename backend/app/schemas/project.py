from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import PROJECT_ROLE_VIEWER, PROJECT_ROLES
from app.core.notification_prefs import sanitize_notification_preferences
from app.models.finding import FindingType, Severity
from app.models.license import DeploymentModel, DistributionModel, LibraryUsage
from app.models.project import Project, Scan


class LicensePolicySchema(BaseModel):
    """License compliance policy controlling how copyleft findings are evaluated.

    Field types reuse the ``str``-enums from :mod:`app.models.license` so the API
    contract and the license analyzer share one source of truth;
    ``use_enum_values``/``validate_default`` serialize values as plain strings.
    """

    model_config = ConfigDict(use_enum_values=True, validate_default=True)

    distribution_model: DistributionModel = Field(
        DistributionModel.DISTRIBUTED,
        description="How the project is distributed: internal_only (no external distribution), "
        "distributed (binary/source to third parties), open_source (project is open source)",
    )
    deployment_model: DeploymentModel = Field(
        DeploymentModel.NETWORK_FACING,
        description="How the project is deployed: network_facing (SaaS/web/API), "
        "cli_batch (CLI/batch/daemon), desktop, embedded",
    )
    library_usage: LibraryUsage = Field(
        LibraryUsage.MIXED,
        description="How dependencies are used: unmodified (as-is via public API), "
        "modified (forked/patched), mixed (some modified)",
    )
    allow_strong_copyleft: bool = Field(False, description="Allow GPL-style licenses (reduces severity to INFO)")
    allow_network_copyleft: bool = Field(False, description="Allow AGPL/SSPL licenses (reduces severity)")


class BranchInfo(BaseModel):
    name: str
    is_active: bool
    last_scan_at: datetime | None = None


class ProjectWithTeam(Project):
    """Project with team name enrichment for list views."""

    team_name: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ProjectList(BaseModel):
    items: list[Project]
    total: int
    page: int
    size: int
    pages: int


class ProjectListEnriched(BaseModel):
    """Project list with team names enriched."""

    items: list[ProjectWithTeam]
    total: int
    page: int
    size: int
    pages: int


class ProjectCreate(BaseModel):
    name: str = Field(
        ..., min_length=1, max_length=200, description="The name of the project", examples=["My Awesome App"]
    )
    team_id: str | None = Field(None, description="ID of the team this project belongs to")
    active_analyzers: list[str] = Field(
        default_factory=lambda: ["trivy", "osv", "license_compliance", "end_of_life"],
        description="List of analyzers to run on this project",
        examples=[["end_of_life", "os_malware", "trivy"]],
    )
    retention_days: int | None = Field(90, description="Number of days to keep scan history", ge=1)
    retention_action: str | None = Field(
        "delete",
        description="Action when retention period expires: delete, archive, or none",
    )
    license_policy: LicensePolicySchema | None = Field(
        None, description="License compliance policy controlling copyleft finding severity"
    )
    analyzer_settings: dict[str, dict[str, Any]] | None = Field(
        None, description="Per-analyzer configuration overrides keyed by analyzer ID"
    )


class ProjectUpdate(BaseModel):
    name: str | None = Field(None, description="New name for the project")
    team_id: str | None = Field(None, description="Transfer project to a team")
    active_analyzers: list[str] | None = Field(None, description="Updated list of active analyzers")
    retention_days: int | None = Field(None, description="Number of days to keep scan history", ge=1)
    retention_action: str | None = Field(
        None,
        description="Action when retention period expires: delete, archive, or none",
    )
    default_branch: str | None = Field(None, description="Default branch to show in dashboard")
    gitlab_mr_comments_enabled: bool | None = Field(None, description="Post scan results as MR comments on GitLab")
    enforce_notification_settings: bool | None = Field(
        None, description="Enforce admin notification settings for all members"
    )
    license_policy: LicensePolicySchema | None = Field(
        None, description="License compliance policy controlling copyleft finding severity"
    )
    analyzer_settings: dict[str, dict[str, Any]] | None = Field(
        None, description="Per-analyzer configuration overrides keyed by analyzer ID"
    )


class ProjectMemberInvite(BaseModel):
    email: str = Field(
        ...,
        description="Email address of the user to invite",
        examples=["colleague@example.com"],
    )
    role: str = Field(
        PROJECT_ROLE_VIEWER,
        description=f"Role to assign ({', '.join(PROJECT_ROLES)})",
        examples=[PROJECT_ROLE_VIEWER],
    )

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in PROJECT_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(PROJECT_ROLES)}")
        return v


class ProjectMemberUpdate(BaseModel):
    role: str | None = Field(
        None,
        description=f"New role to assign ({', '.join(PROJECT_ROLES)})",
        examples=[PROJECT_ROLE_VIEWER],
    )
    notification_preferences: dict[str, list[str]] | None = Field(
        None, description="Notification preferences for the member"
    )

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str | None) -> str | None:
        if v and v not in PROJECT_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(PROJECT_ROLES)}")
        return v


class ProjectNotificationSettings(BaseModel):
    notification_preferences: dict[str, list[str]] = Field(
        ...,
        description="Map of event types to notification channels",
        examples=[
            {
                "analysis_completed": ["email", "slack"],
                "vulnerability_found": ["slack"],
            }
        ],
    )
    enforce_notification_settings: bool | None = Field(
        None, description="Enforce these settings for all members (Owner only)"
    )

    @field_validator("notification_preferences")
    @classmethod
    def _sanitize_prefs(cls, v: Any) -> dict[str, list[str]]:
        return sanitize_notification_preferences(v)


class ProjectApiKeyResponse(BaseModel):
    project_id: str = Field(..., description="The unique ID of the project")
    api_key: str = Field(..., description="The generated API Key (ProjectID.Secret)")
    note: str = "This key will only be shown once. Please save it securely."


class RiskyProject(BaseModel):
    """A project entry in the top risky projects list."""

    id: str = Field(..., description="Project ID")
    name: str = Field(..., description="Project name")
    risk: float = Field(..., description="Calculated risk score")


class RecentScan(Scan):
    """Scan with additional project name for cross-project views."""

    project_name: str = Field(..., description="Name of the project this scan belongs to")


class DashboardStats(BaseModel):
    """Dashboard statistics for project overview."""

    total_projects: int = Field(..., description="Total number of accessible projects")
    total_critical: int = Field(..., description="Total critical findings across projects")
    total_high: int = Field(..., description="Total high findings across projects")
    avg_risk_score: float = Field(..., description="Average risk score across projects")
    top_risky_projects: list[RiskyProject] = Field(..., description="Top 5 projects by risk score")


class ScanFindingItem(BaseModel):
    """A single finding item in the scan findings response."""

    # Core finding fields
    id: str = Field(..., description="Logical finding ID (e.g. CVE-2021-44228)")
    finding_id: str = Field(..., description="Finding identifier")
    type: FindingType = Field(..., description="Type of finding")
    severity: Severity = Field(..., description="Severity level")
    component: str = Field(..., description="Affected component")
    version: str | None = Field(None, description="Affected version")
    description: str = Field(..., description="Finding description")
    scanners: list[str] = Field(default_factory=list, description="Scanners that detected this")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional details")

    # Reference fields
    project_id: str = Field(..., description="Project ID")
    scan_id: str = Field(..., description="Scan ID")

    # Status fields
    waived: bool = Field(default=False, description="Whether this finding is waived")
    waiver_reason: str | None = Field(None, description="Reason for waiver")
    waiver_lapsed: bool = Field(default=False, description="Whether the matched waiver has lapsed")
    lapsed_waiver_id: str | None = Field(None, description="ID of the lapsed waiver, if any")

    # Metadata
    found_in: list[str] = Field(default_factory=list, description="Files where found")
    aliases: list[str] = Field(default_factory=list, description="Alternative IDs")
    related_findings: list[str] = Field(default_factory=list, description="Related finding IDs")
    created_at: datetime | None = Field(None, description="When the finding was created")

    # Enriched fields from dependency lookup
    source_type: str | None = Field(None, description="Source type (e.g. image, filesystem)")
    source_target: str | None = Field(None, description="Source target path")
    layer_digest: str | None = Field(None, description="Docker layer digest")
    found_by: str | None = Field(None, description="Scanner that found this")
    locations: list[str] | None = Field(None, description="File locations")
    purl: str | None = Field(None, description="Package URL")
    direct: bool | None = Field(None, description="Whether this is a direct dependency")
    direct_inferred: bool | None = Field(None, description="Whether the direct flag was inferred")

    # Computed fields
    severity_rank: int = Field(default=0, description="Numeric severity rank for sorting")

    model_config = ConfigDict(use_enum_values=True)


class ScanFindingsResponse(BaseModel):
    """Paginated response for scan findings."""

    items: list[ScanFindingItem] = Field(..., description="List of findings")
    total: int = Field(..., description="Total number of findings")
    page: int = Field(..., description="Current page number")
    size: int = Field(..., description="Number of items per page")
    pages: int = Field(..., description="Total number of pages")
