from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import PROJECT_ROLES, PROJECT_ROLE_VIEWER
from app.models.finding import FindingType, Severity
from app.models.project import Project, Scan


class ProjectWithTeam(Project):
    """Project with team name enrichment for list views."""

    team_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ProjectList(BaseModel):
    items: List[Project]
    total: int
    page: int
    size: int
    pages: int


class ProjectListEnriched(BaseModel):
    """Project list with team names enriched."""

    items: List[ProjectWithTeam]
    total: int
    page: int
    size: int
    pages: int


class ProjectCreate(BaseModel):
    name: str = Field(..., description="The name of the project", examples=["My Awesome App"])
    team_id: Optional[str] = Field(None, description="ID of the team this project belongs to")
    active_analyzers: List[str] = Field(
        default=["trivy", "osv", "license_compliance", "end_of_life"],
        description="List of analyzers to run on this project",
        examples=[["end_of_life", "os_malware", "trivy"]],
    )
    retention_days: Optional[int] = Field(90, description="Number of days to keep scan history", ge=1)


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, description="New name for the project")
    team_id: Optional[str] = Field(None, description="Transfer project to a team")
    active_analyzers: Optional[List[str]] = Field(None, description="Updated list of active analyzers")
    retention_days: Optional[int] = Field(None, description="Number of days to keep scan history", ge=1)
    default_branch: Optional[str] = Field(None, description="Default branch to show in dashboard")
    enforce_notification_settings: Optional[bool] = Field(
        None, description="Enforce owner notification settings for all members"
    )
    owner_notification_preferences: Optional[Dict[str, List[str]]] = Field(
        None, description="Notification preferences for the owner"
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
    role: Optional[str] = Field(
        None,
        description=f"New role to assign ({', '.join(PROJECT_ROLES)})",
        examples=[PROJECT_ROLE_VIEWER],
    )
    notification_preferences: Optional[Dict[str, List[str]]] = Field(
        None, description="Notification preferences for the member"
    )

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: Optional[str]) -> Optional[str]:
        if v and v not in PROJECT_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(PROJECT_ROLES)}")
        return v


class ProjectNotificationSettings(BaseModel):
    notification_preferences: Dict[str, List[str]] = Field(
        ...,
        description="Map of event types to notification channels",
        examples=[
            {
                "analysis_completed": ["email", "slack"],
                "vulnerability_found": ["slack"],
            }
        ],
    )
    enforce_notification_settings: Optional[bool] = Field(
        None, description="Enforce these settings for all members (Owner only)"
    )


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
    top_risky_projects: List[RiskyProject] = Field(..., description="Top 5 projects by risk score")


class ScanFindingItem(BaseModel):
    """A single finding item in the scan findings response."""

    # Core finding fields
    id: str = Field(..., description="Logical finding ID (e.g. CVE-2021-44228)")
    finding_id: str = Field(..., description="Finding identifier")
    type: FindingType = Field(..., description="Type of finding")
    severity: Severity = Field(..., description="Severity level")
    component: str = Field(..., description="Affected component")
    version: Optional[str] = Field(None, description="Affected version")
    description: str = Field(..., description="Finding description")
    scanners: List[str] = Field(default_factory=list, description="Scanners that detected this")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")

    # Reference fields
    project_id: str = Field(..., description="Project ID")
    scan_id: str = Field(..., description="Scan ID")

    # Status fields
    waived: bool = Field(default=False, description="Whether this finding is waived")
    waiver_reason: Optional[str] = Field(None, description="Reason for waiver")

    # Metadata
    found_in: List[str] = Field(default_factory=list, description="Files where found")
    aliases: List[str] = Field(default_factory=list, description="Alternative IDs")
    related_findings: List[str] = Field(default_factory=list, description="Related finding IDs")
    created_at: Optional[datetime] = Field(None, description="When the finding was created")

    # Enriched fields from dependency lookup
    source_type: Optional[str] = Field(None, description="Source type (e.g. image, filesystem)")
    source_target: Optional[str] = Field(None, description="Source target path")
    layer_digest: Optional[str] = Field(None, description="Docker layer digest")
    found_by: Optional[str] = Field(None, description="Scanner that found this")
    locations: Optional[List[str]] = Field(None, description="File locations")
    purl: Optional[str] = Field(None, description="Package URL")
    direct: Optional[bool] = Field(None, description="Whether this is a direct dependency")

    # Computed fields
    severity_rank: int = Field(default=0, description="Numeric severity rank for sorting")

    model_config = ConfigDict(use_enum_values=True)


class ScanFindingsResponse(BaseModel):
    """Paginated response for scan findings."""

    items: List[ScanFindingItem] = Field(..., description="List of findings")
    total: int = Field(..., description="Total number of findings")
    page: int = Field(..., description="Current page number")
    size: int = Field(..., description="Number of items per page")
    pages: int = Field(..., description="Total number of pages")
