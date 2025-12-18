from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Dict, Any
from app.models.project import Project

class ProjectList(BaseModel):
    items: List[Project]
    total: int
    page: int
    size: int
    pages: int

class ProjectCreate(BaseModel):
    name: str = Field(..., description="The name of the project", example="My Awesome App")
    team_id: Optional[str] = Field(None, description="ID of the team this project belongs to")
    active_analyzers: List[str] = Field(
        default=["trivy", "osv", "license_compliance", "end_of_life"], 
        description="List of analyzers to run on this project",
        example=["end_of_life", "os_malware", "trivy"]
    )
    retention_days: Optional[int] = Field(90, description="Number of days to keep scan history", ge=1)

class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, description="New name for the project")
    team_id: Optional[str] = Field(None, description="Transfer project to a team")
    active_analyzers: Optional[List[str]] = Field(None, description="Updated list of active analyzers")
    retention_days: Optional[int] = Field(None, description="Number of days to keep scan history", ge=1)
    default_branch: Optional[str] = Field(None, description="Default branch to show in dashboard")
    enforce_notification_settings: Optional[bool] = Field(None, description="Enforce owner notification settings for all members")
    owner_notification_preferences: Optional[Dict[str, List[str]]] = Field(None, description="Notification preferences for the owner")

class ProjectMemberInvite(BaseModel):
    email: str = Field(..., description="Email address of the user to invite", example="colleague@example.com")
    role: str = Field("viewer", description="Role to assign (viewer, editor, admin)", example="editor")

    @field_validator('role')
    def validate_role(cls, v):
        if v not in ["viewer", "editor", "admin"]:
            raise ValueError('Role must be one of: viewer, editor, admin')
        return v

class ProjectMemberUpdate(BaseModel):
    role: Optional[str] = Field(None, description="New role to assign (viewer, editor, admin)", example="admin")
    notification_preferences: Optional[Dict[str, List[str]]] = Field(None, description="Notification preferences for the member")

    @field_validator('role')
    def validate_role(cls, v):
        if v and v not in ["viewer", "editor", "admin"]:
            raise ValueError('Role must be one of: viewer, editor, admin')
        return v

class ProjectNotificationSettings(BaseModel):
    notification_preferences: Dict[str, List[str]] = Field(
        ..., 
        description="Map of event types to notification channels",
        example={"analysis_completed": ["email", "slack"], "vulnerability_found": ["slack"]}
    )
    enforce_notification_settings: Optional[bool] = Field(None, description="Enforce these settings for all members (Owner only)")

class ProjectApiKeyResponse(BaseModel):
    project_id: str = Field(..., description="The unique ID of the project")
    api_key: str = Field(..., description="The generated API Key (ProjectID.Secret)")
    note: str = "This key will only be shown once. Please save it securely."



