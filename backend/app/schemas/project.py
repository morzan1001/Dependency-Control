from pydantic import BaseModel, Field
from typing import List, Optional, Dict

class ProjectCreate(BaseModel):
    name: str = Field(..., description="The name of the project", example="My Awesome App")
    team_id: Optional[str] = Field(None, description="ID of the team this project belongs to")
    active_analyzers: List[str] = Field(
        default=["end_of_life"], 
        description="List of analyzers to run on this project",
        example=["end_of_life", "os_malware"]
    )
    retention_days: Optional[int] = Field(90, description="Number of days to keep scan history", ge=1)

class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, description="New name for the project")
    team_id: Optional[str] = Field(None, description="Transfer project to a team")
    active_analyzers: Optional[List[str]] = Field(None, description="Updated list of active analyzers")
    retention_days: Optional[int] = Field(None, description="Number of days to keep scan history", ge=1)
    default_branch: Optional[str] = Field(None, description="Default branch to show in dashboard")
    owner_notification_preferences: Optional[Dict[str, List[str]]] = Field(None, description="Notification preferences for the owner")

class ProjectMemberInvite(BaseModel):
    email: str = Field(..., description="Email address of the user to invite", example="colleague@example.com")
    role: str = Field("viewer", description="Role to assign (viewer, editor, admin)", example="editor")

class ProjectMemberUpdate(BaseModel):
    role: Optional[str] = Field(None, description="New role to assign (viewer, editor, admin)", example="admin")
    notification_preferences: Optional[Dict[str, List[str]]] = Field(None, description="Notification preferences for the member")

class ProjectNotificationSettings(BaseModel):
    notification_preferences: Dict[str, List[str]] = Field(
        ..., 
        description="Map of event types to notification channels",
        example={"analysis_completed": ["email", "slack"], "vulnerability_found": ["slack"]}
    )

class ProjectApiKeyResponse(BaseModel):
    project_id: str = Field(..., description="The unique ID of the project")
    api_key: str = Field(..., description="The generated API Key (ProjectID.Secret)")
    note: str = "This key will only be shown once. Please save it securely."



