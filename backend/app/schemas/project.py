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

class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, description="New name for the project")
    team_id: Optional[str] = Field(None, description="Transfer project to a team")
    active_analyzers: Optional[List[str]] = Field(None, description="Updated list of active analyzers")

class ProjectMemberInvite(BaseModel):
    email: str = Field(..., description="Email address of the user to invite", example="colleague@example.com")
    role: str = Field("viewer", description="Role to assign (viewer, editor, admin)", example="editor")

class ProjectMemberUpdate(BaseModel):
    role: str = Field(..., description="New role to assign (viewer, editor, admin)", example="admin")

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



