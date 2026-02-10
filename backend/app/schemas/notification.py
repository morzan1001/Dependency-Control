from typing import List, Optional

from pydantic import BaseModel, Field


class AdvisoryPackage(BaseModel):
    name: str = Field(..., description="Affected package name")
    version: Optional[str] = Field(None, description="Affected version (inclusive max)")
    type: Optional[str] = Field(None, description="Package type (npm, pypi...)")


class BroadcastRequest(BaseModel):
    type: str = Field(..., description="Type of message: 'general' or 'advisory'")
    target_type: str = Field(..., description="Target audience: 'global', 'teams', 'advisory'")
    target_teams: Optional[List[str]] = Field(None, description="List of Team IDs if target_type is 'teams'")
    channels: Optional[List[str]] = Field(None, description="Channels to send to (email, slack, mattermost)")

    # For Advisory
    packages: Optional[List[AdvisoryPackage]] = Field(None, description="List of affected packages for advisory")

    subject: str
    message: str
    dry_run: bool = Field(False, description="If true, only calculates impact without sending")


class BroadcastResult(BaseModel):
    recipient_count: int
    project_count: int = 0
    unique_user_count: int = 0


class BroadcastHistoryItem(BaseModel):
    id: str
    type: str
    target_type: str
    subject: str
    created_at: str
    created_by: Optional[str] = None
    recipient_count: int
    project_count: int
    unique_user_count: int = 0
    teams: Optional[List[str]] = None
