from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid

class ProjectMember(BaseModel):
    user_id: str
    role: str = "viewer"  # "admin", "editor", "viewer"
    notification_preferences: Dict[str, List[str]] = Field(default_factory=dict)

class Project(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    name: str
    owner_id: str
    team_id: Optional[str] = None
    owner_notification_preferences: Dict[str, List[str]] = Field(default_factory=dict)
    members: List[ProjectMember] = []
    api_key_hash: Optional[str] = Field(None, exclude=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    active_analyzers: List[str] = []
    stats: Optional[Dict[str, int]] = None
    last_scan_at: Optional[datetime] = None
    retention_days: int = 90  # Default retention period in days

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class Scan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    project_id: str
    branch: str
    commit_hash: Optional[str] = None
    sbom: Optional[Dict[str, Any]] = None # Made optional for secret-only scans
    created_at: datetime = Field(default_factory=datetime.utcnow)
    status: str = "pending"
    findings_summary: Optional[List[Dict[str, Any]]] = None
    findings_count: Optional[int] = None
    stats: Optional[Dict[str, int]] = None
    completed_at: Optional[datetime] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class AnalysisResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    scan_id: str
    analyzer_name: str
    result: Dict[str, Any]
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
