from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
from app.models.finding import Finding
from app.models.stats import Stats

class ProjectMember(BaseModel):
    user_id: str
    role: str = "viewer"  # "admin", "editor", "viewer"
    notification_preferences: Dict[str, List[str]] = Field(default_factory=dict)
    username: Optional[str] = None
    inherited_from: Optional[str] = None # e.g. "Team: DevOps"

class Project(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    name: str
    owner_id: str
    team_id: Optional[str] = None
    owner_notification_preferences: Dict[str, List[str]] = Field(default_factory=dict)
    members: List[ProjectMember] = []
    api_key_hash: Optional[str] = Field(None, exclude=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    active_analyzers: List[str] = ["trivy", "osv", "license_compliance", "end_of_life"]
    stats: Optional[Stats] = None
    last_scan_at: Optional[datetime] = None
    latest_scan_id: Optional[str] = None
    retention_days: int = 90  # Default retention period in days
    default_branch: Optional[str] = None
    gitlab_project_id: Optional[int] = None
    gitlab_project_path: Optional[str] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class Scan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
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
    
    sboms: List[Dict[str, Any]] = [] # Raw SBOMs (Deprecated: use sbom_refs for new scans)
    
    # New: Reference to stored SBOM files (GridFS/S3)
    # This allows us to keep the Scan document small while preserving the raw data.
    sbom_refs: List[Dict[str, Any]] = [] 
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    status: str = "pending"
    findings_summary: Optional[List[Finding]] = None
    findings_count: Optional[int] = None
    stats: Optional[Stats] = None
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
