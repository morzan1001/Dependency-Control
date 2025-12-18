from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List

class BaseIngest(BaseModel):
    pipeline_id: int = Field(..., description="Unique ID of the pipeline run")
    commit_hash: str = Field(..., description="Git commit hash")
    branch: str = Field(..., description="Git branch name")
    
    pipeline_iid: Optional[int] = Field(None, description="Project-level pipeline ID")
    project_url: Optional[str] = Field(None, description="URL to the project")
    pipeline_url: Optional[str] = Field(None, description="URL to the pipeline")
    
    job_id: Optional[int] = Field(None, description="CI Job ID")
    job_started_at: Optional[str] = Field(None, description="Job start time")
    
    project_name: Optional[str] = Field(None, description="Name of the project")
    commit_message: Optional[str] = Field(None, description="Commit message")
    commit_tag: Optional[str] = Field(None, description="Git tag")
    pipeline_user: Optional[str] = Field(None, description="User who triggered the pipeline")

class SBOMIngest(BaseIngest):
    sboms: List[Dict[str, Any]] = Field(default_factory=list, description="List of SBOM JSON contents")

