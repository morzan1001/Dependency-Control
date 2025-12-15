from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List

class PipelineMetadata(BaseModel):
    ci_pipeline_id: int = Field(..., alias="CI_PIPELINE_ID")
    ci_pipeline_iid: Optional[int] = Field(None, alias="CI_PIPELINE_IID")
    ci_project_url: Optional[str] = Field(None, alias="CI_PROJECT_URL")
    ci_commit_branch: Optional[str] = Field(None, alias="CI_COMMIT_BRANCH")
    ci_default_branch: Optional[str] = Field(None, alias="CI_DEFAULT_BRANCH")
    ci_project_path: Optional[str] = Field(None, alias="CI_PROJECT_PATH")
    ci_project_id: Optional[int] = Field(None, alias="CI_PROJECT_ID")
    ci_project_title: Optional[str] = Field(None, alias="CI_PROJECT_TITLE")
    ci_commit_message: Optional[str] = Field(None, alias="CI_COMMIT_MESSAGE")
    ci_commit_tag: Optional[str] = Field(None, alias="CI_COMMIT_TAG")
    ci_job_started_at: Optional[str] = Field(None, alias="CI_JOB_STARTED_AT")
    ci_job_id: Optional[int] = Field(None, alias="CI_JOB_ID")
    ci_project_name: Optional[str] = Field(None, alias="CI_PROJECT_NAME")

    class Config:
        populate_by_name = True

class SBOMIngest(BaseModel):
    # Deprecated fields (kept for backward compatibility if needed, but we prefer metadata)
    project_name: Optional[str] = Field(None, description="Name of the project (informational)")
    branch: Optional[str] = Field(None, description="Git branch name")
    commit_hash: Optional[str] = Field(None, description="Git commit hash")
    
    metadata: PipelineMetadata
    sboms: List[Dict[str, Any]] = Field(default_factory=list, description="List of SBOM JSON contents")
    
    # Backward compatibility for single SBOM
    sbom: Optional[Dict[str, Any]] = Field(None, description="Single SBOM JSON content (deprecated, use sboms)")
