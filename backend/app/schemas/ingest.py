from pydantic import BaseModel, Field
from typing import Dict, Any, Optional

class SBOMIngest(BaseModel):
    project_name: str = Field(..., description="Name of the project (informational)", example="My App")
    branch: str = Field(..., description="Git branch name", example="main")
    commit_hash: Optional[str] = Field(None, description="Git commit hash", example="a1b2c3d4")
    sbom: Dict[str, Any] = Field(..., description="The SBOM JSON content", example={"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []})
