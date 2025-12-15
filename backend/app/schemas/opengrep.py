from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from app.schemas.ingest import PipelineMetadata

class OpenGrepLocation(BaseModel):
    path: str
    start: Dict[str, int]
    end: Dict[str, int]
    lines: Optional[str] = None

class OpenGrepExtra(BaseModel):
    message: Optional[str] = None
    severity: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class OpenGrepFinding(BaseModel):
    check_id: str
    path: str
    start: Dict[str, int]
    end: Dict[str, int]
    extra: OpenGrepExtra

class OpenGrepIngest(BaseModel):
    project_name: Optional[str] = None
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    metadata: PipelineMetadata
    findings: List[OpenGrepFinding]
