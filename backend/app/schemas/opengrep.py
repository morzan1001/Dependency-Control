from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

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
    project_name: str
    branch: str
    commit_hash: Optional[str] = None
    findings: List[OpenGrepFinding]
