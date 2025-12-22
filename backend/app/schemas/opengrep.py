from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from app.schemas.ingest import BaseIngest


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


class OpenGrepIngest(BaseIngest):
    findings: List[OpenGrepFinding]
