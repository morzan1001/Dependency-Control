from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

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
    """Schema for OpenGrep SAST scan results."""

    findings: List[OpenGrepFinding] = Field(
        default_factory=list,
        description="List of SAST findings from OpenGrep.",
    )
