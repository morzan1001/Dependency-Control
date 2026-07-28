from typing import Any

from pydantic import BaseModel, Field

from app.schemas.ingest import BaseIngest


class OpenGrepLocation(BaseModel):
    path: str
    start: dict[str, int]
    end: dict[str, int]
    lines: str | None = None


class OpenGrepExtra(BaseModel):
    message: str | None = None
    severity: str | None = None
    metadata: dict[str, Any] | None = None
    fingerprint: str | None = None
    lines: str | None = None


class OpenGrepFinding(BaseModel):
    check_id: str
    path: str
    start: dict[str, int]
    end: dict[str, int]
    extra: OpenGrepExtra


class OpenGrepIngest(BaseIngest):
    """Schema for OpenGrep SAST scan results."""

    findings: list[OpenGrepFinding] = Field(
        default_factory=list,
        description="List of SAST findings from OpenGrep.",
    )
