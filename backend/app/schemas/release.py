"""Request and response models for marking, unmarking and listing releases."""

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT, validate_release_environment
from app.schemas.datetimes import UtcDatetime


class ReleaseMarkRequest(BaseModel):
    commit_hash: str = Field(..., min_length=1, description="Commit whose newest scan becomes the release")
    version: str | None = Field(None, description="Release name; falls back to the scan's commit_tag")
    environment: str | None = Field(None, description=f"Slug; falls back to {DEFAULT_RELEASE_ENVIRONMENT}")
    released_at: datetime | None = Field(None, description="Release time; falls back to server time")

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str | None) -> str | None:
        return validate_release_environment(v)


class ReleaseItem(BaseModel):
    """One release record plus the state of the analysis behind it, so a deploy whose scan has not
    finished analysing reads differently from an environment nothing is deployed to."""

    scan_id: str = Field(..., description="The released artefact's scan")
    project_id: str
    environment: str
    version: str | None = None
    released_at: UtcDatetime
    commit_hash: str | None = None
    branch: str | None = None
    scan_status: str | None = Field(None, description="Status of the released scan; null once retention removed it")
    analysis_scan_id: str | None = Field(
        None,
        description="Scan whose analysis represents this release, following re-scans; "
        "null while nothing in its chain has finished analysing",
    )


class ReleaseListResponse(BaseModel):
    items: list[ReleaseItem]
    total: int
    page: int
    size: int


class ReleaseUnmarkResponse(BaseModel):
    scan_id: str
    environment: str = Field(..., description="The environment the scan was withdrawn from")
    is_release: bool = Field(
        ..., description="The scan's flag afterwards; still true while another environment holds it"
    )
    remaining_environments: list[str]
    environment_release: ReleaseItem | None = Field(
        None,
        description="What the environment reports as running now that the scan is withdrawn: the "
        "record underneath it, or null once nothing is released there. Every other field describes "
        "the scan, and a withdrawal that uncovers an older record changes the environment too",
    )
