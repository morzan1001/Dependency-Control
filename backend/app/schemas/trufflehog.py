from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.ingest import BaseIngest


class TruffleHogFinding(BaseModel):
    SourceMetadata: dict[str, Any] | None = None
    # Synthesized by the secret-scan CI template (not a native TruffleHog field): whether
    # the finding's file path still exists at the scanned commit's HEAD tree.
    DcInCurrentTree: bool | None = None
    SourceID: str | int | None = None
    SourceType: str | int | None = None
    SourceName: str | None = None
    DetectorType: str | int

    @field_validator("SourceID", "SourceType", "DetectorType", mode="before")
    @classmethod
    def _coerce_to_str(cls, v: Any) -> Any:
        """TruffleHog >= 3.x emits these as integers (enum ordinals).
        Coerce to str so downstream code stays uniform."""
        if isinstance(v, int):
            return str(v)
        return v

    DecoderName: str | None = None
    Verified: bool | None = None
    Raw: str | None = None
    Redacted: str | None = None
    ExtraData: dict[str, Any] | None = None
    StructuredData: dict[str, Any] | None = None


class TruffleHogIngest(BaseIngest):
    """Schema for TruffleHog secret scan results."""

    findings: list[TruffleHogFinding] = Field(
        default_factory=list,
        description="List of secrets found by TruffleHog.",
    )
