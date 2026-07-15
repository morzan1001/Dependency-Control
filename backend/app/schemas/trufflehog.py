from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator

from app.schemas.ingest import BaseIngest


class TruffleHogFinding(BaseModel):
    SourceMetadata: Optional[Dict[str, Any]] = None
    # Synthesized by the secret-scan CI template (not a native TruffleHog field): whether
    # the finding's file path still exists at the scanned commit's HEAD tree.
    DcInCurrentTree: Optional[bool] = None
    SourceID: Optional[Union[str, int]] = None
    SourceType: Optional[Union[str, int]] = None
    SourceName: Optional[str] = None
    DetectorType: Union[str, int]

    @field_validator("SourceID", "SourceType", "DetectorType", mode="before")
    @classmethod
    def _coerce_to_str(cls, v: Any) -> Any:
        """TruffleHog >= 3.x emits these as integers (enum ordinals).
        Coerce to str so downstream code stays uniform."""
        if isinstance(v, int):
            return str(v)
        return v

    DecoderName: Optional[str] = None
    Verified: Optional[bool] = None
    Raw: Optional[str] = None
    Redacted: Optional[str] = None
    ExtraData: Optional[Dict[str, Any]] = None
    StructuredData: Optional[Dict[str, Any]] = None


class TruffleHogIngest(BaseIngest):
    """Schema for TruffleHog secret scan results."""

    findings: List[TruffleHogFinding] = Field(
        default_factory=list,
        description="List of secrets found by TruffleHog.",
    )
