from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from app.schemas.ingest import BaseIngest


class TruffleHogFinding(BaseModel):
    SourceMetadata: Optional[Dict[str, Any]] = None
    SourceID: Optional[str] = None
    SourceType: Optional[str] = None
    SourceName: Optional[str] = None
    DetectorType: str
    DecoderName: Optional[str] = None
    Verified: Optional[bool] = None
    Raw: Optional[str] = None
    Redacted: Optional[str] = None
    ExtraData: Optional[Dict[str, Any]] = None
    StructuredData: Optional[Dict[str, Any]] = None


class TruffleHogIngest(BaseIngest):
    findings: List[TruffleHogFinding]
