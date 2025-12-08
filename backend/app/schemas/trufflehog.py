from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

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

class TruffleHogIngest(BaseModel):
    project_name: str
    branch: str
    commit_hash: Optional[str] = None
    findings: List[TruffleHogFinding]
