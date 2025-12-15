from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from app.schemas.ingest import PipelineMetadata

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
    project_name: Optional[str] = None
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    metadata: PipelineMetadata
    findings: List[TruffleHogFinding]
