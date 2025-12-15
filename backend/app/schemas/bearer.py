from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from app.schemas.ingest import PipelineMetadata

class BearerIngest(BaseModel):
    project_name: Optional[str] = None
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    metadata: PipelineMetadata
    findings: Dict[str, Any] # Bearer JSON output usually has a root key like "findings" or "vulnerabilities", or it IS the dictionary.
    # Based on "feat(report): add new jsonv2 format", it might be complex.
    # Let's accept the whole JSON report as a dict and parse it in the aggregator.
