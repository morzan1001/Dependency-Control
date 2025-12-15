from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from app.schemas.ingest import PipelineMetadata

class KicsFile(BaseModel):
    file_name: str
    similarity_id: Optional[str] = None
    line: int
    resource_type: Optional[str] = None
    resource_name: Optional[str] = None
    issue_type: Optional[str] = None
    search_key: Optional[str] = None
    search_line: Optional[int] = None
    search_value: Optional[str] = None
    expected_value: Optional[str] = None
    actual_value: Optional[str] = None

class KicsQuery(BaseModel):
    query_name: str
    query_id: str
    query_url: Optional[str] = None
    severity: str
    platform: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    description_id: Optional[str] = None
    files: List[KicsFile]

class KicsIngest(BaseModel):
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    metadata: PipelineMetadata
    kics_version: Optional[str] = None
    queries: List[KicsQuery] = []
