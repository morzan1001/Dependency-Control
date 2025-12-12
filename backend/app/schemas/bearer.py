from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class BearerIngest(BaseModel):
    project_name: str
    branch: str
    commit_hash: str
    findings: Dict[str, Any] # Bearer JSON output usually has a root key like "findings" or "vulnerabilities", or it IS the dictionary.
    # Based on "feat(report): add new jsonv2 format", it might be complex.
    # Let's accept the whole JSON report as a dict and parse it in the aggregator.
