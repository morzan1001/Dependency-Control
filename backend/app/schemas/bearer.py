from typing import Any, Dict, List, Optional

from pydantic import Field

from app.schemas.ingest import BaseIngest


class BearerIngest(BaseIngest):
    """Schema for Bearer SAST/Data Security scan results."""

    findings: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Bearer JSON output. Can be the full report or just the findings section.",
    )
