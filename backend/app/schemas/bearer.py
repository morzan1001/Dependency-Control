from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.schemas.ingest import BaseIngest


class BearerSourceLocation(BaseModel):
    """Source location information for a Bearer finding."""

    start: int
    end: int
    column: Optional[Dict[str, int]] = None


class BearerFinding(BaseModel):
    """Individual Bearer finding structure."""

    # Core identification
    id: str = Field(description="Rule ID (e.g., 'go_lang_logger_leak')")
    cwe_ids: List[str] = Field(default_factory=list, description="CWE identifiers")
    title: str = Field(description="Human-readable title of the finding")
    description: Optional[str] = Field(None, description="Detailed description with remediation guidance")
    documentation_url: Optional[str] = Field(None, description="Link to Bearer documentation for this rule")

    # Location information
    line_number: Optional[int] = Field(None, description="Line number of the finding")
    full_filename: Optional[str] = Field(None, description="Full path to the file")
    filename: Optional[str] = Field(None, description="Filename (may be relative)")
    source: Optional[BearerSourceLocation] = Field(None, description="Source location details")
    sink: Optional[Dict[str, Any]] = Field(None, description="Sink location and content")
    parent_line_number: Optional[int] = Field(None, description="Parent context line number")

    # Categorization
    category_groups: List[str] = Field(
        default_factory=list,
        description="Category groups (e.g., 'PII', 'Personal Data')",
    )

    # Code context
    code_extract: Optional[str] = Field(None, description="Code snippet showing the finding")

    # Fingerprinting for deduplication
    fingerprint: Optional[str] = Field(None, description="Unique fingerprint for dedup")
    old_fingerprint: Optional[str] = Field(None, description="Previous fingerprint if rule changed")


class BearerIngest(BaseIngest):
    """Schema for Bearer SAST/Data Security scan results."""

    findings: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Bearer JSON output. Findings are grouped by severity (critical, high, medium, low, warning).",
    )
