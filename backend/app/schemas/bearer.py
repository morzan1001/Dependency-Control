from typing import Any

from pydantic import BaseModel, Field

from app.schemas.ingest import BaseIngest


class BearerSourceLocation(BaseModel):
    start: int
    end: int
    column: dict[str, int] | None = None


class BearerFinding(BaseModel):
    id: str = Field(description="Rule ID (e.g., 'go_lang_logger_leak')")
    cwe_ids: list[str] = Field(default_factory=list, description="CWE identifiers")
    title: str = Field(description="Human-readable title of the finding")
    description: str | None = Field(None, description="Detailed description with remediation guidance")
    documentation_url: str | None = Field(None, description="Link to Bearer documentation for this rule")

    line_number: int | None = Field(None, description="Line number of the finding")
    full_filename: str | None = Field(None, description="Full path to the file")
    filename: str | None = Field(None, description="Filename (may be relative)")
    source: BearerSourceLocation | None = Field(None, description="Source location details")
    sink: dict[str, Any] | None = Field(None, description="Sink location and content")
    parent_line_number: int | None = Field(None, description="Parent context line number")

    category_groups: list[str] = Field(
        default_factory=list,
        description="Category groups (e.g., 'PII', 'Personal Data')",
    )

    code_extract: str | None = Field(None, description="Code snippet showing the finding")


class BearerIngest(BaseIngest):
    findings: dict[str, Any] | None = Field(
        default_factory=dict,
        description="Bearer JSON output. Findings are grouped by severity (critical, high, medium, low, warning).",
    )
