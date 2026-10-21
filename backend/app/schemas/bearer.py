from typing import Any

from pydantic import BaseModel, Field, model_validator

from app.schemas.ingest import PipelineIngest


class BearerSourceLocation(BaseModel):
    # Bearer writes an unset location as {}.
    start: int | None = None
    end: int | None = None
    column: dict[str, int] | None = None


class BearerFinding(BaseModel):
    id: str | None = Field(None, description="Rule ID (e.g., 'go_lang_logger_leak')")
    severity: str | None = Field(None, description="Severity; a grouped report gives each entry its group's key")
    cwe_ids: list[str] | None = Field(None, description="CWE identifiers")
    title: str | None = Field(None, description="Human-readable title of the finding")
    description: str | None = Field(None, description="Detailed description with remediation guidance")
    documentation_url: str | None = Field(None, description="Link to Bearer documentation for this rule")

    line_number: int | None = Field(None, description="Line number of the finding")
    full_filename: str | None = Field(None, description="Full path to the file")
    filename: str | None = Field(None, description="Filename (may be relative)")
    source: BearerSourceLocation | None = Field(None, description="Source location details")
    sink: dict[str, Any] | None = Field(None, description="Sink location and content")
    parent_line_number: int | None = Field(None, description="Parent context line number")
    snippet: str | None = Field(None, description="Content of the parent context")

    category_groups: list[str] = Field(
        default_factory=list,
        description="Category groups (e.g., 'PII', 'Personal Data')",
    )

    code_extract: str | None = Field(None, description="Code snippet showing the finding")

    @model_validator(mode="after")
    def _sets_a_bearer_key(self) -> "BearerFinding":
        # Every key is optional and a grouped report injects severity, so only another key marks Bearer output.
        if not self.model_fields_set - {"severity"}:
            raise ValueError("no Bearer finding key is set")
        return self


def bearer_entries(container: Any) -> list[Any] | None:
    """Bearer posts a flat list or severity groups; a group's severity is each entry's default."""
    if isinstance(container, list):
        return container
    if isinstance(container, dict):
        return [
            {"severity": key.lower(), **item} if isinstance(item, dict) else item
            for key, items in container.items()
            if isinstance(items, list)
            for item in items
        ]
    return None


class BearerIngest(PipelineIngest):
    findings: dict[str, Any] | None = Field(
        default_factory=dict,
        description="Bearer JSON output. Findings are grouped by severity (critical, high, medium, low, warning).",
    )
