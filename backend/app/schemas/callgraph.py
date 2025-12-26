"""
Callgraph Ingest Schema

Schemas for parsing and validating callgraph data from various tools.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class MadgeImport(BaseModel):
    """Import entry from madge (JavaScript/TypeScript)."""

    # madge format: { "src/file.js": ["./utils", "lodash", "@org/pkg"] }
    pass


class MadgeCallgraph(BaseModel):
    """
    Madge JSON output format.

    Example:
    {
        "src/index.js": ["./utils", "lodash"],
        "src/utils.js": ["axios", "./helpers"]
    }
    """

    dependencies: Dict[str, List[str]] = Field(default_factory=dict)


class PyanNode(BaseModel):
    """Node from pyan (Python)."""

    name: str
    type: str  # module, class, function
    file: Optional[str] = None
    line: Optional[int] = None


class PyanEdge(BaseModel):
    """Edge from pyan (Python)."""

    source: str
    target: str
    type: str = "calls"  # calls, uses, defines


class PyanCallgraph(BaseModel):
    """
    Pyan JSON output format.

    Generated with: pyan3 --json src/**/*.py
    """

    nodes: List[PyanNode] = []
    edges: List[PyanEdge] = []


class GoCallvisNode(BaseModel):
    """Node from go-callvis."""

    id: str
    label: str
    package: str
    type: str  # func, method


class GoCallvisEdge(BaseModel):
    """Edge from go-callvis."""

    from_id: str = Field(alias="from")
    to_id: str = Field(alias="to")
    type: str = "call"


class GoCallvisCallgraph(BaseModel):
    """
    go-callvis JSON output format.
    """

    nodes: List[GoCallvisNode] = []
    edges: List[GoCallvisEdge] = []


class GenericImport(BaseModel):
    """Generic import entry for custom formats."""

    file: str
    module: str
    line: Optional[int] = None
    symbols: List[str] = []


class GenericCall(BaseModel):
    """Generic call entry for custom formats."""

    caller_file: str
    caller_function: Optional[str] = None
    callee_module: str
    callee_function: Optional[str] = None
    line: Optional[int] = None


class GenericCallgraph(BaseModel):
    """
    Generic callgraph format that can be used for any language.

    This is the recommended format for custom integrations.
    """

    language: str
    tool: str = "custom"
    tool_version: Optional[str] = None
    imports: List[GenericImport] = []
    calls: List[GenericCall] = []
    source_files: List[str] = []


class CallgraphUploadRequest(BaseModel):
    """Request body for callgraph upload endpoint."""

    # Format detection
    format: str = "auto"  # auto, madge, pyan, go-callvis, generic

    # Language (required if format is generic or auto-detection fails)
    language: Optional[str] = None  # javascript, typescript, python, go, java

    # Pipeline context (for exact matching with SBOM scans)
    # pipeline_id is the PRIMARY key - ensures callgraph matches exact CI/CD run
    pipeline_id: Optional[int] = None  # GitLab CI pipeline ID (preferred)
    branch: Optional[str] = None  # Git branch (fallback if no pipeline_id)
    commit_hash: Optional[str] = None  # Specific commit (optional, for traceability)

    # Tool info
    tool: Optional[str] = None
    tool_version: Optional[str] = None

    # The actual callgraph data (format depends on 'format' field)
    data: Dict[str, Any]

    # Optional: link to a specific scan
    scan_id: Optional[str] = None

    # Optional: metadata
    source_files_count: Optional[int] = None
    analysis_duration_ms: Optional[int] = None


class CallgraphUploadResponse(BaseModel):
    """Response from callgraph upload endpoint."""

    success: bool
    message: str
    project_id: str

    # Stats
    imports_parsed: int = 0
    calls_parsed: int = 0
    modules_detected: int = 0

    # Warnings
    warnings: List[str] = []
