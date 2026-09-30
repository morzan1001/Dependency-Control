"""Call graph data uploaded from CI/CD pipelines for reachability analysis."""

from pydantic import BaseModel, Field

from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class ModuleUsage(BaseModel):
    """Aggregated usage information for a module/package."""

    module: str
    import_count: int = 0  # number of files importing this module
    call_count: int = 0  # number of calls into this module
    import_locations: list[str] = []
    used_symbols: list[str] = []


class Callgraph(MongoDocument, CreatedAtModel):
    """What a project's callgraph upload resolves to: per-module usage, the coverage universe and totals."""

    project_id: str

    # Matched on scan_id (uuid5 of project+pipeline+commit), else on pipeline_id (GitLab pipeline or GitHub run).
    pipeline_id: int | None = None
    branch: str | None = None
    commit_hash: str | None = None
    scan_id: str | None = None

    # Language and tool info
    language: str  # javascript, typescript, python, go, java, etc.
    tool: str  # madge, jdeps, etc.
    tool_version: str | None = None

    # Aggregated data for quick lookups
    module_usage: dict[str, ModuleUsage] = Field(default_factory=dict)

    # Coverage universe: packages the producer actually resolved and inspected.
    # Only these may ever be falsified as unreachable.
    analyzed_modules: list[str] = Field(default_factory=list)

    # Metadata
    source_files_analyzed: int = 0
    total_imports: int = 0
    total_calls: int = 0
    analysis_duration_ms: int | None = None
