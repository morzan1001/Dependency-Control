from pydantic import BaseModel, Field

from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class ModuleUsage(BaseModel):
    module: str
    import_count: int = 0
    call_count: int = 0
    import_locations: list[str] = []
    used_symbols: list[str] = []


class Callgraph(MongoDocument, CreatedAtModel):
    project_id: str

    # Matched on scan_id (uuid5 of project+pipeline+commit), else on pipeline_id (GitLab pipeline or GitHub run).
    pipeline_id: int | None = None
    branch: str | None = None
    commit_hash: str | None = None
    scan_id: str | None = None

    language: str
    tool: str
    tool_version: str | None = None

    module_usage: dict[str, ModuleUsage] = Field(default_factory=dict)

    # Only the packages the producer resolved and inspected may ever be judged unreachable.
    analyzed_modules: list[str] = Field(default_factory=list)

    source_files_analyzed: int = 0
    total_imports: int = 0
    total_calls: int = 0
    analysis_duration_ms: int | None = None
