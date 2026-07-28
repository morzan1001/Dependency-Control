from pydantic import BaseModel, Field

from app.schemas.ingest import BaseIngest


class KicsFile(BaseModel):
    file_name: str
    similarity_id: str | None = None
    line: int
    resource_type: str | None = None
    resource_name: str | None = None
    issue_type: str | None = None
    search_key: str | None = None
    search_line: int | None = None
    search_value: str | None = None
    expected_value: str | None = None
    actual_value: str | None = None


class KicsQuery(BaseModel):
    query_name: str
    query_id: str
    query_url: str | None = None
    severity: str
    platform: str | None = None
    category: str | None = None
    description: str | None = None
    description_id: str | None = None
    files: list[KicsFile]


class KicsIngest(BaseIngest):
    kics_version: str | None = None
    queries: list[KicsQuery] = Field(default_factory=list)
