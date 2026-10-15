from datetime import datetime

from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT
from app.models.types import MongoDocument


def release_identity(environment: str | None, version: str | None, commit_tag: str | None) -> tuple[str, str | None]:
    return environment or DEFAULT_RELEASE_ENVIRONMENT, version or commit_tag


class Release(MongoDocument):
    project_id: str
    environment: str
    version: str | None = None
    scan_id: str
    released_at: datetime
