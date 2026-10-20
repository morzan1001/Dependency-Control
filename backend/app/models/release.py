from datetime import datetime

from app.models.types import MongoDocument


class Release(MongoDocument):
    project_id: str
    environment: str
    version: str | None = None
    scan_id: str
    released_at: datetime
