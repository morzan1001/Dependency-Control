from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional
from datetime import datetime
import uuid

class Webhook(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    project_id: Optional[str] = None
    url: str
    events: List[str] # ["scan_completed", "vulnerability_found"]
    secret: Optional[str] = None
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_triggered_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
