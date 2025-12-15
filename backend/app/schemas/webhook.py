from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class WebhookCreate(BaseModel):
    url: str
    events: List[str]
    secret: Optional[str] = None

class WebhookUpdate(BaseModel):
    url: Optional[str] = None
    events: Optional[List[str]] = None
    is_active: Optional[bool] = None
    secret: Optional[str] = None

class WebhookResponse(WebhookCreate):
    id: str
    project_id: Optional[str] = None
    is_active: bool
    created_at: datetime
    last_triggered_at: Optional[datetime] = None
