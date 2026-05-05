"""Chat conversation and message models."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal

from pydantic import ConfigDict, Field

from app.models.base import CreatedAtModel
from app.models.types import PyObjectId


class Conversation(CreatedAtModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    user_id: str
    title: str = "New Conversation"
    message_count: int = 0
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(populate_by_name=True)


class Message(CreatedAtModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    conversation_id: str
    role: Literal["user", "assistant", "tool"]
    content: str = ""
    images: List[str] = Field(default_factory=list)
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    token_count: int = 0

    model_config = ConfigDict(populate_by_name=True)
