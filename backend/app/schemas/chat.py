from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class ConversationCreate(BaseModel):
    title: str | None = None


class ConversationResponse(BaseModel):
    id: str = Field(validation_alias="_id")
    user_id: str
    title: str
    created_at: datetime
    updated_at: datetime
    message_count: int


class ConversationListResponse(BaseModel):
    conversations: list[ConversationResponse]
    total: int


class MessageCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000)


class ToolCallResponse(BaseModel):
    tool_name: str
    arguments: dict[str, Any]
    result: dict[str, Any]
    duration_ms: int


class MessageResponse(BaseModel):
    id: str = Field(validation_alias="_id")
    conversation_id: str
    role: Literal["user", "assistant", "tool"]
    content: str
    tool_calls: list[ToolCallResponse]
    created_at: datetime


class ConversationDetailResponse(BaseModel):
    conversation: ConversationResponse
    messages: list[MessageResponse]
