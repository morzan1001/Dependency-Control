"""Request/response schemas for the chat API."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ConversationCreate(BaseModel):
    title: Optional[str] = None


class ConversationResponse(BaseModel):
    id: str
    user_id: str
    title: str
    created_at: datetime
    updated_at: datetime
    message_count: int

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class ConversationListResponse(BaseModel):
    conversations: List[ConversationResponse]
    total: int


class MessageCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000)
    images: List[str] = Field(default_factory=list)


class ToolCallResponse(BaseModel):
    tool_name: str
    arguments: Dict[str, Any]
    result: Dict[str, Any]
    duration_ms: int


class MessageResponse(BaseModel):
    id: str
    conversation_id: str
    role: str
    content: str
    images: List[str]
    tool_calls: List[ToolCallResponse]
    token_count: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class ConversationDetailResponse(BaseModel):
    conversation: ConversationResponse
    messages: List[MessageResponse]
