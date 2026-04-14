"""Request/response schemas for the chat API."""

from datetime import datetime
from typing import Annotated, Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class ConversationCreate(BaseModel):
    title: Optional[str] = None


class ConversationResponse(BaseModel):
    id: str = Field(validation_alias="_id")
    user_id: str
    title: str
    created_at: datetime
    updated_at: datetime
    message_count: int

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class ConversationListResponse(BaseModel):
    conversations: List[ConversationResponse]
    total: int

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class MessageCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000)
    # Limit: at most 4 images per message, at most ~1.5MB each (base64)
    images: List[Annotated[str, Field(max_length=2_000_000)]] = Field(
        default_factory=list, max_length=4
    )


class ToolCallResponse(BaseModel):
    tool_name: str
    arguments: Dict[str, Any]
    result: Dict[str, Any]
    duration_ms: int


class MessageResponse(BaseModel):
    id: str = Field(validation_alias="_id")
    conversation_id: str
    role: Literal["user", "assistant", "tool"]
    content: str
    images: List[str]
    tool_calls: List[ToolCallResponse]
    token_count: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class ConversationDetailResponse(BaseModel):
    conversation: ConversationResponse
    messages: List[MessageResponse]

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
