"""Chat API endpoints for the AI security assistant."""

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.responses import StreamingResponse

from app.api import deps
from app.api.deps import DatabaseDep, PermissionChecker
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_404
from app.core.config import settings
from app.core.permissions import Permissions
from app.models.user import User
from app.repositories.chat import ChatRepository
from app.schemas.chat import (
    ConversationCreate,
    ConversationDetailResponse,
    ConversationListResponse,
    ConversationResponse,
    MessageCreate,
)
from app.services.chat.rate_limiter import enforce_rate_limit
from app.services.chat.service import ChatService

_MSG_CONVERSATION_NOT_FOUND = "Conversation not found"

router = CustomAPIRouter()


def _check_chat_enabled() -> None:
    if not settings.CHAT_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Chat feature is currently disabled",
        )


ChatUserDep = Annotated[User, Depends(PermissionChecker(Permissions.CHAT_ACCESS))]
ChatHistoryReaderDep = Annotated[User, Depends(PermissionChecker(Permissions.CHAT_HISTORY_READ))]
ChatHistoryDeleterDep = Annotated[User, Depends(PermissionChecker(Permissions.CHAT_HISTORY_DELETE))]
# Route dependencies run before parameters, so chat access is refused before history reading.
_REQUIRES_CHAT_ACCESS = [Depends(PermissionChecker(Permissions.CHAT_ACCESS))]


@router.post("/conversations", responses=RESP_AUTH)
async def create_conversation(
    body: ConversationCreate,
    current_user: ChatUserDep,
    db: DatabaseDep,
) -> ConversationResponse:
    """Create a new chat conversation."""
    _check_chat_enabled()

    conv = await ChatService(db).create_conversation(current_user, title=body.title)
    return ConversationResponse.model_validate(conv)


@router.get("/conversations", responses=RESP_AUTH, dependencies=_REQUIRES_CHAT_ACCESS)
async def list_conversations(
    current_user: ChatHistoryReaderDep,
    db: DatabaseDep,
) -> ConversationListResponse:
    """List the current user's chat conversations."""
    _check_chat_enabled()

    convs = await ChatRepository(db).list_conversations(user_id=str(current_user.id))
    return ConversationListResponse(conversations=convs, total=len(convs))


@router.get("/conversations/{conversation_id}", responses=RESP_AUTH_404, dependencies=_REQUIRES_CHAT_ACCESS)
async def get_conversation(
    conversation_id: str,
    current_user: ChatHistoryReaderDep,
    db: DatabaseDep,
) -> ConversationDetailResponse:
    """Get a conversation with its messages."""
    _check_chat_enabled()

    repo = ChatRepository(db)
    conv = await repo.get_conversation(conversation_id, user_id=str(current_user.id))
    if not conv:
        raise HTTPException(status_code=404, detail=_MSG_CONVERSATION_NOT_FOUND)

    messages = await repo.get_recent_messages(conversation_id, limit=100)
    return ConversationDetailResponse(conversation=conv, messages=messages)


@router.delete("/conversations/{conversation_id}", responses=RESP_AUTH_404)
async def delete_conversation(
    conversation_id: str,
    current_user: ChatHistoryDeleterDep,
    db: DatabaseDep,
) -> dict[str, str]:
    """Delete a conversation and all its messages."""
    _check_chat_enabled()

    if not await ChatRepository(db).delete_conversation(conversation_id, user_id=str(current_user.id)):
        raise HTTPException(status_code=404, detail=_MSG_CONVERSATION_NOT_FOUND)

    return {"detail": "Conversation deleted"}


@router.post("/conversations/{conversation_id}/messages", responses=RESP_AUTH_404)
async def send_message(
    conversation_id: str,
    body: MessageCreate,
    current_user: ChatUserDep,
    db: DatabaseDep,
) -> StreamingResponse:
    """Send a message and stream the AI response via SSE."""
    _check_chat_enabled()
    system_settings = await deps.get_system_settings(db)

    await enforce_rate_limit(
        str(current_user.id),
        per_minute=system_settings.chat_rate_limit_per_minute,
        per_hour=system_settings.chat_rate_limit_per_hour,
    )

    service = ChatService(db)
    conv = await service.repo.get_conversation(conversation_id, user_id=str(current_user.id))
    if not conv:
        raise HTTPException(status_code=404, detail=_MSG_CONVERSATION_NOT_FOUND)

    return StreamingResponse(
        service.send_message(
            conversation_id,
            current_user,
            body.content,
            max_tool_rounds=system_settings.chat_max_tool_rounds,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
