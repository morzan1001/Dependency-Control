"""Chat API endpoints for the AI security assistant."""

import logging

import redis.asyncio as redis
from fastapi import HTTPException, status
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_404
from app.core.config import settings
from app.core.permissions import Permissions, has_permission
from app.models.system import SystemSettings
from app.models.user import User
from app.schemas.chat import (
    ConversationCreate,
    ConversationDetailResponse,
    ConversationListResponse,
    ConversationResponse,
    MessageCreate,
)
from app.services.chat.rate_limiter import ChatRateLimiter
from app.services.chat.service import ChatService

logger = logging.getLogger(__name__)

router = CustomAPIRouter()


async def _get_system_settings(db: AsyncIOMotorDatabase) -> SystemSettings:
    doc = await db["system_settings"].find_one({"_id": "current"})
    if doc:
        return SystemSettings(**doc)
    return SystemSettings()


def _check_chat_enabled() -> None:
    if not settings.CHAT_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Chat feature is currently disabled",
        )


def _check_permission(user: User, permission: str) -> None:
    if not has_permission(user.permissions, permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )


@router.post("/conversations", response_model=ConversationResponse, responses=RESP_AUTH)
async def create_conversation(
    body: ConversationCreate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ConversationResponse:
    """Create a new chat conversation."""
    _check_chat_enabled()
    _check_permission(current_user, Permissions.CHAT_ACCESS)

    service = ChatService(db)
    conv = await service.create_conversation(current_user, title=body.title)
    return ConversationResponse(
        id=conv["_id"],
        user_id=conv["user_id"],
        title=conv["title"],
        created_at=conv["created_at"],
        updated_at=conv["updated_at"],
        message_count=conv["message_count"],
    )


@router.get("/conversations", response_model=ConversationListResponse, responses=RESP_AUTH)
async def list_conversations(
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ConversationListResponse:
    """List the current user's chat conversations."""
    _check_chat_enabled()
    _check_permission(current_user, Permissions.CHAT_ACCESS)
    _check_permission(current_user, Permissions.CHAT_HISTORY_READ)

    service = ChatService(db)
    convs = await service.list_conversations(current_user)
    return ConversationListResponse(
        conversations=[
            ConversationResponse(
                id=c["_id"],
                user_id=c["user_id"],
                title=c["title"],
                created_at=c["created_at"],
                updated_at=c["updated_at"],
                message_count=c["message_count"],
            )
            for c in convs
        ],
        total=len(convs),
    )


@router.get("/conversations/{conversation_id}", response_model=ConversationDetailResponse, responses=RESP_AUTH_404)
async def get_conversation(
    conversation_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ConversationDetailResponse:
    """Get a conversation with its messages."""
    _check_chat_enabled()
    _check_permission(current_user, Permissions.CHAT_ACCESS)
    _check_permission(current_user, Permissions.CHAT_HISTORY_READ)

    service = ChatService(db)
    conv = await service.get_conversation(conversation_id, current_user)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    messages = await service.get_messages(conversation_id, current_user)
    return ConversationDetailResponse(
        conversation=ConversationResponse(
            id=conv["_id"],
            user_id=conv["user_id"],
            title=conv["title"],
            created_at=conv["created_at"],
            updated_at=conv["updated_at"],
            message_count=conv["message_count"],
        ),
        messages=messages,
    )


@router.delete("/conversations/{conversation_id}", responses=RESP_AUTH_404)
async def delete_conversation(
    conversation_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, str]:
    """Delete a conversation and all its messages."""
    _check_chat_enabled()
    _check_permission(current_user, Permissions.CHAT_HISTORY_DELETE)

    service = ChatService(db)
    deleted = await service.delete_conversation(conversation_id, current_user)
    if not deleted:
        raise HTTPException(status_code=404, detail="Conversation not found")

    return {"detail": "Conversation deleted"}


@router.post("/conversations/{conversation_id}/messages", responses=RESP_AUTH_404)
async def send_message(
    conversation_id: str,
    body: MessageCreate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> StreamingResponse:
    """Send a message and stream the AI response via SSE."""
    _check_chat_enabled()
    _check_permission(current_user, Permissions.CHAT_ACCESS)
    system_settings = await _get_system_settings(db)

    # Rate limiting (uses SystemSettings values — admin-tunable)
    try:
        async with redis.from_url(settings.REDIS_URL) as redis_client:
            limiter = ChatRateLimiter(redis_client)
            allowed, retry_after = await limiter.check_rate_limit(
                str(current_user.id),
                per_minute=system_settings.chat_rate_limit_per_minute,
                per_hour=system_settings.chat_rate_limit_per_hour,
            )
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(retry_after)},
            )
    except redis.RedisError:
        logger.warning("Redis unavailable for rate limiting, allowing request")

    # Verify conversation exists and belongs to user
    service = ChatService(db)
    conv = await service.get_conversation(conversation_id, current_user)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    return StreamingResponse(
        service.send_message(conversation_id, current_user, body.content, body.images),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
