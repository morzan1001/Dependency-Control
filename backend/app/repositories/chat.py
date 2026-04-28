"""Repository for chat conversations and messages."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.metrics import track_db_operation

_CONV_COL = "chat_conversations"
_MSG_COL = "chat_messages"


class ChatRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.conversations = db[_CONV_COL]
        self.messages = db[_MSG_COL]

    async def create_conversation(self, user_id: str, title: str = "New Conversation") -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        doc = {
            "_id": str(uuid.uuid4()),
            "user_id": user_id,
            "title": title,
            "created_at": now,
            "updated_at": now,
            "message_count": 0,
        }
        with track_db_operation(_CONV_COL, "insert"):
            await self.conversations.insert_one(doc)
        return doc

    async def list_conversations(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        with track_db_operation(_CONV_COL, "find"):
            cursor = self.conversations.find(
                {"user_id": user_id},
                sort=[("updated_at", -1)],
                limit=limit,
            )
            return await cursor.to_list(length=limit)

    async def get_conversation(self, conversation_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        with track_db_operation(_CONV_COL, "find_one"):
            return await self.conversations.find_one({"_id": conversation_id, "user_id": user_id})

    async def delete_conversation(self, conversation_id: str, user_id: str) -> bool:
        with track_db_operation(_CONV_COL, "delete"):
            result = await self.conversations.delete_one({"_id": conversation_id, "user_id": user_id})
        if result.deleted_count > 0:
            with track_db_operation(_MSG_COL, "delete_many"):
                await self.messages.delete_many({"conversation_id": conversation_id})
            return True
        return False

    async def update_conversation_title(self, conversation_id: str, user_id: str, title: str) -> None:
        with track_db_operation(_CONV_COL, "update"):
            await self.conversations.update_one(
                {"_id": conversation_id, "user_id": user_id},
                {"$set": {"title": title, "updated_at": datetime.now(timezone.utc)}},
            )

    async def add_message(
        self,
        conversation_id: str,
        role: str,
        content: str = "",
        images: Optional[List[str]] = None,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        token_count: int = 0,
    ) -> Dict[str, Any]:
        doc = {
            "_id": str(uuid.uuid4()),
            "conversation_id": conversation_id,
            "role": role,
            "content": content,
            "images": images or [],
            "tool_calls": tool_calls or [],
            "token_count": token_count,
            "created_at": datetime.now(timezone.utc),
        }
        with track_db_operation(_MSG_COL, "insert"):
            await self.messages.insert_one(doc)
        with track_db_operation(_CONV_COL, "update"):
            await self.conversations.update_one(
                {"_id": conversation_id},
                {
                    "$inc": {"message_count": 1},
                    "$set": {"updated_at": datetime.now(timezone.utc)},
                },
            )
        return doc

    async def get_messages(self, conversation_id: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        with track_db_operation(_MSG_COL, "find"):
            cursor = self.messages.find(
                {"conversation_id": conversation_id},
                sort=[("created_at", 1)],
                skip=skip,
                limit=limit,
            )
            return await cursor.to_list(length=limit)

    async def get_recent_messages(self, conversation_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Get the most recent N messages for context building."""
        with track_db_operation(_MSG_COL, "find"):
            cursor = self.messages.find(
                {"conversation_id": conversation_id},
                sort=[("created_at", -1)],
                limit=limit,
            )
            messages = await cursor.to_list(length=limit)
        messages.reverse()
        return messages
