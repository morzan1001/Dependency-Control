"""
Broadcast Repository

Centralizes all database operations for broadcasts.
"""

from typing import List

from app.models.broadcast import Broadcast
from app.repositories.base import BaseRepository


class BroadcastRepository(BaseRepository[Broadcast]):
    """Repository for broadcast database operations."""

    collection_name = "broadcasts"
    model_class = Broadcast

    async def get_history(self, limit: int = 50) -> List[Broadcast]:
        """Get broadcast history sorted by creation date (newest first)."""
        return await self.find_many(
            query={},
            sort_by="created_at",
            sort_order=-1,
            limit=limit,
        )
