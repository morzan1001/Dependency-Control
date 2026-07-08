"""Repository for broadcasts."""

from typing import List

from app.models.broadcast import Broadcast
from app.repositories.base import BaseRepository


class BroadcastRepository(BaseRepository[Broadcast]):
    collection_name = "broadcasts"
    model_class = Broadcast

    async def get_history(self, limit: int = 50) -> List[Broadcast]:
        return await self.find_many(
            query={},
            sort_by="created_at",
            sort_order=-1,
            limit=limit,
        )
