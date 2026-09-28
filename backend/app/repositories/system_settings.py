"""Repository for system settings."""

from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.system import SystemSettings


class SystemSettingsRepository:
    SETTINGS_ID = "current"

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.system_settings

    async def get(self) -> SystemSettings:
        """The stored settings, or the defaults while none are stored; update() upserts the document."""
        data = await self.collection.find_one({"_id": self.SETTINGS_ID})
        return SystemSettings(**data) if data else SystemSettings()

    async def update(self, update_data: dict[str, Any]) -> SystemSettings:
        await self.collection.update_one(
            {"_id": self.SETTINGS_ID},
            {"$set": update_data},
            upsert=True,
        )
        return await self.get()
