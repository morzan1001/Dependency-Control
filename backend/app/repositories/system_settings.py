"""Repository for system settings."""

from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.system import SystemSettings


class SystemSettingsRepository:
    SETTINGS_ID = "current"

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.system_settings

    async def get(self, auto_init: bool = False) -> SystemSettings:
        """auto_init persists defaults to the DB when no settings document exists."""
        data = await self.collection.find_one({"_id": self.SETTINGS_ID})
        if data:
            return SystemSettings(**data)

        default_settings = SystemSettings()
        if auto_init:
            await self.collection.insert_one(default_settings.model_dump(by_alias=True))
        return default_settings

    async def update(self, update_data: dict[str, Any]) -> SystemSettings:
        await self.collection.update_one(
            {"_id": self.SETTINGS_ID},
            {"$set": update_data},
            upsert=True,
        )
        return await self.get()
