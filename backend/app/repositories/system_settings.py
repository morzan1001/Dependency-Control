"""Repository for system settings."""

from typing import Any, Dict, Optional

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

    async def get_raw(self) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one({"_id": self.SETTINGS_ID})

    async def update(self, update_data: Dict[str, Any]) -> SystemSettings:
        await self.collection.update_one(
            {"_id": self.SETTINGS_ID},
            {"$set": update_data},
            upsert=True,
        )
        return await self.get()

    async def get_field(self, field: str, default: Any = None) -> Any:
        data = await self.get_raw()
        if data:
            return data.get(field, default)
        return default

    async def is_feature_enabled(self, feature: str) -> bool:
        data = await self.get_raw()
        if data:
            return bool(data.get(feature, False))
        return False


def get_system_settings_repo(db: AsyncIOMotorDatabase) -> SystemSettingsRepository:
    return SystemSettingsRepository(db)
