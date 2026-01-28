"""
System Settings Repository

Centralizes all database operations for system settings.
"""

from typing import Any, Dict, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.system import SystemSettings


class SystemSettingsRepository:
    """Repository for system settings database operations."""

    SETTINGS_ID = "current"

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.system_settings

    async def get(self, auto_init: bool = False) -> SystemSettings:
        """
        Get current system settings.

        Args:
            auto_init: If True, creates default settings in DB if not found

        Returns:
            SystemSettings object (from DB or defaults)
        """
        data = await self.collection.find_one({"_id": self.SETTINGS_ID})
        if data:
            return SystemSettings(**data)

        default_settings = SystemSettings()
        if auto_init:
            await self.collection.insert_one(default_settings.model_dump(by_alias=True))
        return default_settings

    async def get_raw(self) -> Optional[Dict[str, Any]]:
        """
        Get raw settings document from database.

        Returns:
            Raw dict or None if not found
        """
        return await self.collection.find_one({"_id": self.SETTINGS_ID})

    async def update(self, update_data: Dict[str, Any]) -> SystemSettings:
        """
        Update system settings.

        Args:
            update_data: Dict of fields to update

        Returns:
            Updated SystemSettings object
        """
        await self.collection.update_one(
            {"_id": self.SETTINGS_ID},
            {"$set": update_data},
            upsert=True,
        )
        return await self.get()

    async def get_field(self, field: str, default: Any = None) -> Any:
        """
        Get a specific field from settings.

        Args:
            field: Field name to retrieve
            default: Default value if field not found

        Returns:
            Field value or default
        """
        data = await self.get_raw()
        if data:
            return data.get(field, default)
        return default

    async def is_feature_enabled(self, feature: str) -> bool:
        """
        Check if a feature flag is enabled.

        Args:
            feature: Feature name (e.g., 'gitlab_integration_enabled')

        Returns:
            True if enabled, False otherwise
        """
        data = await self.get_raw()
        if data:
            return bool(data.get(feature, False))
        return False


def get_system_settings_repo(db: AsyncIOMotorDatabase) -> SystemSettingsRepository:
    """Factory function to create a SystemSettingsRepository instance."""
    return SystemSettingsRepository(db)
