import logging

from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient

from app.core.config import settings

logger = logging.getLogger(__name__)

# Import metrics for database monitoring
try:
    from app.core.metrics import db_connections_active
except ImportError:
    # Fallback if metrics module is not available yet (during initial setup)
    db_connections_active = None


class Database:
    client: Optional[AsyncIOMotorClient] = None


db = Database()


async def get_database():
    if db.client is None:
        raise RuntimeError("Database client not initialized.")
    return db.client[settings.DATABASE_NAME]


async def connect_to_mongo():
    db.client = AsyncIOMotorClient(settings.MONGODB_URL)
    logger.info("Connected to MongoDB")
    if db_connections_active:
        db_connections_active.set(1)


async def close_mongo_connection():
    if db.client is not None:
        db.client.close()
        logger.info("Closed MongoDB connection")
        if db_connections_active:
            db_connections_active.set(0)
