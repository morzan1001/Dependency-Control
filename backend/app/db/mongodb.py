"""
MongoDB connection management.

Handles database connection lifecycle with proper type safety,
connection pooling, and multi-pod compatibility.
"""

import logging
from typing import Any, Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.config import settings

logger = logging.getLogger(__name__)

# Import metrics for database monitoring
try:
    from app.core.metrics import db_connections_active
except ImportError:
    # Fallback if metrics module is not available yet (during initial setup)
    db_connections_active = None


# Connection pool settings (Motor uses these internally)
# These can be overridden via MONGODB_URL query parameters
DEFAULT_MAX_POOL_SIZE = 25 
DEFAULT_MIN_POOL_SIZE = 2 
DEFAULT_SERVER_SELECTION_TIMEOUT_MS = 30000  # 30 seconds
DEFAULT_CONNECT_TIMEOUT_MS = 20000  # 20 seconds
DEFAULT_SOCKET_TIMEOUT_MS = 30000  # 30 seconds


class Database:
    """Singleton database client holder."""

    client: Optional[AsyncIOMotorClient[Any]] = None


db = Database()


async def get_database() -> AsyncIOMotorDatabase[Any]:
    """
    Get the database instance.

    Returns:
        The Motor async database instance.

    Raises:
        RuntimeError: If the database client is not initialized.
    """
    if db.client is None:
        raise RuntimeError("Database client not initialized.")
    return db.client[settings.DATABASE_NAME]


async def connect_to_mongo() -> None:
    """
    Establish connection to MongoDB.

    Uses connection pooling for multi-pod compatibility.
    Motor handles connection pooling internally.
    """
    # Build connection options
    # Note: These can be overridden if specified in MONGODB_URL
    db.client = AsyncIOMotorClient(
        settings.MONGODB_URL,
        maxPoolSize=DEFAULT_MAX_POOL_SIZE,
        minPoolSize=DEFAULT_MIN_POOL_SIZE,
        serverSelectionTimeoutMS=DEFAULT_SERVER_SELECTION_TIMEOUT_MS,
        connectTimeoutMS=DEFAULT_CONNECT_TIMEOUT_MS,
        socketTimeoutMS=DEFAULT_SOCKET_TIMEOUT_MS,
    )

    # Validate connection by pinging the server
    try:
        await db.client.admin.command("ping")
        logger.info("Connected to MongoDB")
        if db_connections_active:
            db_connections_active.set(1)
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        db.client = None
        raise


async def close_mongo_connection() -> None:
    """Close the MongoDB connection gracefully."""
    if db.client is not None:
        db.client.close()
        db.client = None
        logger.info("Closed MongoDB connection")
        if db_connections_active:
            db_connections_active.set(0)
