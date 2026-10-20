import logging
from datetime import timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.config import settings
from app.core.metrics import DbCommandMetrics, DbHeartbeatFailures, db_connections_active

logger = logging.getLogger(__name__)


DEFAULT_MAX_POOL_SIZE = 50
DEFAULT_MIN_POOL_SIZE = 5
DEFAULT_SERVER_SELECTION_TIMEOUT_MS = 30000
DEFAULT_CONNECT_TIMEOUT_MS = 20000
DEFAULT_SOCKET_TIMEOUT_MS = 30000
# Below the socket timeout, so mongod aborts a runaway read, which is not retried, before the driver resends it.
DEFAULT_MAX_TIME_MS = 25000


class Database:
    client: AsyncIOMotorClient[Any] | None = None


db = Database()


async def get_database() -> AsyncIOMotorDatabase[Any]:
    if db.client is None:
        raise RuntimeError("Database client not initialized.")
    return db.client[settings.DATABASE_NAME]


def create_client(url: str, **options: Any) -> AsyncIOMotorClient[Any]:
    # A keyword beats a URI option, so a readPreference in the URL cannot move reads to a lagging secondary.
    return AsyncIOMotorClient(
        url,
        readPreference="primary",
        tz_aware=True,
        tzinfo=timezone.utc,
        event_listeners=[DbCommandMetrics(), DbHeartbeatFailures()],
        **options,
    )


async def connect_to_mongo() -> None:
    db.client = create_client(
        settings.MONGODB_URL,
        maxPoolSize=DEFAULT_MAX_POOL_SIZE,
        minPoolSize=DEFAULT_MIN_POOL_SIZE,
        serverSelectionTimeoutMS=DEFAULT_SERVER_SELECTION_TIMEOUT_MS,
        connectTimeoutMS=DEFAULT_CONNECT_TIMEOUT_MS,
        socketTimeoutMS=DEFAULT_SOCKET_TIMEOUT_MS,
        retryWrites=True,
        retryReads=True,
        compressors="zstd,zlib",
    )

    try:
        await db.client.admin.command("ping")
        logger.info("Connected to MongoDB")
        db_connections_active.set(1)
    except Exception as e:
        logger.exception("Failed to connect to MongoDB: %s", e)
        db.client = None
        raise


async def close_mongo_connection() -> None:
    if db.client is not None:
        db.client.close()
        db.client = None
        logger.info("Closed MongoDB connection")
        db_connections_active.set(0)
