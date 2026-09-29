"""MongoDB connection management."""

import asyncio
import logging
from datetime import timezone
from typing import Any

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.core.config import settings
from app.core.metrics import DbCommandMetrics, DbHeartbeatFailures, db_connections_active

logger = logging.getLogger(__name__)


DEFAULT_MAX_POOL_SIZE = 50
DEFAULT_MIN_POOL_SIZE = 5
DEFAULT_SERVER_SELECTION_TIMEOUT_MS = 30000
DEFAULT_CONNECT_TIMEOUT_MS = 20000
DEFAULT_SOCKET_TIMEOUT_MS = 30000


async def open_gridfs_download_with_retry(
    fs: AsyncIOMotorGridFSBucket, file_id: ObjectId, attempts: int = 4, base_delay: float = 0.25
) -> Any:
    """Open a GridFS download stream, retrying with exponential backoff; a just-committed file can momentarily be unreadable under load."""
    last_err: Exception | None = None
    for attempt in range(attempts):
        try:
            return await fs.open_download_stream(file_id)
        except Exception as err:
            last_err = err
            if attempt < attempts - 1:
                await asyncio.sleep(base_delay * (2**attempt))
    assert last_err is not None
    raise last_err


class Database:
    """Singleton database client holder."""

    client: AsyncIOMotorClient[Any] | None = None


db = Database()


async def get_database() -> AsyncIOMotorDatabase[Any]:
    """Return the Motor database, or raise if the client is not initialized."""
    if db.client is None:
        raise RuntimeError("Database client not initialized.")
    return db.client[settings.DATABASE_NAME]


def create_client(url: str, **options: Any) -> AsyncIOMotorClient[Any]:
    """A client whose reads see their own writes and whose datetimes come back aware UTC."""
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
    """Establish the pooled connection to MongoDB."""
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
        if db_connections_active:
            db_connections_active.set(1)
    except Exception as e:
        logger.exception("Failed to connect to MongoDB: %s", e)
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
