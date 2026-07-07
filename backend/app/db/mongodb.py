"""MongoDB connection management."""

import asyncio
import logging
from typing import Any, Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket
from prometheus_client import Gauge
from pymongo import ReadPreference

from app.core.config import settings

logger = logging.getLogger(__name__)

db_connections_active: Optional[Gauge] = None

try:
    from app.core.metrics import db_connections_active
except ImportError:
    pass


DEFAULT_MAX_POOL_SIZE = 50
DEFAULT_MIN_POOL_SIZE = 5
DEFAULT_SERVER_SELECTION_TIMEOUT_MS = 30000
DEFAULT_CONNECT_TIMEOUT_MS = 20000
DEFAULT_SOCKET_TIMEOUT_MS = 30000


def primary_gridfs_bucket(db: AsyncIOMotorDatabase) -> AsyncIOMotorGridFSBucket:
    """Pin to PRIMARY so read-your-writes paths don't miss a just-written file on a lagging secondary."""
    return AsyncIOMotorGridFSBucket(db.with_options(read_preference=ReadPreference.PRIMARY))


async def open_gridfs_download_with_retry(
    fs: AsyncIOMotorGridFSBucket, file_id: ObjectId, attempts: int = 4, base_delay: float = 0.25
) -> Any:
    """Open a GridFS download stream, retrying with exponential backoff; a just-committed file can momentarily be unreadable under load."""
    last_err: Optional[Exception] = None
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

    client: Optional[AsyncIOMotorClient[Any]] = None


db = Database()


async def get_database() -> AsyncIOMotorDatabase[Any]:
    """Return the Motor database, or raise if the client is not initialized."""
    if db.client is None:
        raise RuntimeError("Database client not initialized.")
    return db.client[settings.DATABASE_NAME]


async def connect_to_mongo() -> None:
    """Establish the pooled connection to MongoDB."""
    db.client = AsyncIOMotorClient(
        settings.MONGODB_URL,
        maxPoolSize=DEFAULT_MAX_POOL_SIZE,
        minPoolSize=DEFAULT_MIN_POOL_SIZE,
        serverSelectionTimeoutMS=DEFAULT_SERVER_SELECTION_TIMEOUT_MS,
        connectTimeoutMS=DEFAULT_CONNECT_TIMEOUT_MS,
        socketTimeoutMS=DEFAULT_SOCKET_TIMEOUT_MS,
        retryWrites=True,
        retryReads=True,
        compressors="zstd,zlib",
        readPreference=settings.MONGODB_READ_PREFERENCE,
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
