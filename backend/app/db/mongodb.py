"""
MongoDB connection management.

Handles database connection lifecycle with proper type safety,
connection pooling, and multi-pod compatibility.
"""

import asyncio
import logging
from typing import Any, Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket
from prometheus_client import Gauge
from pymongo import ReadPreference

from app.core.config import settings

logger = logging.getLogger(__name__)

# Import metrics for database monitoring
db_connections_active: Optional[Gauge] = None

try:
    from app.core.metrics import db_connections_active
except ImportError:
    pass


# Connection pool settings (Motor uses these internally)
# These can be overridden via MONGODB_URL query parameters
DEFAULT_MAX_POOL_SIZE = 50
DEFAULT_MIN_POOL_SIZE = 5
DEFAULT_SERVER_SELECTION_TIMEOUT_MS = 30000  # 30 seconds
DEFAULT_CONNECT_TIMEOUT_MS = 20000  # 20 seconds
DEFAULT_SOCKET_TIMEOUT_MS = 30000  # 30 seconds


def primary_gridfs_bucket(db: AsyncIOMotorDatabase) -> AsyncIOMotorGridFSBucket:
    """GridFS bucket pinned to the PRIMARY.

    The global client defaults to ``secondaryPreferred``; a freshly-written SBOM may not be
    on a secondary yet (replication lag), so read-your-writes paths — analysis loading a
    SBOM that ingest just uploaded — must read the primary or they hit a spurious
    ``no file in gridfs`` and silently skip the whole analysis.
    """
    return AsyncIOMotorGridFSBucket(db.with_options(read_preference=ReadPreference.PRIMARY))


async def open_gridfs_download_with_retry(
    fs: AsyncIOMotorGridFSBucket, file_id: ObjectId, attempts: int = 4, base_delay: float = 0.25
) -> Any:
    """Open a GridFS download stream, retrying with exponential backoff.

    Even reading the primary, a just-committed file can momentarily be unreadable under
    load; a short bounded retry turns a transient miss into a success instead of a failed
    scan. Re-raises the last error once ``attempts`` are exhausted.
    """
    last_err: Optional[Exception] = None
    for attempt in range(attempts):
        try:
            return await fs.open_download_stream(file_id)
        except Exception as err:  # gridfs NoFile etc. — bounded retry, then re-raise
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
        retryWrites=True,
        retryReads=True,
        compressors="zstd,zlib",
        readPreference=settings.MONGODB_READ_PREFERENCE,
    )

    # Validate connection by pinging the server
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
