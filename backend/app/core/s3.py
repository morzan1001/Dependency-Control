"""
S3-Compatible Storage Client

Provides async S3 operations for archive storage.
Supports both AWS S3 and MinIO via aiobotocore.
"""

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Optional

from aiobotocore.session import AioSession, get_session  # type: ignore[import-untyped]

from app.core.config import settings

logger = logging.getLogger(__name__)

_session: Optional[AioSession] = None


def _get_session() -> AioSession:
    global _session
    if _session is None:
        _session = get_session()
    return _session


def is_archive_enabled() -> bool:
    """Check if S3 archive storage is configured and enabled."""
    return bool(settings.S3_ENDPOINT_URL and settings.S3_ACCESS_KEY)


@asynccontextmanager
async def get_s3_client() -> AsyncGenerator[Any, None]:
    """
    Get an async S3 client as a context manager.

    Usage:
        async with get_s3_client() as s3:
            await s3.put_object(Bucket=..., Key=..., Body=...)
    """
    session = _get_session()

    kwargs: dict[str, Any] = {
        "region_name": settings.S3_REGION,
        "aws_access_key_id": settings.S3_ACCESS_KEY,
        "aws_secret_access_key": settings.S3_SECRET_KEY,
        "use_ssl": settings.S3_USE_SSL,
    }

    if settings.S3_ENDPOINT_URL:
        kwargs["endpoint_url"] = settings.S3_ENDPOINT_URL

    async with session.create_client("s3", **kwargs) as client:
        yield client


async def ensure_bucket_exists() -> None:
    """Create the archive bucket if it doesn't exist."""
    if not is_archive_enabled():
        return

    async with get_s3_client() as s3:
        try:
            await s3.head_bucket(Bucket=settings.S3_BUCKET_NAME)
            logger.info(f"S3 bucket '{settings.S3_BUCKET_NAME}' exists.")
        except Exception:
            logger.info(f"Creating S3 bucket '{settings.S3_BUCKET_NAME}'...")
            await s3.create_bucket(Bucket=settings.S3_BUCKET_NAME)
            logger.info(f"S3 bucket '{settings.S3_BUCKET_NAME}' created.")


async def upload_bytes(key: str, data: bytes, content_type: str = "application/gzip") -> int:
    """Upload bytes to S3. Returns the size uploaded."""
    async with get_s3_client() as s3:
        await s3.put_object(
            Bucket=settings.S3_BUCKET_NAME,
            Key=key,
            Body=data,
            ContentType=content_type,
        )
    return len(data)


async def download_bytes(key: str) -> bytes:
    """Download an object from S3 as bytes."""
    async with get_s3_client() as s3:
        response = await s3.get_object(
            Bucket=settings.S3_BUCKET_NAME,
            Key=key,
        )
        async with response["Body"] as stream:
            data: bytes = await stream.read()
            return data


async def delete_object(key: str) -> None:
    """Delete an object from S3."""
    async with get_s3_client() as s3:
        await s3.delete_object(
            Bucket=settings.S3_BUCKET_NAME,
            Key=key,
        )
