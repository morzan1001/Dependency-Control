"""S3-compatible storage client with streaming upload/download support."""

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, AsyncIterator, Optional, cast

from aiobotocore.session import AioSession, get_session  # type: ignore[import-untyped]

from app.core.config import settings
from app.core.constants import S3_MULTIPART_PART_SIZE

logger = logging.getLogger(__name__)

_session: Optional[AioSession] = None


def _get_session() -> AioSession:
    global _session
    if _session is None:
        _session = get_session()
    return _session


def _reset_session() -> None:
    """Drop the cached session. Useful after hard connection errors."""
    global _session
    _session = None


def is_archive_enabled() -> bool:
    return bool(settings.S3_ENDPOINT_URL and settings.S3_ACCESS_KEY)


@asynccontextmanager
async def get_s3_client() -> AsyncGenerator[Any, None]:
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


def _bucket(bucket: Optional[str]) -> str:
    return bucket or settings.S3_BUCKET_NAME


async def ensure_bucket_exists() -> None:
    if not is_archive_enabled():
        return
    async with get_s3_client() as s3:
        try:
            await s3.head_bucket(Bucket=settings.S3_BUCKET_NAME)
            logger.info(f"S3 bucket '{settings.S3_BUCKET_NAME}' exists.")
        except Exception:
            logger.info(f"Creating S3 bucket '{settings.S3_BUCKET_NAME}'...")
            await s3.create_bucket(Bucket=settings.S3_BUCKET_NAME)


async def upload_bytes(
    key: str, data: bytes, content_type: str = "application/gzip", *, bucket: Optional[str] = None
) -> int:
    """Single-PUT upload for small objects. Use upload_stream for large/streaming uploads."""
    async with get_s3_client() as s3:
        await s3.put_object(Bucket=_bucket(bucket), Key=key, Body=data, ContentType=content_type)
    return len(data)


async def download_bytes(key: str, *, bucket: Optional[str] = None) -> bytes:
    """Buffered download for small objects. Use download_stream for large objects."""
    async with get_s3_client() as s3:
        response = await s3.get_object(Bucket=_bucket(bucket), Key=key)
        async with response["Body"] as stream:
            return cast(bytes, await stream.read())


async def upload_stream(
    key: str,
    source: AsyncIterator[bytes],
    *,
    content_type: str = "application/octet-stream",
    bucket: Optional[str] = None,
    part_size: int = S3_MULTIPART_PART_SIZE,
) -> int:
    """Multipart-upload a stream to S3.

    Buffers each part to ``part_size`` bytes (default ~5.25 MiB) before sending,
    except the last part which can be smaller. Returns the total bytes uploaded.

    On any failure during the stream, calls ``AbortMultipartUpload`` and re-raises.
    An empty stream is uploaded as a zero-byte object via ``PutObject`` (multipart
    requires at least one part).
    """
    b = _bucket(bucket)
    async with get_s3_client() as s3:
        init = await s3.create_multipart_upload(Bucket=b, Key=key, ContentType=content_type)
        upload_id = init["UploadId"]
        try:
            parts: list[dict[str, Any]] = []
            buffer = bytearray()
            part_number = 1
            total = 0

            async for chunk in source:
                if not chunk:
                    continue
                buffer.extend(chunk)
                while len(buffer) >= part_size:
                    part = bytes(buffer[:part_size])
                    del buffer[:part_size]
                    resp = await s3.upload_part(
                        Bucket=b, Key=key, UploadId=upload_id, PartNumber=part_number, Body=part
                    )
                    parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
                    total += len(part)
                    part_number += 1

            # Final partial part (if any)
            if buffer:
                resp = await s3.upload_part(
                    Bucket=b, Key=key, UploadId=upload_id, PartNumber=part_number, Body=bytes(buffer)
                )
                parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
                total += len(buffer)
                buffer.clear()

            if not parts:
                # Empty stream: abort multipart and write a zero-byte object via PutObject.
                await s3.abort_multipart_upload(Bucket=b, Key=key, UploadId=upload_id)
                await s3.put_object(Bucket=b, Key=key, Body=b"", ContentType=content_type)
                return 0

            await s3.complete_multipart_upload(
                Bucket=b, Key=key, UploadId=upload_id, MultipartUpload={"Parts": parts}
            )
            return total
        except Exception:
            try:
                await s3.abort_multipart_upload(Bucket=b, Key=key, UploadId=upload_id)
            except Exception:
                logger.exception("AbortMultipartUpload failed for upload_id=%s", upload_id)
            raise


async def download_stream(
    key: str, *, bucket: Optional[str] = None, chunk_size: int = 65536
) -> AsyncIterator[bytes]:
    """Stream an S3 object as an async iterator of chunks (default 64 KiB each)."""
    async with get_s3_client() as s3:
        response = await s3.get_object(Bucket=_bucket(bucket), Key=key)
        async with response["Body"] as stream:
            async for chunk in stream.iter_chunks(chunk_size):
                yield chunk


async def delete_object(key: str, *, bucket: Optional[str] = None) -> None:
    async with get_s3_client() as s3:
        await s3.delete_object(Bucket=_bucket(bucket), Key=key)


async def list_objects(prefix: str = "", *, bucket: Optional[str] = None) -> list[dict[str, Any]]:
    """List S3 objects under a prefix. Returns the raw Contents entries (Key, Size, LastModified, ...)."""
    async with get_s3_client() as s3:
        response = await s3.list_objects_v2(Bucket=_bucket(bucket), Prefix=prefix)
        return cast(list[dict[str, Any]], response.get("Contents", []))
