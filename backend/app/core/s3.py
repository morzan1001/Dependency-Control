import functools
import logging
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from aiobotocore.session import AioSession, get_session
from botocore.config import Config as BotoConfig

from app.core.config import settings
from app.core.constants import S3_MULTIPART_PART_SIZE

logger = logging.getLogger(__name__)


@functools.cache
def _get_session() -> AioSession:
    return get_session()


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
        # botocore >= 1.36 sends x-amz-checksum-* headers, which GCS interop rejects with SignatureDoesNotMatch.
        "config": BotoConfig(
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    }
    if settings.S3_ENDPOINT_URL:
        kwargs["endpoint_url"] = settings.S3_ENDPOINT_URL
    async with session.create_client("s3", **kwargs) as client:
        yield client


def _bucket(bucket: str | None) -> str:
    return bucket or settings.S3_BUCKET_NAME


def archive_key_prefix() -> str:
    prefix = settings.S3_KEY_PREFIX.strip("/")
    return f"{prefix}/" if prefix else ""


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


async def upload_stream(
    key: str,
    source: AsyncIterator[bytes],
    *,
    content_type: str = "application/octet-stream",
    bucket: str | None = None,
    part_size: int = S3_MULTIPART_PART_SIZE,
) -> int:
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

            if buffer:
                resp = await s3.upload_part(
                    Bucket=b, Key=key, UploadId=upload_id, PartNumber=part_number, Body=bytes(buffer)
                )
                parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
                total += len(buffer)
                buffer.clear()

            if not parts:
                # Multipart needs at least one part, so an empty stream becomes a zero-byte PutObject.
                await s3.abort_multipart_upload(Bucket=b, Key=key, UploadId=upload_id)
                await s3.put_object(Bucket=b, Key=key, Body=b"", ContentType=content_type)
                return 0

            await s3.complete_multipart_upload(Bucket=b, Key=key, UploadId=upload_id, MultipartUpload={"Parts": parts})
            return total
        except BaseException:  # a cancelled upload leaves billed parts that list_objects never shows
            try:
                await s3.abort_multipart_upload(Bucket=b, Key=key, UploadId=upload_id)
            except Exception:
                logger.exception("AbortMultipartUpload failed for upload_id=%s", upload_id)
            raise


async def download_stream(key: str, *, bucket: str | None = None, chunk_size: int = 65536) -> AsyncIterator[bytes]:
    async with get_s3_client() as s3:
        response = await s3.get_object(Bucket=_bucket(bucket), Key=key)
        async with response["Body"] as stream:
            async for chunk in stream.iter_chunks(chunk_size):
                yield chunk


async def delete_object(key: str, *, bucket: str | None = None) -> None:
    async with get_s3_client() as s3:
        await s3.delete_object(Bucket=_bucket(bucket), Key=key)


async def list_objects(prefix: str = "", *, bucket: str | None = None) -> AsyncIterator[list[dict[str, Any]]]:
    """One listing page, at most 1000 objects, at a time."""
    kwargs: dict[str, Any] = {"Bucket": _bucket(bucket), "Prefix": prefix}
    async with get_s3_client() as s3:
        while True:
            response = await s3.list_objects_v2(**kwargs)
            yield response.get("Contents", [])
            token = response.get("NextContinuationToken")
            if not response.get("IsTruncated") or not token:
                return
            kwargs["ContinuationToken"] = token
