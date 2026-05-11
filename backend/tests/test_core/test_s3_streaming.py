from typing import AsyncIterator
from unittest.mock import patch

import pytest

from tests.helpers.fake_s3 import FakeS3Client, fake_get_s3_client


@pytest.fixture
def fake_s3():
    fake = FakeS3Client()
    with patch("app.core.s3.get_s3_client", lambda: fake_get_s3_client(fake)):
        with patch("app.core.s3.settings") as mock_settings:
            mock_settings.S3_BUCKET_NAME = "test-bucket"
            mock_settings.S3_REGION = "us-east-1"
            mock_settings.S3_ACCESS_KEY = "ak"
            mock_settings.S3_SECRET_KEY = "sk"
            mock_settings.S3_ENDPOINT_URL = "http://localhost:9000"
            mock_settings.S3_USE_SSL = False
            yield fake


@pytest.mark.asyncio
async def test_upload_stream_assembles_parts(fake_s3):
    from app.core.s3 import upload_stream

    async def source() -> AsyncIterator[bytes]:
        # Yield in small bits — upload_stream must buffer to part size
        for chunk in (b"A" * 1_000_000, b"B" * 6_000_000, b"C" * 100_000):
            yield chunk

    total = await upload_stream("proj/scan.bundle", source())
    assert total == 7_100_000
    assert fake_s3.objects["proj/scan.bundle"] == b"A" * 1_000_000 + b"B" * 6_000_000 + b"C" * 100_000
    assert fake_s3.aborted_uploads == []


@pytest.mark.asyncio
async def test_upload_stream_aborts_on_part_failure(fake_s3):
    from app.core.s3 import upload_stream

    fake_s3.fail_next_upload_part = True

    async def source() -> AsyncIterator[bytes]:
        yield b"X" * 6_000_000

    with pytest.raises(RuntimeError, match="simulated"):
        await upload_stream("proj/scan.bundle", source())

    assert len(fake_s3.aborted_uploads) == 1
    assert "proj/scan.bundle" not in fake_s3.objects


@pytest.mark.asyncio
async def test_download_stream_chunks_body(fake_s3):
    from app.core.s3 import download_stream

    fake_s3.objects["k"] = b"D" * 200_000

    chunks: list[bytes] = []
    async for chunk in download_stream("k"):
        chunks.append(chunk)
    assert b"".join(chunks) == b"D" * 200_000
    assert len(chunks) > 1  # confirms chunking


@pytest.mark.asyncio
async def test_upload_stream_with_bucket_override(fake_s3):
    from app.core.s3 import upload_stream

    async def source() -> AsyncIterator[bytes]:
        yield b"Z" * 100

    await upload_stream("k", source(), bucket="alt-bucket")
    assert "k" in fake_s3.objects


@pytest.mark.asyncio
async def test_upload_bytes_still_works(fake_s3):
    """Backward-compat wrapper for small uploads."""
    from app.core.s3 import upload_bytes
    n = await upload_bytes("small", b"hello")
    assert n == 5
    assert fake_s3.objects["small"] == b"hello"


@pytest.mark.asyncio
async def test_download_bytes_still_works(fake_s3):
    """Backward-compat wrapper for small downloads."""
    from app.core.s3 import download_bytes
    fake_s3.objects["small"] = b"world"
    data = await download_bytes("small")
    assert data == b"world"


@pytest.mark.asyncio
async def test_delete_object_with_bucket_override(fake_s3):
    from app.core.s3 import delete_object
    fake_s3.objects["k"] = b"x"
    await delete_object("k", bucket="alt-bucket")
    assert "k" not in fake_s3.objects


@pytest.mark.asyncio
async def test_list_objects_returns_under_prefix(fake_s3):
    from app.core.s3 import list_objects
    fake_s3.objects["a/1"] = b"a"
    fake_s3.objects["a/2"] = b"b"
    fake_s3.objects["b/1"] = b"c"
    result = await list_objects(prefix="a/")
    keys = sorted([item["Key"] for item in result])
    assert keys == ["a/1", "a/2"]
