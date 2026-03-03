"""Tests for S3-compatible storage client.

Tests the async S3 client functions with mocked aiobotocore session.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.s3 import (
    delete_object,
    download_bytes,
    ensure_bucket_exists,
    is_archive_enabled,
    upload_bytes,
)

MODULE = "app.core.s3"


# ---------------------------------------------------------------------------
# is_archive_enabled
# ---------------------------------------------------------------------------

class TestIsArchiveEnabled:
    def test_enabled_when_both_set(self):
        with patch(f"{MODULE}.settings") as mock_settings:
            mock_settings.S3_ENDPOINT_URL = "http://minio:9000"
            mock_settings.S3_ACCESS_KEY = "minioadmin"
            assert is_archive_enabled() is True

    def test_disabled_when_endpoint_empty(self):
        with patch(f"{MODULE}.settings") as mock_settings:
            mock_settings.S3_ENDPOINT_URL = ""
            mock_settings.S3_ACCESS_KEY = "minioadmin"
            assert is_archive_enabled() is False

    def test_disabled_when_access_key_empty(self):
        with patch(f"{MODULE}.settings") as mock_settings:
            mock_settings.S3_ENDPOINT_URL = "http://minio:9000"
            mock_settings.S3_ACCESS_KEY = ""
            assert is_archive_enabled() is False

    def test_disabled_when_both_empty(self):
        with patch(f"{MODULE}.settings") as mock_settings:
            mock_settings.S3_ENDPOINT_URL = ""
            mock_settings.S3_ACCESS_KEY = ""
            assert is_archive_enabled() is False


# ---------------------------------------------------------------------------
# ensure_bucket_exists
# ---------------------------------------------------------------------------

class TestEnsureBucketExists:
    def test_skips_when_not_enabled(self):
        with patch(f"{MODULE}.is_archive_enabled", return_value=False):
            asyncio.run(ensure_bucket_exists())
            # No error = success (nothing to assert, just verify no exception)

    def test_does_not_create_if_bucket_exists(self):
        mock_s3 = AsyncMock()
        mock_s3.head_bucket = AsyncMock()  # No exception = bucket exists

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_s3)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.get_s3_client", return_value=mock_ctx),
            patch(f"{MODULE}.settings") as mock_settings,
        ):
            mock_settings.S3_BUCKET_NAME = "dc-archives"
            asyncio.run(ensure_bucket_exists())

        mock_s3.head_bucket.assert_called_once_with(Bucket="dc-archives")
        mock_s3.create_bucket.assert_not_called()

    def test_creates_bucket_if_not_exists(self):
        mock_s3 = AsyncMock()
        mock_s3.head_bucket = AsyncMock(side_effect=Exception("Not found"))
        mock_s3.create_bucket = AsyncMock()

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_s3)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}.get_s3_client", return_value=mock_ctx),
            patch(f"{MODULE}.settings") as mock_settings,
        ):
            mock_settings.S3_BUCKET_NAME = "dc-archives"
            asyncio.run(ensure_bucket_exists())

        mock_s3.create_bucket.assert_called_once_with(Bucket="dc-archives")


# ---------------------------------------------------------------------------
# upload_bytes
# ---------------------------------------------------------------------------

class TestUploadBytes:
    def test_uploads_data(self):
        mock_s3 = AsyncMock()
        mock_s3.put_object = AsyncMock()

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_s3)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        data = b"compressed-archive-data"

        with (
            patch(f"{MODULE}.get_s3_client", return_value=mock_ctx),
            patch(f"{MODULE}.settings") as mock_settings,
        ):
            mock_settings.S3_BUCKET_NAME = "dc-archives"
            result = asyncio.run(upload_bytes("proj-1/scan-1.json.gz", data))

        assert result == len(data)
        mock_s3.put_object.assert_called_once_with(
            Bucket="dc-archives",
            Key="proj-1/scan-1.json.gz",
            Body=data,
            ContentType="application/gzip",
        )


# ---------------------------------------------------------------------------
# download_bytes
# ---------------------------------------------------------------------------

class TestDownloadBytes:
    def test_downloads_data(self):
        expected_data = b"compressed-archive-data"

        mock_stream = AsyncMock()
        mock_stream.read = AsyncMock(return_value=expected_data)
        mock_stream.__aenter__ = AsyncMock(return_value=mock_stream)
        mock_stream.__aexit__ = AsyncMock(return_value=False)

        mock_s3 = AsyncMock()
        mock_s3.get_object = AsyncMock(return_value={"Body": mock_stream})

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_s3)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(f"{MODULE}.get_s3_client", return_value=mock_ctx),
            patch(f"{MODULE}.settings") as mock_settings,
        ):
            mock_settings.S3_BUCKET_NAME = "dc-archives"
            result = asyncio.run(download_bytes("proj-1/scan-1.json.gz"))

        assert result == expected_data
        mock_s3.get_object.assert_called_once_with(
            Bucket="dc-archives",
            Key="proj-1/scan-1.json.gz",
        )


# ---------------------------------------------------------------------------
# delete_object
# ---------------------------------------------------------------------------

class TestDeleteObject:
    def test_deletes_object(self):
        mock_s3 = AsyncMock()
        mock_s3.delete_object = AsyncMock()

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_s3)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(f"{MODULE}.get_s3_client", return_value=mock_ctx),
            patch(f"{MODULE}.settings") as mock_settings,
        ):
            mock_settings.S3_BUCKET_NAME = "dc-archives"
            asyncio.run(delete_object("proj-1/scan-1.json.gz"))

        mock_s3.delete_object.assert_called_once_with(
            Bucket="dc-archives",
            Key="proj-1/scan-1.json.gz",
        )
