import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.s3 import (
    delete_object,
    ensure_bucket_exists,
    get_s3_client,
    is_archive_enabled,
)

MODULE = "app.core.s3"


class TestGetS3Client:
    def test_checksums_only_when_required(self):
        # botocore >= 1.36 sends x-amz-checksum-* headers, which GCS interop rejects with SignatureDoesNotMatch.
        captured = {}

        class FakeClientCtx:
            async def __aenter__(self):
                return AsyncMock()

            async def __aexit__(self, *args):
                return False

        mock_session = MagicMock()
        mock_session.create_client = lambda service, **kwargs: (captured.update(kwargs), FakeClientCtx())[1]

        async def run():
            async with get_s3_client():
                pass

        with (
            patch(f"{MODULE}._get_session", return_value=mock_session),
            patch(f"{MODULE}.settings") as mock_settings,
        ):
            mock_settings.S3_REGION = "europe-west1"
            mock_settings.S3_ACCESS_KEY = "ak"
            mock_settings.S3_SECRET_KEY = "sk"
            mock_settings.S3_USE_SSL = True
            mock_settings.S3_ENDPOINT_URL = "https://storage.googleapis.com"
            asyncio.run(run())

        config = captured.get("config")
        assert config is not None
        assert config.request_checksum_calculation == "when_required"
        assert config.response_checksum_validation == "when_required"


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


class TestEnsureBucketExists:
    def test_skips_when_not_enabled(self):
        with patch(f"{MODULE}.is_archive_enabled", return_value=False):
            asyncio.run(ensure_bucket_exists())

    def test_does_not_create_if_bucket_exists(self):
        mock_s3 = AsyncMock()
        mock_s3.head_bucket = AsyncMock()  # no exception means the bucket exists

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


class TestArchiveKeyPrefix:
    @pytest.mark.parametrize(
        ("configured", "prefix"),
        [("", ""), ("dc-a", "dc-a/"), ("/dc-a/", "dc-a/"), ("shared/dc-a", "shared/dc-a/")],
    )
    def test_the_configured_prefix_becomes_one_leading_path(self, configured, prefix):
        from app.core.s3 import archive_key_prefix

        with patch(f"{MODULE}.settings") as mock_settings:
            mock_settings.S3_KEY_PREFIX = configured
            assert archive_key_prefix() == prefix
