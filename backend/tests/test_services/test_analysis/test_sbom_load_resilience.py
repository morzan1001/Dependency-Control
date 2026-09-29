"""SBOM GridFS load resilience: primary read with bounded retry."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.db.mongodb import open_gridfs_download_with_retry


class TestOpenGridfsDownloadWithRetry:
    def test_retries_then_succeeds(self):
        # two transient misses (file not replicated yet) then success
        fs = SimpleNamespace(
            open_download_stream=AsyncMock(side_effect=[RuntimeError("no file"), RuntimeError("no file"), "STREAM"])
        )
        result = asyncio.run(open_gridfs_download_with_retry(fs, "oid", attempts=4, base_delay=0))
        assert result == "STREAM"
        assert fs.open_download_stream.await_count == 3

    def test_raises_after_exhausting_attempts(self):
        fs = SimpleNamespace(open_download_stream=AsyncMock(side_effect=RuntimeError("still no file")))
        with pytest.raises(RuntimeError, match="still no file"):
            asyncio.run(open_gridfs_download_with_retry(fs, "oid", attempts=3, base_delay=0))
        assert fs.open_download_stream.await_count == 3
