"""A reaped GridFS file never comes back, so each reader reports it on the first read instead of retrying."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from bson import ObjectId
from gridfs.errors import NoFile

from app.services.analysis import engine
from app.services.gridfs_maintenance import load_gridfs_json


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "load",
    [load_gridfs_json, lambda fs, file_id: engine._load_sbom(fs, file_id, 1, False)],
    ids=["stored-json", "sbom"],
)
async def test_a_missing_file_is_reported_on_the_first_read(load):
    fs = SimpleNamespace(open_download_stream=AsyncMock(side_effect=NoFile("gone")))

    with pytest.raises(NoFile):
        await load(fs, str(ObjectId()))
    assert fs.open_download_stream.await_count == 1
