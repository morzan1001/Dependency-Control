import json
from typing import Any

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.services.analysis import engine
from app.services.gridfs_maintenance import make_gridfs_ref


_FILENAME = "sbom.json"


def sbom_ref(file_id: str) -> dict[str, Any]:
    return make_gridfs_ref(file_id, _FILENAME)


async def store_sbom(db: Any, sbom: dict[str, Any] | bytes, file_id: str | None = None) -> dict[str, Any]:
    data = sbom if isinstance(sbom, bytes) else json.dumps(sbom).encode()
    fs = AsyncIOMotorGridFSBucket(db)
    if file_id is None:
        file_id = str(await fs.upload_from_stream(_FILENAME, data))
    else:
        await fs.upload_from_stream_with_id(ObjectId(file_id), _FILENAME, data)
    return sbom_ref(file_id)


def unreadable_downloads(monkeypatch: Any, file_ids: set[str]) -> None:
    """The analysis engine's reads of these stored SBOMs fail as in a GridFS outage."""
    real_bucket = engine.AsyncIOMotorGridFSBucket

    def bucket(db: Any) -> Any:
        fs = real_bucket(db)
        real_open = fs.open_download_stream

        async def open_download_stream(file_id: Any, *args: Any, **kwargs: Any) -> Any:
            if str(file_id) in file_ids:
                raise OSError("gridfs outage")
            return await real_open(file_id, *args, **kwargs)

        fs.open_download_stream = open_download_stream
        return fs

    monkeypatch.setattr(engine, "AsyncIOMotorGridFSBucket", bucket)
