"""SBOMs stored the way ingest stores them: a GridFS file behind each scan ref."""

import json
from typing import Any

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.services.gridfs_maintenance import make_gridfs_ref


async def store_sbom(db: Any, sbom: dict[str, Any] | bytes, file_id: str | None = None) -> dict[str, Any]:
    """Upload the SBOM to the database's GridFS, under ``file_id`` when given, and return its scan ref."""
    data = sbom if isinstance(sbom, bytes) else json.dumps(sbom).encode()
    fs = AsyncIOMotorGridFSBucket(db)
    filename = "sbom.json"
    if file_id is None:
        file_id = str(await fs.upload_from_stream(filename, data))
    else:
        await fs.upload_from_stream_with_id(ObjectId(file_id), filename, data)
    return make_gridfs_ref(file_id, filename)
