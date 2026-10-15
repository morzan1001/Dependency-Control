import json
from typing import Any

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

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
