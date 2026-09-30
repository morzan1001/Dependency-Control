"""GridFS files: SBOM reference shape, JSON upload, load and streaming, and the orphan reaper, the one deleter of files."""

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

from bson import ObjectId
from gridfs.errors import NoFile
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.core import abatched
from app.core.constants import ARCHIVE_BATCH_SIZE, ARCHIVE_ORPHAN_MIN_AGE_HOURS
from app.db.mongodb import open_gridfs_download_with_retry

logger = logging.getLogger(__name__)

_GRIDFS_REFERENCE = "gridfs_reference"
# Every field holding str(fs.files _id); a file none of them names is an orphan.
_GRIDFS_REFERENCES = (
    ("scans", "sbom_refs.gridfs_id"),
    ("analysis_results", "result_gridfs_id"),
    ("compliance_reports", "artifact_gridfs_id"),
    ("callgraphs", "graph_gridfs_id"),
    ("adhoc_jobs", "input_file_id"),
    ("adhoc_jobs", "result_file_id"),
)


def make_gridfs_ref(file_id: Any, filename: str) -> dict[str, Any]:
    return {"type": _GRIDFS_REFERENCE, "gridfs_id": str(file_id), "filename": filename}


def gridfs_ref_id(ref: Any) -> str | None:
    """The GridFS file id of an SBOM reference, or None when ``ref`` is not one."""
    if isinstance(ref, dict) and ref.get("type") == _GRIDFS_REFERENCE and ref.get("gridfs_id"):
        return str(ref["gridfs_id"])
    return None


async def load_gridfs_json(fs: AsyncIOMotorGridFSBucket, file_id: str) -> Any:
    """Download and parse one stored JSON file; raises on failure so each caller keeps its own policy."""
    stream = await open_gridfs_download_with_retry(fs, ObjectId(file_id))
    return await asyncio.to_thread(json.loads, await stream.read())


async def iter_gridfs_chunks(stream: Any) -> AsyncIterator[bytes]:
    """Yield an open download stream chunk by chunk and close it once drained or abandoned."""
    try:
        while chunk := await stream.readchunk():
            yield chunk
    finally:
        # motor's AgnosticGridOut.close() returns a coroutine at runtime though the stub claims None.
        close_result = stream.close()
        if close_result is not None:
            await close_result


def extract_gridfs_ids_from_refs(sbom_refs: list[Any]) -> list[str]:
    return [gid for ref in sbom_refs if (gid := gridfs_ref_id(ref))]


async def upload_gridfs_json(db: Any, filename: str, obj: Any, metadata: dict[str, Any] | None = None) -> str:
    data = await asyncio.to_thread(lambda: json.dumps(obj).encode())
    return str(await AsyncIOMotorGridFSBucket(db).upload_from_stream(filename, data, metadata=metadata))


async def _referenced_ids(db: Any, file_ids: list[str]) -> set[str]:
    referenced: set[str] = set()
    for collection, field in _GRIDFS_REFERENCES:
        referenced.update(await db[collection].distinct(field, {field: {"$in": file_ids}}))
    return referenced


async def _reap_orphan_chunks(db: Any, cutoff: datetime) -> None:
    """Delete the chunks an upload left without a files document, e.g. when its pod died mid-upload."""
    before = ObjectId.from_datetime(cutoff)
    files_ids = db["fs.chunks"].aggregate([{"$match": {"files_id": {"$lt": before}}}, {"$group": {"_id": "$files_id"}}])
    async for batch in abatched(files_ids, ARCHIVE_BATCH_SIZE):
        ids = [group["_id"] for group in batch]
        present = set(await db["fs.files"].distinct("_id", {"_id": {"$in": ids}}))
        orphans = [file_id for file_id in ids if file_id not in present]
        if orphans:
            # A restore re-uploads under the archived (old) id, so its fresh chunks are left alone.
            await db["fs.chunks"].delete_many({"files_id": {"$in": orphans}, "_id": {"$lt": before}})


async def reap_orphan_gridfs_files(db: Any) -> int:
    """Delete GridFS files no registry field references, and orphan chunks, once older than the safety window."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ARCHIVE_ORPHAN_MIN_AGE_HOURS)
    fs = AsyncIOMotorGridFSBucket(db)
    deleted = 0
    old_files = db["fs.files"].find({"uploadDate": {"$lt": cutoff}}, {"_id": 1})
    async for batch in abatched(old_files, ARCHIVE_BATCH_SIZE):
        referenced = await _referenced_ids(db, [str(doc["_id"]) for doc in batch])
        for doc in batch:
            if str(doc["_id"]) in referenced:
                continue
            with contextlib.suppress(NoFile):
                await fs.delete(doc["_id"])
            deleted += 1
    await _reap_orphan_chunks(db, cutoff)
    if deleted:
        logger.info(f"GridFS orphan reaper: deleted {deleted} unreferenced file(s)")
    return deleted
