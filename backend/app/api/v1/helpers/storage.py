"""Shared utilities for GridFS and file storage operations."""

import json
import logging
from typing import Any, Dict, List, Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.db.mongodb import open_gridfs_download_with_retry, primary_gridfs_bucket

logger = logging.getLogger(__name__)


async def load_from_gridfs(
    db: AsyncIOMotorDatabase,
    file_id: str,
) -> Optional[Dict[str, Any]]:
    """Load and parse JSON content from GridFS, or None if loading fails."""
    try:
        fs = primary_gridfs_bucket(db)
        grid_out = await open_gridfs_download_with_retry(fs, ObjectId(file_id))
        content: bytes = await grid_out.read()
        data: Dict[str, Any] = json.loads(content)
        return data
    except Exception as e:
        logger.exception("Failed to load file from GridFS: %s", e)
        return None


async def resolve_sbom_refs(
    db: AsyncIOMotorDatabase,
    sbom_items: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Resolve SBOM references from GridFS or inline data into resolved SBOMs."""
    if not sbom_items:
        return []

    resolved_sboms = []
    fs = primary_gridfs_bucket(db)

    for index, item in enumerate(sbom_items):
        if isinstance(item, dict) and item.get("type") == "gridfs_reference":
            gridfs_id = item.get("gridfs_id") or item.get("file_id")
            if gridfs_id:
                try:
                    stream = await open_gridfs_download_with_retry(fs, ObjectId(gridfs_id))
                    content: bytes = await stream.read()
                    sbom_data = json.loads(content)
                    resolved_sboms.append(
                        {
                            "index": index,
                            "filename": item.get("filename"),
                            "storage": "gridfs",
                            "sbom": sbom_data,
                        }
                    )
                except Exception as e:
                    logger.exception("Failed to load SBOM from GridFS: %s", e)
                    resolved_sboms.append(
                        {
                            "index": index,
                            "filename": item.get("filename"),
                            "storage": "gridfs",
                            "error": "Failed to load SBOM from storage",
                            "sbom": None,
                        }
                    )
        else:
            logger.warning(f"Invalid SBOM reference format at index {index}: {type(item)}")

    return resolved_sboms


async def delete_gridfs_files(
    db: AsyncIOMotorDatabase,
    file_ids: List[str],
) -> int:
    """Delete multiple files from GridFS, returning the count deleted."""
    if not file_ids:
        return 0

    fs = AsyncIOMotorGridFSBucket(db)
    deleted = 0

    for file_id in file_ids:
        try:
            await fs.delete(ObjectId(file_id))
            deleted += 1
        except Exception as e:
            logger.warning(f"Could not delete GridFS file {file_id}: {e}")

    return deleted
