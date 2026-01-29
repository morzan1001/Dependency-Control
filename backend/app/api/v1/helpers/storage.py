"""
Storage Helper Functions

Shared utilities for GridFS and file storage operations.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

logger = logging.getLogger(__name__)


async def load_from_gridfs(
    db: AsyncIOMotorDatabase,
    file_id: str,
) -> Optional[Dict[str, Any]]:
    """
    Load and parse JSON content from GridFS.

    Args:
        db: Database instance
        file_id: GridFS file ID as string

    Returns:
        Parsed JSON content or None if loading fails
    """
    try:
        fs = AsyncIOMotorGridFSBucket(db)
        grid_out = await fs.open_download_stream(ObjectId(file_id))
        content: bytes = await grid_out.read()
        return json.loads(content)
    except Exception as e:
        logger.error(f"Failed to load file from GridFS: {e}")
        return None


async def resolve_sbom_refs(
    db: AsyncIOMotorDatabase,
    sbom_items: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Resolve SBOM references from GridFS or inline data.

    Args:
        db: Database instance
        sbom_items: List of SBOM items (refs or inline data)

    Returns:
        List of resolved SBOMs with metadata
    """
    if not sbom_items:
        return []

    resolved_sboms = []
    fs = AsyncIOMotorGridFSBucket(db)

    for index, item in enumerate(sbom_items):
        if isinstance(item, dict) and item.get("type") == "gridfs_reference":
            gridfs_id = item.get("gridfs_id") or item.get("file_id")
            if gridfs_id:
                try:
                    stream = await fs.open_download_stream(ObjectId(gridfs_id))
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
                    logger.error(f"Failed to load SBOM from GridFS: {e}")
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
            # Invalid SBOM reference format
            logger.warning(
                f"Invalid SBOM reference format at index {index}: {type(item)}"
            )

    return resolved_sboms


async def delete_gridfs_files(
    db: AsyncIOMotorDatabase,
    file_ids: List[str],
) -> int:
    """
    Delete multiple files from GridFS.

    Args:
        db: Database instance
        file_ids: List of GridFS file IDs to delete

    Returns:
        Number of successfully deleted files
    """
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
