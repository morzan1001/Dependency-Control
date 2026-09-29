"""Shared utilities for GridFS and file storage operations."""

import logging
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db.mongodb import primary_gridfs_bucket
from app.services.gridfs_maintenance import gridfs_ref_id, load_gridfs_json

logger = logging.getLogger(__name__)


async def load_from_gridfs(
    db: AsyncIOMotorDatabase,
    file_id: str,
) -> dict[str, Any] | None:
    """Load and parse JSON content from GridFS, or None if loading fails."""
    try:
        data: dict[str, Any] = await load_gridfs_json(primary_gridfs_bucket(db), file_id)
        return data
    except Exception as e:
        logger.exception("Failed to load file from GridFS: %s", e)
        return None


async def resolve_sbom_refs(
    db: AsyncIOMotorDatabase,
    sbom_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve SBOM references from GridFS or inline data into resolved SBOMs."""
    if not sbom_items:
        return []

    resolved_sboms = []
    fs = primary_gridfs_bucket(db)

    for index, item in enumerate(sbom_items):
        gridfs_id = gridfs_ref_id(item)
        if not gridfs_id:
            logger.warning(f"Invalid SBOM reference format at index {index}: {type(item)}")
            continue
        try:
            resolved_sboms.append(
                {
                    "index": index,
                    "filename": item.get("filename"),
                    "storage": "gridfs",
                    "sbom": await load_gridfs_json(fs, gridfs_id),
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

    return resolved_sboms
