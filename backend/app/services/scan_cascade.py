"""The one cascade that removes everything a scan owns.

Retention, archival and project deletion all route through it: a second hand-maintained list of
the same collections is how ``crypto_assets`` and ``finding_records`` came to outlive their project.
"""

import logging
from typing import Any

from app.core.constants import SCAN_KEYED_COLLECTIONS, SCAN_SCOPED_COLLECTIONS
from app.services.gridfs_maintenance import cleanup_gridfs_files, extract_gridfs_ids_from_refs

logger = logging.getLogger(__name__)


async def collect_gridfs_ids(db: Any, scan_ids: list[str]) -> list[str]:
    """Collect all GridFS IDs referenced by the given scans."""
    gridfs_ids: list[str] = []
    async for scan_doc in db.scans.find({"_id": {"$in": scan_ids}}, {"sbom_refs": 1}):
        gridfs_ids.extend(extract_gridfs_ids_from_refs(scan_doc.get("sbom_refs", [])))
    return gridfs_ids


async def delete_scans_and_related_data(db: Any, scan_ids: list[str], label: str = "") -> int:
    """Delete the scans and every document keyed to them, GridFS SBOMs included."""
    if not scan_ids:
        return 0

    gridfs_ids = await collect_gridfs_ids(db, scan_ids)

    for collection in SCAN_SCOPED_COLLECTIONS:
        await getattr(db, collection).delete_many({"scan_id": {"$in": scan_ids}})
    for collection in SCAN_KEYED_COLLECTIONS:
        await getattr(db, collection).delete_many({"_id": {"$in": scan_ids}})
    result = await db.scans.delete_many({"_id": {"$in": scan_ids}})

    await cleanup_gridfs_files(db, gridfs_ids, deleted_scan_ids=scan_ids)

    if label:
        logger.info(f"{label}: Deleted {result.deleted_count} scans ({len(gridfs_ids)} GridFS files).")

    count: int = result.deleted_count
    return count
