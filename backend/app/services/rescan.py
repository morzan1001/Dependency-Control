"""The one way a rescan is created, whether the scheduler or a user asks for it."""

import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from app.core.constants import HOUSEKEEPING_RESCAN_LOCK_TTL_SECONDS, SCAN_ACTIVE_STATUSES, SCAN_STATUS_PENDING
from app.models.project import Scan
from app.repositories.distributed_locks import DistributedLocksRepository
from app.repositories.scans import ScanRepository

if TYPE_CHECKING:
    from app.core.worker import WorkerManager


def build_rescan(source: dict[str, Any]) -> Scan:
    return Scan(
        project_id=source["project_id"],
        branch=source.get("branch", "unknown"),
        commit_hash=source.get("commit_hash"),
        # A pipeline id would collide with ingest's (pipeline, commit) lookup.
        pipeline_id=None,
        pipeline_iid=source.get("pipeline_iid"),
        project_url=source.get("project_url"),
        pipeline_url=source.get("pipeline_url"),
        job_id=source.get("job_id"),
        job_started_at=source.get("job_started_at"),
        project_name=source.get("project_name"),
        commit_message=source.get("commit_message"),
        commit_tag=source.get("commit_tag"),
        sbom_refs=source.get("sbom_refs", []),
        sbom_generation=source.get("sbom_generation"),
        # Drives the analysis engine's analyzer selection, so the rescan must run under it too.
        scan_type=source.get("scan_type"),
        status=SCAN_STATUS_PENDING,
        created_at=datetime.now(timezone.utc),
        is_rescan=True,
        original_scan_id=str(source.get("original_scan_id") or source["_id"]),
    )


async def create_rescan(db: Any, source: dict[str, Any], worker_manager: "WorkerManager") -> Scan | None:
    """Queue a rescan of ``source``, or return None while its lineage already has one under way."""
    rescan = build_rescan(source)
    root_id = rescan.original_scan_id
    lock_repo = DistributedLocksRepository(db)
    lock_name = f"rescan_create:{rescan.project_id}:{root_id}"
    holder_id = f"rescan-{os.getenv('HOSTNAME', 'unknown')}"
    if not await lock_repo.acquire_lock(lock_name, holder_id, ttl_seconds=HOUSEKEEPING_RESCAN_LOCK_TTL_SECONDS):
        return None
    try:
        if await db.scans.find_one({"original_scan_id": root_id, "status": {"$in": SCAN_ACTIVE_STATUSES}}, {"_id": 1}):
            return None
        await ScanRepository(db).create(rescan)
        now = datetime.now(timezone.utc)
        await db.scans.update_one(
            {"_id": root_id},
            {
                "$set": {
                    "latest_run": {"scan_id": rescan.id, "status": SCAN_STATUS_PENDING, "created_at": now},
                    "last_rescanned_at": now,
                }
            },
        )
        await worker_manager.add_job(rescan.id)
        return rescan
    finally:
        await lock_repo.release_lock(lock_name, holder_id)
