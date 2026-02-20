import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional

from app.core.config import settings
from app.core.constants import (
    HOUSEKEEPING_BRANCH_SYNC_INTERVAL_HOURS,
    HOUSEKEEPING_MAIN_LOOP_INTERVAL_SECONDS,
    HOUSEKEEPING_MAX_SCAN_RETRIES,
    HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS,
    HOUSEKEEPING_STALE_SCAN_INTERVAL_SECONDS,
    HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS,
)
from app.db.mongodb import get_database
from app.models.project import Project, Scan
from app.repositories.system_settings import SystemSettingsRepository
from app.core.metrics import update_db_stats
from app.core.cache import update_cache_stats

if TYPE_CHECKING:
    from app.core.worker import WorkerManager

logger = logging.getLogger(__name__)


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure a datetime is timezone-aware (UTC).

    MongoDB returns naive datetimes (always UTC but without tzinfo).
    This adds UTC tzinfo if missing, enabling safe comparison with
    timezone-aware datetimes like datetime.now(timezone.utc).
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def _get_referenced_scan_ids(db) -> list[str]:
    """
    Get all scan IDs that are referenced by rescans (via original_scan_id).
    These scans should NOT be deleted by retention cleanup to prevent orphaned SBOM refs.

    Returns:
        List of scan IDs that are referenced by active rescans
    """
    cursor = db.scans.find(
        {
            "is_rescan": True,
            "original_scan_id": {"$exists": True, "$ne": None},
        },
        {"original_scan_id": 1},
    )

    referenced_ids = set()
    async for doc in cursor:
        original_id = doc.get("original_scan_id")
        if original_id:
            referenced_ids.add(original_id)

    return list(referenced_ids)


async def check_scheduled_rescans(worker_manager: Optional["WorkerManager"]) -> None:
    """
    Checks for projects that need a periodic re-scan.
    """
    if not worker_manager:
        return

    logger.debug("Checking for scheduled re-scans...")
    try:
        db = await get_database()

        # Get System Settings
        repo = SystemSettingsRepository(db)
        system_settings = await repo.get()

        # Iterate over all projects using Pydantic models
        async for project_data in db.projects.find({}):
            try:
                project = Project(**project_data)

                # Determine if enabled (project setting overrides global)
                enabled = project.rescan_enabled
                if enabled is None:
                    enabled = system_settings.global_rescan_enabled

                if not enabled:
                    continue

                # Determine interval (project setting overrides global)
                interval_hours = project.rescan_interval
                if interval_hours is None:
                    interval_hours = system_settings.global_rescan_interval

                if not interval_hours or interval_hours <= 0:
                    continue

                # Check last scan time
                if not project.last_scan_at:
                    # If never scanned, we can't re-scan
                    continue

                # Check if time to scan
                last_scan_aware = _ensure_utc(project.last_scan_at)
                next_scan_due = last_scan_aware + timedelta(hours=interval_hours)
                if datetime.now(timezone.utc) < next_scan_due:
                    continue

                # Find the latest SUCCESSFUL scan with SBOMs
                latest_valid_scan = await db.scans.find_one(
                    {
                        "project_id": project.id,
                        "status": "completed",
                        "sbom_refs": {"$exists": True, "$ne": []},
                    },
                    sort=[("created_at", -1)],
                )

                if not latest_valid_scan:
                    logger.info(f"Project {project.name} due for re-scan, but no valid previous scan with SBOMs found.")
                    continue

                # Acquire distributed lock to prevent duplicate rescans
                from app.repositories import DistributedLocksRepository
                import os

                lock_repo = DistributedLocksRepository(db)
                lock_name = f"rescan_create:{project.id}"
                holder_id = f"housekeeping-{os.getenv('HOSTNAME', 'unknown')}"

                if not await lock_repo.acquire_lock(lock_name, holder_id, ttl_seconds=60):
                    logger.debug(
                        f"Could not acquire lock for rescanning {project.name}. Another pod is creating rescan."
                    )
                    continue

                try:
                    # Re-check for active scans inside lock (TOCTOU prevention)
                    active_scan = await db.scans.find_one(
                        {
                            "project_id": project.id,
                            "status": {"$in": ["pending", "processing"]},
                        }
                    )

                    if active_scan:
                        logger.debug(f"Project {project.name} already has active scan")
                        continue

                    # Create rescan
                    logger.info(f"Triggering re-scan for project {project.name} (Last scan: {project.last_scan_at})")

                    new_scan = Scan(
                        project_id=project.id,
                        branch=latest_valid_scan.get("branch", "unknown"),
                        commit_hash=latest_valid_scan.get("commit_hash"),
                        pipeline_id=None,
                        pipeline_iid=latest_valid_scan.get("pipeline_iid"),
                        project_url=latest_valid_scan.get("project_url"),
                        pipeline_url=latest_valid_scan.get("pipeline_url"),
                        job_id=latest_valid_scan.get("job_id"),
                        job_started_at=latest_valid_scan.get("job_started_at"),
                        project_name=latest_valid_scan.get("project_name"),
                        commit_message=latest_valid_scan.get("commit_message"),
                        commit_tag=latest_valid_scan.get("commit_tag"),
                        sbom_refs=latest_valid_scan.get("sbom_refs", []),
                        status="pending",
                        created_at=datetime.now(timezone.utc),
                        is_rescan=True,
                        original_scan_id=str(latest_valid_scan["_id"]),
                    )

                    await db.scans.insert_one(new_scan.model_dump(by_alias=True))

                    # Update source scan to track new rescan (preserves completed status)
                    await db.scans.update_one(
                        {"_id": str(latest_valid_scan["_id"])},
                        {"$set": {"latest_rescan_id": new_scan.id}},
                    )

                    await worker_manager.add_job(new_scan.id)
                    logger.info(f"Rescan {new_scan.id} created for project {project.name}")

                finally:
                    # Always release lock
                    await lock_repo.release_lock(lock_name)
            except Exception as e:
                logger.error(f"Error processing project {project_data.get('name')}: {e}")

    except Exception as e:
        logger.error(f"Scheduled re-scan check failed: {e}")


async def run_housekeeping() -> None:
    """
    Periodically cleans up old scan data based on project retention settings.
    """
    logger.info("Starting housekeeping task...")

    try:
        db = await get_database()

        # Get System Settings
        repo = SystemSettingsRepository(db)
        system_settings = await repo.get()

        # Determine retention strategy
        if system_settings.retention_mode == "global":
            retention_days = system_settings.global_retention_days
            if retention_days > 0:
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
                logger.info(f"Running global housekeeping. Deleting scans older than {cutoff_date}")

                # Find old scans
                # IMPORTANT: Don't delete scans that are referenced by rescans (orphaned SBOM protection)
                referenced_scan_ids = await _get_referenced_scan_ids(db)

                cursor = db.scans.find(
                    {
                        "created_at": {"$lt": cutoff_date},
                        # Don't delete scans that have active rescans pointing to them
                        "_id": {"$nin": referenced_scan_ids},
                    },
                    {"_id": 1},
                )

                scan_ids_to_delete = [str(doc["_id"]) async for doc in cursor]

                if scan_ids_to_delete:
                    # Bulk delete all related data
                    await db.analysis_results.delete_many({"scan_id": {"$in": scan_ids_to_delete}})
                    await db.findings.delete_many({"scan_id": {"$in": scan_ids_to_delete}})
                    await db.finding_records.delete_many({"scan_id": {"$in": scan_ids_to_delete}})
                    await db.dependencies.delete_many({"scan_id": {"$in": scan_ids_to_delete}})
                    result = await db.scans.delete_many({"_id": {"$in": scan_ids_to_delete}})
                    logger.info(f"Global housekeeping: Deleted {result.deleted_count} scans.")

        else:
            # Project-specific retention (Optimized: Group by retention_days)
            logger.info("Running project-specific housekeeping...")

            # Group projects by retention_days to minimize DB queries
            pipeline = [
                {"$match": {"retention_days": {"$gt": 0}}},  # Ignore keep-forever
                {
                    "$group": {
                        "_id": "$retention_days",
                        "project_ids": {"$push": "$_id"},
                    }
                },
            ]

            async for group in db.projects.aggregate(pipeline):
                days = group["_id"]
                project_ids = group["project_ids"]

                if not days or days <= 0:
                    continue

                cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

                # Find scans for this batch of projects that are too old
                # IMPORTANT: Don't delete scans that are referenced by rescans
                referenced_scan_ids = await _get_referenced_scan_ids(db)

                cursor = db.scans.find(
                    {
                        "project_id": {"$in": project_ids},
                        "created_at": {"$lt": cutoff_date},
                        # Don't delete scans that have active rescans pointing to them
                        "_id": {"$nin": referenced_scan_ids},
                    },
                    {"_id": 1},
                )

                scan_ids_to_delete = [str(doc["_id"]) async for doc in cursor]

                if scan_ids_to_delete:
                    # Bulk delete all related data for this retention group
                    await db.analysis_results.delete_many({"scan_id": {"$in": scan_ids_to_delete}})
                    await db.findings.delete_many({"scan_id": {"$in": scan_ids_to_delete}})
                    await db.finding_records.delete_many({"scan_id": {"$in": scan_ids_to_delete}})
                    await db.dependencies.delete_many({"scan_id": {"$in": scan_ids_to_delete}})
                    result = await db.scans.delete_many({"_id": {"$in": scan_ids_to_delete}})

                    logger.info(
                        f"Retention {days} days: Deleted {result.deleted_count} scans from {len(project_ids)} projects."
                    )

    except Exception as e:
        logger.error(f"Housekeeping task failed: {e}")


async def trigger_stale_pending_scans(
    worker_manager: Optional["WorkerManager"] = None,
) -> None:
    """
    Finds scans that are 'pending' with results but haven't received new results
    for a configured threshold, and triggers their aggregation.

    This handles the case where only findings-based scanners (TruffleHog, OpenGrep, etc.)
    ran without an SBOM scan, or where the SBOM scanner failed to trigger.

    The logic:
    1. Find scans with status='pending' that have received_results (at least one scanner reported)
    2. Check if last_result_at is older than threshold
    3. Trigger aggregation for these scans
    """
    if not worker_manager:
        return

    logger.debug("Checking for stale pending scans...")
    try:
        db = await get_database()

        # Threshold since last result
        stale_threshold = datetime.now(timezone.utc) - timedelta(seconds=HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS)

        # Find pending scans that have results but are stale
        cursor = db.scans.find(
            {
                "status": "pending",
                "last_result_at": {"$lt": stale_threshold, "$exists": True},
                "received_results": {"$exists": True, "$ne": []},
            }
        )

        count = 0
        async for scan in cursor:
            scan_id = scan["_id"]
            received = scan.get("received_results", [])
            last_result = scan.get("last_result_at")

            logger.info(
                f"Triggering aggregation for stale pending scan {scan_id}. "
                f"Received results from: {received}. Last result at: {last_result}"
            )

            await worker_manager.add_job(str(scan_id))
            count += 1

        if count > 0:
            logger.info(f"Triggered aggregation for {count} stale pending scans.")

    except Exception as e:
        logger.error(f"Stale pending scan check failed: {e}")


async def recover_stuck_scans(
    worker_manager: Optional["WorkerManager"] = None,
) -> None:
    """
    Identifies scans that have been stuck in 'processing' state for too long
    and resets them to 'pending' or marks them as 'failed'.
    """
    logger.debug("Running stuck scan recovery...")
    try:
        db = await get_database()
        # Timeout threshold from settings
        timeout_threshold = datetime.now(timezone.utc) - timedelta(
            seconds=settings.HOUSEKEEPING_STUCK_SCAN_TIMEOUT_SECONDS
        )
        max_retries = HOUSEKEEPING_MAX_SCAN_RETRIES

        # Find stuck scans
        cursor = db.scans.find(
            {
                "status": "processing",
                "$or": [
                    {"analysis_started_at": {"$lt": timeout_threshold}},
                    {"analysis_started_at": {"$exists": False}},
                    {"analysis_started_at": None},
                ],
            }
        )

        async for scan in cursor:
            scan_id = scan["_id"]
            retry_count = scan.get("retry_count", 0)

            if retry_count < max_retries:
                logger.warning(
                    f"Scan {scan_id} stuck in processing. Resetting to pending (Retry {retry_count + 1}/{max_retries})."
                )
                result = await db.scans.update_one(
                    {"_id": scan_id, "status": "processing"},
                    {
                        "$set": {
                            "status": "pending",
                            "worker_id": None,
                            "analysis_started_at": None,
                        },
                        "$inc": {"retry_count": 1},
                    },
                )

                # Re-queue the job if worker_manager is available and we successfully reset it
                if worker_manager and result.modified_count > 0:
                    await worker_manager.add_job(str(scan_id))

            else:
                logger.error(f"Scan {scan_id} failed after {max_retries} retries.")
                await db.scans.update_one(
                    {"_id": scan_id, "status": "processing"},
                    {
                        "$set": {
                            "status": "failed",
                            "error": "Analysis timed out or worker crashed multiple times.",
                        }
                    },
                )

    except Exception as e:
        logger.error(f"Stuck scan recovery failed: {e}")


async def sync_project_branches(project_data: dict, db) -> None:
    """Sync branch status for a single project against its VCS provider."""
    project_id = project_data["_id"]
    project_name = project_data.get("name", project_id)

    # Determine VCS provider
    gitlab_instance_id = project_data.get("gitlab_instance_id")
    gitlab_project_id = project_data.get("gitlab_project_id")
    github_instance_id = project_data.get("github_instance_id")
    github_repo_path = project_data.get("github_repository_path")

    vcs_branches: Optional[list] = None

    try:
        if gitlab_instance_id and gitlab_project_id:
            from app.repositories.gitlab_instances import GitLabInstanceRepository
            from app.services.gitlab import GitLabService

            instance_repo = GitLabInstanceRepository(db)
            instance = await instance_repo.get_by_id(gitlab_instance_id)
            if instance and instance.access_token:
                service = GitLabService(instance)
                vcs_branches = await service.list_branches(gitlab_project_id)

        elif github_instance_id and github_repo_path:
            from app.repositories.github_instances import GitHubInstanceRepository
            from app.services.github import GitHubService

            instance_repo = GitHubInstanceRepository(db)
            instance = await instance_repo.get_by_id(github_instance_id)
            if instance and instance.access_token:
                service = GitHubService(instance)
                parts = github_repo_path.split("/", 1)
                if len(parts) == 2:
                    vcs_branches = await service.list_branches(parts[0], parts[1])

        if vcs_branches is None:
            return

        # Get branches we know from scans
        our_branches = await db.scans.distinct("branch", {"project_id": project_id})
        vcs_set = set(vcs_branches)

        deleted = sorted(b for b in our_branches if b not in vcs_set)

        update_fields: dict = {
            "deleted_branches": deleted,
            "branches_checked_at": datetime.now(timezone.utc),
        }

        # If deleted branches changed, check if latest_scan_id is on a deleted branch
        if deleted:
            current_scan_id = project_data.get("latest_scan_id")
            if current_scan_id:
                scan_doc = await db.scans.find_one(
                    {"_id": current_scan_id}, {"branch": 1}
                )
                if scan_doc and scan_doc.get("branch") in deleted:
                    # Find latest completed scan on an active branch
                    active_scan = await db.scans.find_one(
                        {
                            "project_id": project_id,
                            "branch": {"$nin": deleted},
                            "status": "completed",
                        },
                        sort=[("created_at", -1)],
                    )
                    if active_scan:
                        update_fields["latest_scan_id"] = active_scan["_id"]
                        update_fields["last_scan_at"] = _ensure_utc(active_scan.get("created_at"))
                        # Update project stats from the active scan
                        if active_scan.get("stats"):
                            update_fields["stats"] = active_scan["stats"]
                        logger.info(
                            f"Project {project_name}: updated latest_scan_id to "
                            f"active branch '{active_scan.get('branch')}'"
                        )
                    else:
                        # No active scans at all — clear stats
                        update_fields["latest_scan_id"] = None
                        update_fields["stats"] = None
                        logger.info(f"Project {project_name}: no active branch scans, cleared stats")

        await db.projects.update_one({"_id": project_id}, {"$set": update_fields})

        if deleted:
            logger.info(f"Project {project_name}: {len(deleted)} deleted branch(es) detected")

    except Exception as e:
        logger.error(f"Branch sync failed for project {project_name}: {e}")


async def sync_branch_status() -> None:
    """Sync branch status for all projects with VCS connections."""
    logger.info("Starting branch status sync...")
    try:
        db = await get_database()

        cursor = db.projects.find(
            {"$or": [
                {"gitlab_instance_id": {"$exists": True, "$ne": None}},
                {"github_instance_id": {"$exists": True, "$ne": None}},
            ]},
        )

        count = 0
        async for project_data in cursor:
            await sync_project_branches(project_data, db)
            count += 1

        logger.info(f"Branch status sync completed for {count} project(s)")
    except Exception as e:
        logger.error(f"Branch status sync failed: {e}")


async def stale_scan_loop(
    worker_manager: Optional["WorkerManager"] = None,
) -> None:
    """
    Fast loop to check for stale pending scans that need aggregation.
    Runs frequently to quickly catch scans without SBOM trigger.
    """
    while True:
        try:
            await trigger_stale_pending_scans(worker_manager)
        except Exception as e:
            logger.error(f"Stale scan loop failed: {e}")

        await asyncio.sleep(HOUSEKEEPING_STALE_SCAN_INTERVAL_SECONDS)


async def housekeeping_loop(
    worker_manager: Optional["WorkerManager"] = None,
) -> None:
    """
    Runs the housekeeping tasks.
    - Stuck scan recovery: On each loop iteration
    - Scheduled re-scans: On each loop iteration
    - Database stats update: On each loop iteration
    - Cache stats update: On each loop iteration
    - Data retention cleanup: Every 24 hours
    - Branch status sync: Every 6 hours

    Note: Stale pending scan aggregation runs in a separate faster loop.
    """
    # Use timezone-aware datetime for consistent comparison
    last_retention_run = datetime.min.replace(tzinfo=timezone.utc)
    last_branch_sync = datetime.min.replace(tzinfo=timezone.utc)

    while True:
        # Run stuck scan recovery
        await recover_stuck_scans(worker_manager)

        # Run scheduled re-scans
        await check_scheduled_rescans(worker_manager)

        # Update database statistics metrics
        try:
            db = await get_database()
            await update_db_stats(db)
        except Exception as e:
            logger.error(f"Failed to update database statistics: {e}")

        # Update cache statistics metrics
        try:
            await update_cache_stats()
        except Exception as e:
            logger.error(f"Failed to update cache statistics: {e}")

        # Run retention cleanup if interval has passed (fixed 24h interval)
        if (datetime.now(timezone.utc) - last_retention_run) > timedelta(
            hours=HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS
        ):
            await run_housekeeping()
            last_retention_run = datetime.now(timezone.utc)

        # Run branch status sync if interval has passed
        if (datetime.now(timezone.utc) - last_branch_sync) > timedelta(
            hours=HOUSEKEEPING_BRANCH_SYNC_INTERVAL_HOURS
        ):
            await sync_branch_status()
            last_branch_sync = datetime.now(timezone.utc)

        await asyncio.sleep(HOUSEKEEPING_MAIN_LOOP_INTERVAL_SECONDS)
