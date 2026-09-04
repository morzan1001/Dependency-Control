import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional

from pymongo import ReadPreference

from app.core import ensure_utc
from app.core.cache import update_cache_stats
from app.core.config import settings
from app.core.constants import (
    ARCHIVE_BATCH_SIZE,
    ARCHIVE_ORPHAN_MIN_AGE_HOURS,
    HOUSEKEEPING_BRANCH_SYNC_INTERVAL_HOURS,
    HOUSEKEEPING_MAIN_LOOP_INTERVAL_SECONDS,
    HOUSEKEEPING_MAX_SCAN_RETRIES,
    HOUSEKEEPING_RESCAN_LOCK_TTL_SECONDS,
    HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS,
    HOUSEKEEPING_STALE_SCAN_INTERVAL_SECONDS,
    HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS,
    HOUSEKEEPING_UPDATE_FREQUENCY_RECONCILE_HOUR_UTC,
    RETENTION_ACTION_ARCHIVE,
    RETENTION_ACTION_DELETE,
    RETENTION_PROTECTED_FLAG_VALUES,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_PROCESSING,
    SCAN_USABLE_STATUSES,
)
from app.core.metrics import (
    archive_housekeeping_batch_total,
    archive_housekeeping_scans_processed_total,
    update_archive_stats,
    update_db_stats,
)
from app.core.init_db import SCANS_TIP_SORT
from app.core.s3 import delete_object, is_archive_enabled, list_objects
from app.db.mongodb import get_database
from app.models.project import Project, Scan
from app.repositories.scans import ScanRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.services.audit.retention import prune_old_audit_entries
from app.services.compliance.retention import sweep_expired_compliance_reports
from app.services.gridfs_maintenance import cleanup_gridfs_files, extract_gridfs_ids_from_refs, reap_orphan_gridfs_files
from app.services.releases import release_protected_scan_ids
from app.services.update_frequency_reconcile import run_update_frequency_reconcile

if TYPE_CHECKING:
    from app.core.worker import WorkerManager

logger = logging.getLogger(__name__)


async def _referenced_scan_ids(db: Any, scan_ids: list[str]) -> set[str]:
    """Which of these scans a rescan points at (via original_scan_id); retention must not delete those.

    Asked per batch rather than as one estate-wide set: the whole set spliced into the retention
    cursor as ``$nin`` outgrows the 16 MB BSON document limit and the cursor stops opening at all.
    """
    referenced: set[str] = set()
    async for doc in db.scans.find(
        {"is_rescan": True, "original_scan_id": {"$in": scan_ids}},
        {"original_scan_id": 1},
    ):
        original_id = doc.get("original_scan_id")
        if original_id:
            referenced.add(original_id)
    return referenced


async def _collect_gridfs_ids(db: Any, scan_ids: list[str]) -> list[str]:
    """Collect all GridFS IDs referenced by the given scans."""
    gridfs_ids: list[str] = []
    async for scan_doc in db.scans.find({"_id": {"$in": scan_ids}}, {"sbom_refs": 1}):
        gridfs_ids.extend(extract_gridfs_ids_from_refs(scan_doc.get("sbom_refs", [])))
    return gridfs_ids


async def _delete_scans_and_related_data(db: Any, scan_ids: list[str], label: str = "") -> int:
    """Delete scans and all associated data (findings, dependencies, GridFS SBOMs, callgraphs)."""
    if not scan_ids:
        return 0

    gridfs_ids = await _collect_gridfs_ids(db, scan_ids)

    await db.analysis_results.delete_many({"scan_id": {"$in": scan_ids}})
    await db.findings.delete_many({"scan_id": {"$in": scan_ids}})
    await db.finding_records.delete_many({"scan_id": {"$in": scan_ids}})
    await db.dependencies.delete_many({"scan_id": {"$in": scan_ids}})
    await db.callgraphs.delete_many({"scan_id": {"$in": scan_ids}})
    await db.crypto_assets.delete_many({"scan_id": {"$in": scan_ids}})
    # The update-frequency rollups are keyed by scan id, not by a scan_id field.
    await db.scan_update_deltas.delete_many({"_id": {"$in": scan_ids}})
    await db.scan_outdated_sets.delete_many({"_id": {"$in": scan_ids}})
    result = await db.scans.delete_many({"_id": {"$in": scan_ids}})

    await cleanup_gridfs_files(db, gridfs_ids, deleted_scan_ids=scan_ids)

    if label:
        logger.info(f"{label}: Deleted {result.deleted_count} scans ({len(gridfs_ids)} GridFS files).")

    count: int = result.deleted_count
    return count


async def _reap_orphan_callgraphs(db: Any, batch_size: int = ARCHIVE_BATCH_SIZE) -> int:
    """Delete callgraphs whose scan_id matches no scan, once past the orphan safety window.

    Scan deletion already removes callgraphs by scan_id; this covers uploads whose scan never
    existed. The age window protects a callgraph that arrives before its scan is created.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ARCHIVE_ORPHAN_MIN_AGE_HOURS)

    async def _reap_batch(scan_ids: list[str]) -> int:
        candidates = set(scan_ids)
        async for scan in db.scans.find({"_id": {"$in": sorted(candidates)}}, {"_id": 1}):
            candidates.discard(scan.get("_id"))
        if not candidates:
            return 0
        orphaned = sorted(candidates)
        try:
            result = await db.callgraphs.delete_many(
                {"scan_id": {"$in": orphaned}, "created_at": {"$lt": cutoff}},
            )
        except Exception as e:
            logger.warning(f"Failed to delete orphan callgraphs for scans {orphaned}: {e}")
            return 0
        count: int = result.deleted_count
        if count:
            logger.info(f"Reaped {count} orphan callgraph(s) belonging to {len(orphaned)} missing scan(s)")
        return count

    deleted = 0
    batch: list[str] = []
    cursor = db.callgraphs.find(
        {"created_at": {"$lt": cutoff}, "scan_id": {"$ne": None}},
        {"scan_id": 1},
    )
    async for callgraph in cursor:
        scan_id = callgraph.get("scan_id")
        if not scan_id:
            continue
        batch.append(scan_id)
        if len(batch) >= batch_size:
            deleted += await _reap_batch(batch)
            batch = []
    if batch:
        deleted += await _reap_batch(batch)
    return deleted


def _resolve_rescan_interval(project: Project, system_settings: Any) -> int | None:
    """Return effective rescan interval hours, or None if rescans are disabled."""
    enabled = project.rescan_enabled
    if enabled is None:
        enabled = system_settings.global_rescan_enabled
    if not enabled:
        return None

    interval_hours = project.rescan_interval
    if interval_hours is None:
        interval_hours = system_settings.global_rescan_interval

    if not interval_hours or interval_hours <= 0:
        return None
    return interval_hours


def _rescan_clock(source_scan: dict) -> datetime | None:
    """The instant the due decision measures from; a source never rescanned falls back to its own
    creation time."""
    clock: datetime | None = source_scan.get("last_rescanned_at") or source_scan.get("created_at")
    return clock


def _is_rescan_due(source_scan: dict, interval_hours: int) -> bool:
    """Whether this source scan has gone interval_hours without a rescan."""
    last_rescan_aware = ensure_utc(_rescan_clock(source_scan))
    if not last_rescan_aware:
        return False
    next_rescan_due = last_rescan_aware + timedelta(hours=interval_hours)
    return datetime.now(timezone.utc) >= next_rescan_due


def _build_rescan(project: Project, source_scan: dict) -> Scan:
    return Scan(
        project_id=project.id,
        branch=source_scan.get("branch", "unknown"),
        commit_hash=source_scan.get("commit_hash"),
        pipeline_id=None,
        pipeline_iid=source_scan.get("pipeline_iid"),
        project_url=source_scan.get("project_url"),
        pipeline_url=source_scan.get("pipeline_url"),
        job_id=source_scan.get("job_id"),
        job_started_at=source_scan.get("job_started_at"),
        project_name=source_scan.get("project_name"),
        commit_message=source_scan.get("commit_message"),
        commit_tag=source_scan.get("commit_tag"),
        sbom_refs=source_scan.get("sbom_refs", []),
        # Drives the analysis engine's analyzer selection, so the rescan must run under it too.
        scan_type=source_scan.get("scan_type"),
        status="pending",
        created_at=datetime.now(timezone.utc),
        is_rescan=True,
        original_scan_id=str(source_scan["_id"]),
    )


async def _create_rescan_for_project(
    project: Project, source_scan: dict, db: Any, worker_manager: "WorkerManager"
) -> None:
    """Atomically create a rescan after acquiring the distributed lock."""
    import os

    from app.repositories import DistributedLocksRepository

    source_scan_id = str(source_scan["_id"])
    lock_repo = DistributedLocksRepository(db)
    lock_name = f"rescan_create:{project.id}:{source_scan_id}"
    holder_id = f"housekeeping-{os.getenv('HOSTNAME', 'unknown')}"

    if not await lock_repo.acquire_lock(lock_name, holder_id, ttl_seconds=HOUSEKEEPING_RESCAN_LOCK_TTL_SECONDS):
        logger.debug(f"Could not acquire lock for rescanning {project.name}/{source_scan_id}.")
        return

    try:
        # TOCTOU re-check inside lock — strong read. Scoped to this source so unrelated CI
        # traffic on the project cannot cancel a rescan that is genuinely due.
        scans_primary = db.scans.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]
        active_rescan = await scans_primary.find_one(
            {
                "project_id": project.id,
                "original_scan_id": source_scan_id,
                "status": {"$in": [SCAN_STATUS_PENDING, SCAN_STATUS_PROCESSING]},
            }
        )
        if active_rescan:
            logger.debug(f"Project {project.name} already has an active rescan of {source_scan_id}")
            return

        logger.info(
            f"Triggering re-scan for project {project.name} from source scan {source_scan_id} "
            f"(rescan clock: {_rescan_clock(source_scan)})"
        )
        new_scan = _build_rescan(project, source_scan)

        await db.scans.insert_one(new_scan.model_dump(by_alias=True))
        await db.scans.update_one(
            {"_id": source_scan_id},
            {"$set": {"latest_rescan_id": new_scan.id, "last_rescanned_at": datetime.now(timezone.utc)}},
        )
        await worker_manager.add_job(new_scan.id)
        logger.info(f"Rescan {new_scan.id} created for project {project.name}")
    finally:
        await lock_repo.release_lock(lock_name, holder_id)


async def _branch_tip(project: Project, tip_source: dict[str, Any], db: Any) -> dict | None:
    """The newest build that stands for the project's branch tip, resolved the way analytics
    resolves head: the default branch while the VCS still has one, else any branch it has not
    deleted.

    A tag pipeline names its tag as its branch, so it can hold a release slot but never the tip
    slot — otherwise a project that tags every release stops having its default branch
    re-evaluated, and where the tag build is also the release the two targets collapse to one.
    """
    deleted = project.deleted_branches or []
    if project.default_branch and project.default_branch not in deleted:
        on_default: dict | None = await db.scans.find_one(
            {**tip_source, "branch": project.default_branch}, sort=SCANS_TIP_SORT
        )
        if on_default:
            return on_default

    any_branch: dict[str, Any] = {**tip_source, "$expr": {"$ne": ["$branch", "$commit_tag"]}}
    if deleted:
        any_branch["branch"] = {"$nin": deleted}
    tip: dict | None = await db.scans.find_one(any_branch, sort=SCANS_TIP_SORT)
    return tip


async def _rescan_targets(project: Project, db: Any) -> list[dict]:
    """The branch tip plus the newest release per environment. A release is a second identity that
    has to keep being re-evaluated, not just the tip of its branch.

    Every target is an original, never a rescan: rescans are this loop's own output, and taking one
    back in would deepen the lineage chain by a link per interval and hand the tip slot to whichever
    rescan ran last.
    """
    from app.services.releases import released_scan_ids

    usable_source = {
        "project_id": project.id,
        "status": {"$in": SCAN_USABLE_STATUSES},
        "sbom_refs": {"$exists": True, "$ne": []},
    }

    # Tri-state: scans predating the flag carry no is_rescan field and are originals.
    tip_source = {**usable_source, "is_rescan": {"$ne": True}}

    targets: list[dict] = []
    targeted_ids: set[str] = set()

    # BSON dates are milliseconds, so two scans of one project can share a created_at; _id decides
    # between them, or the tip alternates between passes and each alternate falls due immediately.
    tip = await _branch_tip(project, tip_source, db)
    if tip:
        targets.append(tip)
        targeted_ids.add(str(tip["_id"]))

    # The marked scan itself, never its rescan: rescanning the rescan would grow the chain past
    # the bound effective_scan_ids walks.
    for marked_id in (await released_scan_ids(db, project.id)).values():
        marked = await db.scans.find_one({**usable_source, "_id": marked_id})
        if not marked or str(marked["_id"]) in targeted_ids:
            continue
        targets.append(marked)
        targeted_ids.add(str(marked["_id"]))

    return targets


async def _process_project_rescan(
    project_data: dict, system_settings: Any, db: Any, worker_manager: "WorkerManager"
) -> None:
    """Evaluate a single project and create a rescan for every source that is due."""
    project = Project(**project_data)
    interval_hours = _resolve_rescan_interval(project, system_settings)
    if interval_hours is None:
        return

    targets = await _rescan_targets(project, db)
    if not targets:
        # Fires on every main-loop pass for such a project, so it must not be info.
        logger.debug(f"Project {project.name} has no valid previous scan with SBOMs; nothing to re-scan.")
        return

    for source_scan in targets:
        if _is_rescan_due(source_scan, interval_hours):
            await _create_rescan_for_project(project, source_scan, db, worker_manager)


async def check_scheduled_rescans(worker_manager: Optional["WorkerManager"]) -> None:
    """
    Checks for projects that need a periodic re-scan.
    """
    if not worker_manager:
        return

    logger.debug("Checking for scheduled re-scans...")
    try:
        db = await get_database()

        repo = SystemSettingsRepository(db)
        system_settings = await repo.get()

        # Pre-filter to projects that have been scanned at least once.
        async for project_data in db.projects.find({"last_scan_at": {"$ne": None}}):
            try:
                await _process_project_rescan(project_data, system_settings, db, worker_manager)
            except Exception as e:
                logger.exception("Error processing project %s: %s", project_data.get("name"), e)

    except Exception as e:
        logger.exception("Scheduled re-scan check failed: %s", e)


async def _reap_stale_metadata(db: Any, batch_size: int = ARCHIVE_BATCH_SIZE) -> int:
    """Delete archive_metadata entries whose scan_id is back in db.scans (restore leftovers),
    reclassifying their S3 object as an orphan for the next sweep. Batched to avoid N+1 lookups.
    """

    async def _reap_batch(scan_ids: list[str]) -> int:
        if not scan_ids:
            return 0
        restored: list[str] = []
        async for scan in db.scans.find({"_id": {"$in": scan_ids}}, {"_id": 1}):
            sid = scan.get("_id")
            if sid is not None:
                restored.append(sid)
        if not restored:
            return 0
        try:
            result = await db.archive_metadata.delete_many({"scan_id": {"$in": restored}})
            count: int = result.deleted_count
            if count:
                logger.info(f"Reaped {count} stale archive_metadata entries for restored scans {restored}")
            return count
        except Exception as e:
            logger.warning(f"Failed to delete stale metadata for scans {restored}: {e}")
            return 0

    deleted = 0
    batch: list[str] = []
    async for meta in db.archive_metadata.find({}, {"_id": 1, "scan_id": 1}):
        scan_id = meta.get("scan_id")
        if not scan_id:
            continue
        batch.append(scan_id)
        if len(batch) >= batch_size:
            deleted += await _reap_batch(batch)
            batch = []
    if batch:
        deleted += await _reap_batch(batch)
    return deleted


async def _reap_orphan_s3_objects(db: Any) -> int:
    """Delete S3 archive objects that have no matching ``archive_metadata`` record.

    Runs in two passes:
      1. Stale metadata: drop archive_metadata rows whose scan is already in db.scans
         (post-restore leftovers).
      2. S3 orphans: list bucket, skip objects with matching metadata, delete
         the rest if older than ARCHIVE_ORPHAN_MIN_AGE_HOURS.

    Best-effort: errors are logged and swallowed. Returns the number of S3 objects deleted.
    """
    if not is_archive_enabled():
        return 0

    # Pass 1: clean up stale metadata before computing known_keys
    await _reap_stale_metadata(db)

    try:
        all_objects = await list_objects()
    except Exception as e:
        logger.warning(f"Orphan reaper: list_objects failed: {e}")
        return 0

    known_keys: set[str] = set()
    async for meta in db.archive_metadata.find({}, {"s3_key": 1}):
        key = meta.get("s3_key")
        if key:
            known_keys.add(key)

    cutoff = datetime.now(timezone.utc) - timedelta(hours=ARCHIVE_ORPHAN_MIN_AGE_HOURS)
    deleted = 0
    for obj in all_objects:
        key = obj.get("Key")
        last_mod = obj.get("LastModified")
        if not key or key in known_keys:
            continue
        if last_mod and last_mod > cutoff:
            continue
        try:
            await delete_object(key)
            deleted += 1
            archive_housekeeping_scans_processed_total.labels(status="orphan_reaped").inc()
            logger.info(f"Reaped orphan S3 object: {key}")
        except Exception as e:
            logger.warning(f"Failed to delete orphan {key}: {e}")
    return deleted


async def _archive_scans_and_delete(db: Any, scan_ids: list[str], label: str = "") -> int:
    """
    Archive scans to S3, then delete from MongoDB.

    CRITICAL: Archive MUST succeed before deletion.
    Scans that fail to archive are skipped (not deleted).
    """
    if not scan_ids:
        return 0

    from app.services.archive import archive_scan

    archived_count = 0
    failed_ids: list[str] = []

    for scan_id in scan_ids:
        try:
            metadata = await archive_scan(db, scan_id)
            if metadata:
                archived_count += 1
                archive_housekeeping_scans_processed_total.labels(status="archived").inc()
            else:
                failed_ids.append(scan_id)
                archive_housekeeping_scans_processed_total.labels(status="failed").inc()
        except Exception as e:
            logger.exception("Failed to archive scan %s: %s", scan_id, e)
            failed_ids.append(scan_id)
            archive_housekeeping_scans_processed_total.labels(status="failed").inc()

    if failed_ids:
        logger.warning(f"{label}: {len(failed_ids)} scan(s) failed to archive and will NOT be deleted.")
        archive_housekeeping_batch_total.labels(status="partial_failure").inc()
    else:
        archive_housekeeping_batch_total.labels(status="success").inc()

    successfully_archived = [sid for sid in scan_ids if sid not in failed_ids]

    deleted = await _delete_scans_and_related_data(db, successfully_archived, label)

    if label:
        logger.info(f"{label}: Archived {archived_count} scans, deleted {deleted} from MongoDB.")

    return archived_count


async def _handle_retention_action(db: Any, scan_ids: list[str], action: str, label: str) -> None:
    """Route retention to delete or archive based on the configured action."""
    if not scan_ids:
        return

    if action == RETENTION_ACTION_ARCHIVE and is_archive_enabled():
        await _archive_scans_and_delete(db, scan_ids, label)
    elif action == RETENTION_ACTION_DELETE:
        await _delete_scans_and_related_data(db, scan_ids, label)
    elif action == RETENTION_ACTION_ARCHIVE:
        logger.warning(
            f"{label}: Retention action is 'archive' but S3 is not configured. "
            "Skipping cleanup. Configure S3 or change retention action to 'delete'."
        )


async def _unreferenced(db: Any, scan_ids: list[str]) -> list[str]:
    """The batch minus every scan something still points at: a rescan's source, and either end of a
    release's analysis chain."""
    protected = await _referenced_scan_ids(db, scan_ids)
    protected |= await release_protected_scan_ids(db, scan_ids)
    return [scan_id for scan_id in scan_ids if scan_id not in protected]


async def _process_scans_in_batches(
    db: Any, cursor: Any, action: str, label: str, batch_size: int = ARCHIVE_BATCH_SIZE
) -> None:
    """Stream scan IDs from cursor and process retention in batches, dropping the ones a rescan
    still points at."""
    batch: list[str] = []
    async for doc in cursor:
        batch.append(str(doc["_id"]))
        if len(batch) >= batch_size:
            await _handle_retention_action(db, await _unreferenced(db, batch), action, label)
            batch = []
    if batch:
        await _handle_retention_action(db, await _unreferenced(db, batch), action, label)


async def run_housekeeping() -> None:
    """
    Periodically cleans up old scan data based on project retention settings.
    Supports two actions: 'delete' (permanent removal) and 'archive' (move to S3).
    """
    logger.info("Starting housekeeping task...")

    try:
        db = await get_database()

        repo = SystemSettingsRepository(db)
        system_settings = await repo.get()

        if system_settings.retention_mode == "global":
            retention_days = system_settings.global_retention_days
            retention_action = system_settings.global_retention_action

            if retention_days > 0 and retention_action != "none":
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
                logger.info(
                    f"Running global housekeeping (action={retention_action}). "
                    f"Processing scans older than {cutoff_date}"
                )

                cursor = db.scans.find(
                    {
                        "created_at": {"$lt": cutoff_date},
                        "pinned": {"$nin": RETENTION_PROTECTED_FLAG_VALUES},
                        # Keeps flagged releases out of the candidate stream; the exemption that
                        # decides is _unreferenced, which reads db.releases rather than this flag.
                        "is_release": {"$nin": RETENTION_PROTECTED_FLAG_VALUES},
                        "status": {"$nin": ["pending", "processing"]},
                    },
                    {"_id": 1},
                )

                await _process_scans_in_batches(db, cursor, retention_action, "Global housekeeping")

        else:
            logger.info("Running project-specific housekeeping...")

            # Group projects by (retention_days, retention_action) to minimize DB queries
            pipeline: list[dict[str, Any]] = [
                {
                    "$match": {
                        "retention_days": {"$gt": 0},
                        "$or": [
                            {"retention_action": {"$exists": False}},
                            {"retention_action": {"$ne": "none"}},
                        ],
                    }
                },
                {
                    "$group": {
                        "_id": {
                            "days": "$retention_days",
                            "action": {"$ifNull": ["$retention_action", "delete"]},
                        },
                        "project_ids": {"$push": "$_id"},
                    }
                },
            ]

            async for group in db.projects.aggregate(pipeline):
                days = group["_id"]["days"]
                action = group["_id"]["action"]
                project_ids = group["project_ids"]

                if not days or days <= 0:
                    continue

                cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

                cursor = db.scans.find(
                    {
                        "project_id": {"$in": project_ids},
                        "created_at": {"$lt": cutoff_date},
                        "pinned": {"$nin": RETENTION_PROTECTED_FLAG_VALUES},
                        "is_release": {"$nin": RETENTION_PROTECTED_FLAG_VALUES},
                        "status": {"$nin": ["pending", "processing"]},
                    },
                    {"_id": 1},
                )

                label = f"Retention {days}d/{action} ({len(project_ids)} projects)"
                await _process_scans_in_batches(db, cursor, action, label)

        try:
            await prune_old_audit_entries(db)
        except Exception as e:
            logger.exception("Housekeeping: policy audit retention failed: %s", e)

        try:
            await sweep_expired_compliance_reports(db)
        except Exception as e:
            logger.exception("Housekeeping: compliance report sweep failed: %s", e)

        # Orphan-reaper: delete S3 archive objects with no matching metadata
        try:
            await _reap_orphan_s3_objects(db)
        except Exception as e:
            logger.exception("Orphan reaper failed: %s", e)

        try:
            await reap_orphan_gridfs_files(db)
        except Exception as e:
            logger.exception("GridFS orphan reaper failed: %s", e)

        try:
            await _reap_orphan_callgraphs(db)
        except Exception as e:
            logger.exception("Callgraph orphan reaper failed: %s", e)

    except Exception as e:
        logger.exception("Housekeeping task failed: %s", e)


async def trigger_stale_pending_scans(
    worker_manager: Optional["WorkerManager"] = None,
) -> None:
    """Trigger aggregation for 'pending' scans that have results but have gone stale.

    Covers the case where only findings-based scanners (TruffleHog, OpenGrep, etc.) ran
    without an SBOM scan, or where the SBOM scanner failed to trigger.
    """
    if not worker_manager:
        return

    logger.debug("Checking for stale pending scans...")
    try:
        db = await get_database()

        stale_threshold = datetime.now(timezone.utc) - timedelta(seconds=HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS)

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
        logger.exception("Stale pending scan check failed: %s", e)


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
        timeout_threshold = datetime.now(timezone.utc) - timedelta(
            seconds=settings.HOUSEKEEPING_STUCK_SCAN_TIMEOUT_SECONDS
        )
        max_retries = HOUSEKEEPING_MAX_SCAN_RETRIES

        # Strong read: avoid resetting scans whose "completed" hasn't replicated yet.
        scans_primary = db.scans.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]
        cursor = scans_primary.find(
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
        logger.exception("Stuck scan recovery failed: %s", e)


async def _fetch_gitlab_branches(db: Any, instance_id: str, project_id: str) -> list | None:
    from app.repositories.gitlab_instances import GitLabInstanceRepository
    from app.services.gitlab import GitLabService

    instance = await GitLabInstanceRepository(db).get_by_id(instance_id)
    if not instance or not instance.access_token:
        return None
    try:
        numeric_project_id = int(project_id)
    except (TypeError, ValueError):
        return None
    return await GitLabService(instance).list_branches(numeric_project_id)


async def _fetch_github_branches(db: Any, instance_id: str, repo_path: str) -> list | None:
    from app.repositories.github_instances import GitHubInstanceRepository
    from app.services.github import GitHubService

    gh_instance = await GitHubInstanceRepository(db).get_by_id(instance_id)
    if not gh_instance or not gh_instance.access_token:
        return None
    parts = repo_path.split("/", 1)
    if len(parts) != 2:
        return None
    return await GitHubService(gh_instance).list_branches(parts[0], parts[1])


async def _fetch_vcs_branches(project_data: dict, db: Any) -> list | None:
    """Resolve the VCS provider and return its branch list, or None if unavailable."""
    gitlab_instance_id = project_data.get("gitlab_instance_id")
    gitlab_project_id = project_data.get("gitlab_project_id")
    if gitlab_instance_id and gitlab_project_id:
        return await _fetch_gitlab_branches(db, gitlab_instance_id, gitlab_project_id)

    github_instance_id = project_data.get("github_instance_id")
    github_repo_path = project_data.get("github_repository_path")
    if github_instance_id and github_repo_path:
        return await _fetch_github_branches(db, github_instance_id, github_repo_path)

    return None


async def _fetch_vcs_default_branch(project_data: dict, db: Any) -> str | None:
    """The provider's default branch, so project views need not guess one from scan recency."""
    from app.repositories.github_instances import GitHubInstanceRepository
    from app.repositories.gitlab_instances import GitLabInstanceRepository
    from app.services.github import GitHubService
    from app.services.gitlab import GitLabService

    gitlab_instance_id = project_data.get("gitlab_instance_id")
    gitlab_project_id = project_data.get("gitlab_project_id")
    if gitlab_instance_id and gitlab_project_id:
        instance = await GitLabInstanceRepository(db).get_by_id(gitlab_instance_id)
        if not instance or not instance.access_token:
            return None
        try:
            numeric_project_id = int(gitlab_project_id)
        except (TypeError, ValueError):
            return None
        details = await GitLabService(instance).get_project_details(numeric_project_id)
        return details.default_branch if details else None

    github_instance_id = project_data.get("github_instance_id")
    github_repo_path = project_data.get("github_repository_path")
    if github_instance_id and github_repo_path:
        gh_instance = await GitHubInstanceRepository(db).get_by_id(github_instance_id)
        if not gh_instance or not gh_instance.access_token:
            return None
        parts = github_repo_path.split("/", 1)
        if len(parts) != 2:
            return None
        return await GitHubService(gh_instance).get_default_branch(parts[0], parts[1])

    return None


async def _resolve_latest_scan_after_branch_deletion(
    project_data: dict, deleted: list, db: Any, project_name: str
) -> dict:
    """If the project's latest scan is on a deleted branch, find a replacement.

    Returns a dict of update fields (may be empty).
    """
    current_scan_id = project_data.get("latest_scan_id")
    if not current_scan_id:
        return {}
    scan_doc = await db.scans.find_one({"_id": current_scan_id}, {"branch": 1})
    if not scan_doc or scan_doc.get("branch") not in deleted:
        return {}

    # Delegate the "latest scan on a non-deleted branch" selection to the
    # canonical ScanRepository method (single source of truth). ``deleted`` is
    # the freshly-computed deleted-branch set, not yet persisted on the project.
    active_scan = await ScanRepository(db).get_latest_active_scan(project_data, deleted_branches=deleted)
    if active_scan:
        updates: dict = {
            "latest_scan_id": active_scan.id,
            "last_scan_at": ensure_utc(active_scan.created_at),
        }
        if active_scan.stats:
            updates["stats"] = active_scan.stats.model_dump()
        logger.info(f"Project {project_name}: updated latest_scan_id to active branch '{active_scan.branch}'")
        return updates

    logger.info(f"Project {project_name}: no active branch scans, cleared stats")
    return {"latest_scan_id": None, "stats": None}


async def sync_project_branches(project_data: dict, db: Any) -> None:
    """Sync branch status for a single project against its VCS provider."""
    project_id = project_data["_id"]
    project_name = project_data.get("name", project_id)

    try:
        vcs_branches = await _fetch_vcs_branches(project_data, db)
        if not vcs_branches:
            return

        # A scan whose branch is its own commit tag came off a tag pipeline and names no branch,
        # so counting it would file the tag as a branch the VCS has deleted.
        our_branches = await db.scans.distinct(
            "branch", {"project_id": project_id, "$expr": {"$ne": ["$branch", "$commit_tag"]}}
        )
        vcs_set = set(vcs_branches)
        deleted = sorted(b for b in our_branches if b not in vcs_set)

        update_fields: dict = {
            "deleted_branches": deleted,
            "branches_checked_at": datetime.now(timezone.utc),
        }

        if not project_data.get("default_branch"):
            vcs_default = await _fetch_vcs_default_branch(project_data, db)
            if vcs_default:
                update_fields["default_branch"] = vcs_default

        if deleted:
            update_fields.update(
                await _resolve_latest_scan_after_branch_deletion(project_data, deleted, db, project_name)
            )

        await db.projects.update_one({"_id": project_id}, {"$set": update_fields})

        if deleted:
            logger.info(f"Project {project_name}: {len(deleted)} deleted branch(es) detected")

    except Exception as e:
        logger.exception("Branch sync failed for project %s: %s", project_name, e)


async def sync_branch_status() -> None:
    """Sync branch status for all projects with VCS connections."""
    logger.info("Starting branch status sync...")
    try:
        db = await get_database()

        branch_sync_projection = {
            "_id": 1,
            "name": 1,
            "latest_scan_id": 1,
            "default_branch": 1,
            "gitlab_instance_id": 1,
            "gitlab_project_id": 1,
            "github_instance_id": 1,
            "github_repository_path": 1,
        }
        cursor = db.projects.find(
            {
                "$or": [
                    {"gitlab_instance_id": {"$exists": True, "$ne": None}},
                    {"github_instance_id": {"$exists": True, "$ne": None}},
                ]
            },
            branch_sync_projection,
        )

        count = 0
        async for project_data in cursor:
            await sync_project_branches(project_data, db)
            count += 1

        logger.info(f"Branch status sync completed for {count} project(s)")
    except Exception as e:
        logger.exception("Branch status sync failed: %s", e)


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
            logger.exception("Stale scan loop failed: %s", e)

        await asyncio.sleep(HOUSEKEEPING_STALE_SCAN_INTERVAL_SECONDS)


def _reconcile_due(now: datetime, last_run: datetime) -> bool:
    """Once per calendar day, and only inside the quiet hour.

    An elapsed-time gate would anchor the run to whenever the pod that wins the lock was
    rolled out, so a midday deploy would put a run that re-reads a dependency set per
    repaired scan straight into the working day.
    """
    return now.hour == HOUSEKEEPING_UPDATE_FREQUENCY_RECONCILE_HOUR_UTC and last_run.date() < now.date()


async def reconcile_update_frequency_ledger() -> None:
    """Check the update-frequency delta ledger against the scans and repair what drifted."""
    if not settings.UPDATE_FREQUENCY_RECONCILE_ENABLED:
        return
    try:
        db = await get_database()
        await run_update_frequency_reconcile(db)
    except Exception as e:
        logger.exception("Update-frequency reconcile failed: %s", e)


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
    - Update-frequency ledger reconcile: Once a night, behind its own flag

    Note: Stale pending scan aggregation runs in a separate faster loop.
    """
    last_retention_run = datetime.min.replace(tzinfo=timezone.utc)
    last_branch_sync = datetime.min.replace(tzinfo=timezone.utc)
    last_update_frequency_reconcile = datetime.min.replace(tzinfo=timezone.utc)

    while True:
        await recover_stuck_scans(worker_manager)
        await check_scheduled_rescans(worker_manager)

        try:
            db = await get_database()
            await update_db_stats(db)
        except Exception as e:
            logger.exception("Failed to update database statistics: %s", e)

        try:
            db = await get_database()
            await update_archive_stats(db)
        except Exception as e:
            logger.exception("Failed to update archive statistics: %s", e)

        try:
            await update_cache_stats()
        except Exception as e:
            logger.exception("Failed to update cache statistics: %s", e)

        if (datetime.now(timezone.utc) - last_retention_run) > timedelta(
            hours=HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS
        ):
            await run_housekeeping()
            last_retention_run = datetime.now(timezone.utc)

        if (datetime.now(timezone.utc) - last_branch_sync) > timedelta(hours=HOUSEKEEPING_BRANCH_SYNC_INTERVAL_HOURS):
            await sync_branch_status()
            last_branch_sync = datetime.now(timezone.utc)

        # Stamped whatever the reconcile did: only one pod gets the lock, and the others
        # must not come back for it every five minutes.
        now = datetime.now(timezone.utc)
        if _reconcile_due(now, last_update_frequency_reconcile):
            await reconcile_update_frequency_ledger()
            last_update_frequency_reconcile = now

        await asyncio.sleep(HOUSEKEEPING_MAIN_LOOP_INTERVAL_SECONDS)
