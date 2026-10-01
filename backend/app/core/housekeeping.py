import asyncio
import logging
from collections import Counter
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from functools import partial
from itertools import batched
from typing import TYPE_CHECKING, Any, Optional


from app.core import abatched
from app.core.cache import update_cache_stats
from app.core.config import settings
from app.core.constants import (
    ARCHIVE_BATCH_SIZE,
    ARCHIVE_ORPHAN_MIN_AGE_HOURS,
    ARCHIVE_RESTORE_LOCK_TEMPLATE,
    HOUSEKEEPING_BRANCH_SYNC_INTERVAL_HOURS,
    HOUSEKEEPING_MAIN_LOOP_INTERVAL_SECONDS,
    HOUSEKEEPING_MAX_SCAN_RETRIES,
    HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS,
    HOUSEKEEPING_STALE_SCAN_INTERVAL_SECONDS,
    HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS,
    HOUSEKEEPING_UPDATE_FREQUENCY_RECONCILE_HOUR_UTC,
    RESCAN_HISTORY_RUNS,
    RETENTION_ACTIONS,
    RETENTION_ACTION_ARCHIVE,
    RETENTION_ACTION_DELETE,
    RETENTION_ACTION_NONE,
    RETENTION_PROTECTED_FLAG_VALUES,
    SCAN_ACTIVE_STATUSES,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_PROCESSING,
    SCAN_USABLE_STATUSES,
    SCANS_TIP_SORT,
    SETTINGS_MODE_GLOBAL,
)
from app.core.metrics import (
    archive_housekeeping_batch_total,
    archive_housekeeping_scans_processed_total,
    update_archive_stats,
    update_db_stats,
)
from app.core.s3 import delete_object, is_archive_enabled, list_objects
from app.db.mongodb import get_database
from app.models.project import Project
from app.repositories.distributed_locks import DistributedLocksRepository, LockLost, new_lock_holder, run_holding_lock
from app.repositories.scans import HAS_SBOM_MATCH, USABLE_BUILD_MATCH, ScanRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.services.analysis.notifications import notify_analysis_failed
from app.services.audit.retention import prune_old_audit_entries
from app.services.branch_sync import sync_project_branches
from app.services.compliance.retention import sweep_expired_compliance_reports
from app.services.gridfs_maintenance import reap_orphan_gridfs_files
from app.services.releases import reconcile_release_flags, release_protected_scan_ids
from app.services.rescan import RESCAN_SOURCE_PROJECTION, create_rescan
from app.services.scan_cascade import delete_scans_and_related_data
from app.services.stats import run_waiver_recalc
from app.services.update_frequency_reconcile import run_update_frequency_reconcile

if TYPE_CHECKING:
    from app.core.worker import WorkerManager

logger = logging.getLogger(__name__)

_RETENTION_LOCK_NAME = "retention"
_RETENTION_LOCK_TTL_SECONDS = 600
_EXPIRABLE = {"pinned": {"$nin": RETENTION_PROTECTED_FLAG_VALUES}, "status": {"$nin": SCAN_ACTIVE_STATUSES}}


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

    cursor = db.callgraphs.find({"created_at": {"$lt": cutoff}, "scan_id": {"$ne": None}}, {"scan_id": 1})
    scan_ids = (callgraph["scan_id"] async for callgraph in cursor if callgraph.get("scan_id"))
    return sum([await _reap_batch(batch) async for batch in abatched(scan_ids, batch_size)])


_RESCAN_PROJECT_PROJECTION = dict.fromkeys(
    ("_id", "name", "default_branch", "deleted_branches", "rescan_enabled", "rescan_interval"), 1
)


def resolve_rescan_interval(project: Project, system_settings: Any) -> int | None:
    """Return effective rescan interval hours, or None if rescans are disabled."""
    project_decides = system_settings.rescan_mode != SETTINGS_MODE_GLOBAL
    enabled = project.rescan_enabled if project_decides else None
    if enabled is None:
        enabled = system_settings.global_rescan_enabled
    if not enabled:
        return None

    interval_hours = project.rescan_interval if project_decides else None
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
    last_rescan = _rescan_clock(source_scan)
    if not last_rescan:
        return False
    next_rescan_due = last_rescan + timedelta(hours=interval_hours)
    return datetime.now(timezone.utc) >= next_rescan_due


async def _rescan_targets(project: Project, db: Any) -> list[dict]:
    """The branch tip plus the newest release per environment. A release is a second identity that
    has to keep being re-evaluated, not just the tip of its branch.

    Every target is an original, never a rescan: rescans are this loop's own output, and taking one
    back in would deepen the lineage chain by a link per interval and hand the tip slot to whichever
    rescan ran last.
    """
    from app.services.releases import released_scan_ids

    # Head's own tip build, so the rescan refreshes the analysis head reports; the lineage step is
    # left out because a rescan target has to be the build, not the previous interval's output.
    tip = await ScanRepository(db).head_build(
        project, {**HAS_SBOM_MATCH, **USABLE_BUILD_MATCH}, RESCAN_SOURCE_PROJECTION
    )
    targets = [tip] if tip else []

    # The marked scan itself, never its rescan: rescanning the rescan would grow the chain past
    # the bound effective_scan_ids walks. A failed one is retried, as nothing else analyses it.
    marked_ids = set((await released_scan_ids(db, project.id)).values()) - {target["_id"] for target in targets}
    if marked_ids:
        marked = db.scans.find(
            {
                "project_id": project.id,
                "_id": {"$in": sorted(marked_ids)},
                "status": {"$nin": [SCAN_STATUS_PENDING, SCAN_STATUS_PROCESSING]},
                **HAS_SBOM_MATCH,
            },
            RESCAN_SOURCE_PROJECTION,
        )
        targets.extend(await marked.to_list(None))
    return targets


async def _process_project_rescan(
    project_data: dict, system_settings: Any, db: Any, worker_manager: "WorkerManager"
) -> None:
    """Evaluate a single project and create a rescan for every source that is due."""
    project = Project(**project_data)
    interval_hours = resolve_rescan_interval(project, system_settings)
    if interval_hours is None:
        return

    targets = await _rescan_targets(project, db)
    if not targets:
        # Fires on every main-loop pass for such a project, so it must not be info.
        logger.debug(f"Project {project.name} has no valid previous scan with SBOMs; nothing to re-scan.")
        return

    for source_scan in targets:
        if _is_rescan_due(source_scan, interval_hours) and not worker_manager.is_saturated():
            logger.info(f"Re-scan due for project {project.name} from source scan {source_scan['_id']}")
            await create_rescan(db, source_scan, worker_manager)


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
        async for project_data in db.projects.find({"last_scan_at": {"$ne": None}}, _RESCAN_PROJECT_PROJECTION):
            # The due targets left over stay due, so a later pass, in whichever process has room, takes them.
            if worker_manager.is_saturated():
                break
            try:
                await _process_project_rescan(project_data, system_settings, db, worker_manager)
            except Exception as e:
                logger.exception("Error processing project %s: %s", project_data.get("name"), e)

    except Exception as e:
        logger.exception("Scheduled re-scan check failed: %s", e)


async def _reap_stale_metadata(db: Any, batch_size: int = ARCHIVE_BATCH_SIZE) -> int:
    """Delete archive_metadata rows of scans whose restore completed after they were archived, reclassifying
    their S3 object as an orphan for the next sweep. Batched to avoid N+1 lookups.
    """
    lock_repo = DistributedLocksRepository(db)

    async def _reap_batch(metas: list[dict[str, Any]]) -> int:
        restored_at_by_scan = {
            scan["_id"]: scan["restored_at"]
            async for scan in db.scans.find(
                {
                    "_id": {"$in": [meta["scan_id"] for meta in metas]},
                    "restored_at": {"$ne": None},
                    "restore_in_progress": {"$ne": True},
                },
                {"restored_at": 1},
            )
        }
        restored = [
            meta
            for meta in metas
            if meta["scan_id"] in restored_at_by_scan and restored_at_by_scan[meta["scan_id"]] > meta["archived_at"]
        ]
        if not restored:
            return 0
        # Scans first: a restore holds its lock from before it inserts the scan until after a rollback removes it.
        lock_names = {
            meta["scan_id"]: ARCHIVE_RESTORE_LOCK_TEMPLATE.format(scan_id=meta["scan_id"]) for meta in restored
        }
        held = await lock_repo.held_locks(list(lock_names.values()))
        stale = [meta for meta in restored if lock_names[meta["scan_id"]] not in held]
        if not stale:
            return 0
        stale_scan_ids = [meta["scan_id"] for meta in stale]
        try:
            result = await db.archive_metadata.delete_many({"_id": {"$in": [meta["_id"] for meta in stale]}})
            count: int = result.deleted_count
            if count:
                logger.info(f"Reaped {count} stale archive_metadata entries for restored scans {stale_scan_ids}")
            return count
        except Exception as e:
            logger.warning(f"Failed to delete stale metadata for scans {stale_scan_ids}: {e}")
            return 0

    cursor = db.archive_metadata.find({}, {"_id": 1, "scan_id": 1, "archived_at": 1})
    metas = (meta async for meta in cursor if meta.get("scan_id"))
    return sum([await _reap_batch(batch) async for batch in abatched(metas, batch_size)])


async def _reap_orphan_s3_objects(db: Any) -> int:
    """Delete S3 archive objects that have no matching ``archive_metadata`` record, returning how
    many were deleted. Best-effort: errors are logged and swallowed.
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


async def _delete_expirable(db: Any, scans: dict[str, Any], label: str) -> int:
    """Delete the scans a pin, a release or a new run has not taken out of retention since it picked them."""
    expirable = await db.scans.distinct("_id", {**scans, **_EXPIRABLE})
    released = await release_protected_scan_ids(db, expirable)
    return await delete_scans_and_related_data(db, [sid for sid in expirable if sid not in released], label)


async def _archive_scans_and_delete(db: Any, scan_ids: list[str], label: str = "") -> int:
    """Archive scans to S3, then delete those archived, unchanged since picked and still expirable."""
    if not scan_ids:
        return 0

    from app.services.archive import archive_scan

    picked_at = datetime.now(timezone.utc)
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

    archived = {"$in": scan_ids, "$nin": failed_ids}
    # A scan written to since its archive began holds data its bundle lacks.
    deleted = await _delete_expirable(db, {"_id": archived, "$nor": [{"updated_at": {"$gt": picked_at}}]}, label)
    # Archive anew a kept scan its new bundle predates; a runner that trusted that bundle saw no later write.
    kept = {"_id": archived, "created_at": {"$lt": picked_at}, "updated_at": {"$gt": picked_at}}
    async for scan in db.scans.find(kept, {"updated_at": 1}):
        stale = {"$gte": picked_at, "$lt": scan["updated_at"]}
        await db.archive_metadata.delete_one({"scan_id": scan["_id"], "archived_at": stale})

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
        await _delete_expirable(db, {"_id": {"$in": scan_ids}}, label)
    elif action == RETENTION_ACTION_ARCHIVE:
        logger.warning(
            f"{label}: Retention action is 'archive' but S3 is not configured. "
            "Skipping cleanup. Configure S3 or change retention action to 'delete'."
        )
    elif action != RETENTION_ACTION_NONE:
        # A value stored before the request schemas constrained it. Without this the scans would
        # simply never expire, and disk growth would be the only signal.
        logger.warning(
            f"{label}: Unknown retention action {action!r}; expected one of {RETENTION_ACTIONS}. "
            f"{len(scan_ids)} scans past their retention window were left in place."
        )


async def _project_heads(db: Any, project_ids: set[str]) -> set[str]:
    projects = await db.projects.find(
        {"_id": {"$in": sorted(project_ids)}}, {"latest_scan_id": 1, "default_branch": 1, "deleted_branches": 1}
    ).to_list(None)
    return set((await ScanRepository(db).get_latest_active_scan_ids(projects)).values())


async def _unreferenced(db: Any, scans: list[dict[str, Any]]) -> list[str]:
    """The batch minus every scan something still points at: a rescan's source, either end of a
    release's analysis chain, and a project's head, which otherwise passes to an older or feature build."""
    scan_ids = [str(doc["_id"]) for doc in scans]
    protected = await _referenced_scan_ids(db, scan_ids)
    protected |= await release_protected_scan_ids(db, scan_ids)
    protected |= await _project_heads(db, {doc["project_id"] for doc in scans if doc.get("project_id")})
    return [scan_id for scan_id in scan_ids if scan_id not in protected]


async def _process_scans_in_batches(
    db: Any, cursor: Any, action: str, label: str, batch_size: int = ARCHIVE_BATCH_SIZE
) -> None:
    async for batch in abatched(cursor, batch_size):
        await _handle_retention_action(db, await _unreferenced(db, batch), action, label)


async def _superseded_rescans(db: Any, scope: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
    """Each build's rescans older than its newest RESCAN_HISTORY_RUNS usable ones, except the one its
    latest_rescan_id names."""
    # Keyed on original_scan_id so its index, not a pass over every build, finds the rescans.
    runs = {**scope, "original_scan_id": {"$ne": None}, **_EXPIRABLE}
    # Read up front: a cursor would sit idle past the session timeout while the batches archive.
    crowded = await db.scans.aggregate(
        [
            {"$match": runs},
            {"$group": {"_id": "$original_scan_id", "runs": {"$sum": 1}}},
            {"$match": {"runs": {"$gt": RESCAN_HISTORY_RUNS}}},
        ]
    ).to_list(None)
    for groups in batched(crowded, ARCHIVE_BATCH_SIZE, strict=False):
        roots = [group["_id"] for group in groups]
        current = set(await db.scans.distinct("latest_rescan_id", {"_id": {"$in": roots}}))
        usable_kept: Counter[str] = Counter()
        group_runs = db.scans.find(
            {**runs, "original_scan_id": {"$in": roots}}, {"project_id": 1, "original_scan_id": 1, "status": 1}
        )
        for run in await group_runs.sort(SCANS_TIP_SORT).to_list(None):
            root = run["original_scan_id"]
            if usable_kept[root] < RESCAN_HISTORY_RUNS:
                usable_kept[root] += run.get("status") in SCAN_USABLE_STATUSES
            elif run["_id"] not in current:
                yield run


async def _expire_group(db: Any, days: int, scope: dict[str, Any], action: str, label: str) -> None:
    """Retention for one group: scans past its age and rescans past the history cap. A stored retention no
    cutoff can be computed for fails only its own group."""
    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        cursor = db.scans.find({**scope, "created_at": {"$lt": cutoff_date}, **_EXPIRABLE}, {"_id": 1, "project_id": 1})
        await _process_scans_in_batches(db, cursor, action, label)
        await _process_scans_in_batches(db, _superseded_rescans(db, scope), action, f"{label} rescan history")
    except Exception:
        logger.exception("Housekeeping: %s failed", label)


async def _run_retention(db: Any) -> None:
    """Expire scans on one pod per interval; a run cut short frees the lock for the next pod's pass."""
    locks = DistributedLocksRepository(db)
    holder = new_lock_holder()
    if not await locks.acquire_lock(_RETENTION_LOCK_NAME, holder, ttl_seconds=_RETENTION_LOCK_TTL_SECONDS):
        return
    renew = partial(locks.renew_lock, _RETENTION_LOCK_NAME, holder, _RETENTION_LOCK_TTL_SECONDS)
    try:
        await run_holding_lock(renew, _RETENTION_LOCK_TTL_SECONDS, _expire_scans(db))
    except LockLost:
        logger.error("Retention stopped: another pod took its lock over")
    except BaseException:
        await locks.release_lock(_RETENTION_LOCK_NAME, holder)
        raise
    else:
        await locks.renew_lock(_RETENTION_LOCK_NAME, holder, HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS * 3600)


async def _expire_scans(db: Any) -> None:
    system_settings = await SystemSettingsRepository(db).get()

    if system_settings.retention_mode == SETTINGS_MODE_GLOBAL:
        retention_days = system_settings.global_retention_days
        retention_action = system_settings.global_retention_action
        if retention_days > 0 and retention_action != RETENTION_ACTION_NONE:
            logger.info(f"Running global housekeeping (action={retention_action}, older than {retention_days} days)")
            await _expire_group(db, retention_days, {}, retention_action, "Global housekeeping")
        return

    logger.info("Running project-specific housekeeping...")

    # Group projects by (retention_days, retention_action) to minimize DB queries
    pipeline: list[dict[str, Any]] = [
        {
            "$match": {
                "retention_days": {"$gt": 0},
                "retention_action": {"$ne": RETENTION_ACTION_NONE},
            }
        },
        {
            "$group": {
                "_id": {
                    "days": "$retention_days",
                    "action": {"$ifNull": ["$retention_action", RETENTION_ACTION_DELETE]},
                },
                "project_ids": {"$push": "$_id"},
            }
        },
    ]

    async for group in db.projects.aggregate(pipeline):
        days = group["_id"]["days"]
        action = group["_id"]["action"]
        project_ids = group["project_ids"]
        label = f"Retention {days}d/{action} ({len(project_ids)} projects)"
        await _expire_group(db, days, {"project_id": {"$in": project_ids}}, action, label)


async def run_housekeeping() -> None:
    """Each pod's daily sweep: release flags, audit and compliance report retention, and the orphan reapers."""
    logger.info("Starting housekeeping task...")

    try:
        db = await get_database()

        try:
            await reconcile_release_flags(db)
        except Exception as e:
            logger.exception("Housekeeping: release flag reconcile failed: %s", e)

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
            await _reap_orphan_callgraphs(db)
        except Exception as e:
            logger.exception("Callgraph orphan reaper failed: %s", e)

        try:
            await reap_orphan_gridfs_files(db)
        except Exception as e:
            logger.exception("GridFS orphan reaper failed: %s", e)

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
                "status": SCAN_STATUS_PENDING,
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


async def requeue_waiting_adhoc_jobs(worker_manager: Optional["WorkerManager"] = None) -> None:
    """Queue again the oldest pending ad-hoc jobs whose queue entry died with its pod."""
    if not worker_manager or worker_manager.is_saturated():
        return
    db = await get_database()
    waiting_since = datetime.now(timezone.utc) - timedelta(seconds=HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS)
    cursor = (
        db.adhoc_jobs.find({"status": SCAN_STATUS_PENDING, "created_at": {"$lt": waiting_since}}, {"_id": 1})
        .sort("created_at", 1)
        .limit(worker_manager.num_workers)
    )
    async for job in cursor:
        await worker_manager.add_adhoc_job(job["_id"])


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
        scan_repo = ScanRepository(db)

        cursor = db.scans.find(
            {
                "status": SCAN_STATUS_PROCESSING,
                "$or": [
                    {"analysis_started_at": {"$lt": timeout_threshold}},
                    {"analysis_started_at": {"$exists": False}},
                    {"analysis_started_at": None},
                ],
            }
        )

        async for scan in cursor:
            scan_id = scan["_id"]
            retry_count = scan.get("stuck_retry_count", 0)

            if retry_count < max_retries:
                logger.warning(
                    f"Scan {scan_id} stuck in processing. Resetting to pending (Retry {retry_count + 1}/{max_retries})."
                )
                requeued = await scan_repo.requeue(scan_id, scan.get("worker_id"), counter="stuck_retry_count")
                if requeued and worker_manager:
                    await worker_manager.add_job(str(scan_id))

            else:
                logger.error(f"Scan {scan_id} failed after {max_retries} retries.")
                error = "Analysis timed out or worker crashed multiple times."
                # Every pod runs this loop; only the one whose write lands announces the failure.
                if await scan_repo.mark_failed(scan_id, error, worker_id=scan.get("worker_id")):
                    await notify_analysis_failed(db, scan_id, scan.get("project_id"), error)

    except Exception as e:
        logger.exception("Stuck scan recovery failed: %s", e)


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
            try:
                await sync_project_branches(project_data, db)
            except Exception as e:
                logger.exception("Branch sync failed for project %s: %s", project_data.get("name"), e)
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
            await requeue_waiting_adhoc_jobs(worker_manager)
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
    """Runs the housekeeping tasks on a loop; stale pending scan aggregation runs in its own,
    faster loop.
    """
    last_housekeeping_run = datetime.min.replace(tzinfo=timezone.utc)
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

        try:
            await run_waiver_recalc(await get_database())
        except Exception as e:
            logger.exception("Waiver recalculation failed: %s", e)

        if (datetime.now(timezone.utc) - last_housekeeping_run) > timedelta(
            hours=HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS
        ):
            await run_housekeeping()
            last_housekeeping_run = datetime.now(timezone.utc)

        try:
            await _run_retention(await get_database())
        except Exception as e:
            logger.exception("Housekeeping: retention failed: %s", e)

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
