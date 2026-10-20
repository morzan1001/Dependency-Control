import asyncio
import logging
import re
from collections import Counter
from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable, Coroutine, Iterable
from datetime import datetime, timedelta, timezone
from functools import partial
from itertools import batched
from typing import TYPE_CHECKING, Any


from app.core import abatched
from app.core.cache import update_cache_stats
from app.core.config import settings
from app.core.constants import (
    ARCHIVE_BATCH_SIZE,
    ARCHIVE_KEY_PATTERN,
    ORPHAN_MIN_AGE_HOURS,
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
from app.core.s3 import archive_key_prefix, delete_object, is_archive_enabled, list_objects
from app.db.mongodb import get_database
from app.models.project import Project
from app.repositories.distributed_locks import DistributedLocksRepository, LockLost, new_lock_holder, run_holding_lock
from app.repositories.scans import HAS_SBOM_MATCH, ScanRepository, is_usable_build
from app.repositories.system_settings import SystemSettingsRepository
from app.services.analysis.notifications import notify_analysis_failed
from app.services.audit.retention import prune_old_audit_entries
from app.services.branch_sync import sync_project_branches
from app.services.compliance.retention import sweep_expired_compliance_reports
from app.services.gridfs_maintenance import reap_orphan_gridfs_files
from app.services.releases import reconcile_release_flags, release_protected_scan_ids, released_scan_ids
from app.services.rescan import RESCAN_SOURCE_PROJECTION, create_rescan
from app.services.scan_cascade import delete_scans_and_related_data
from app.services.stats import run_waiver_recalc
from app.services.update_frequency_reconcile import run_update_frequency_reconcile

if TYPE_CHECKING:
    from app.core.worker import AnalysisWorkerManager

logger = logging.getLogger(__name__)

_RETENTION_LOCK_NAME = "retention"
_RETENTION_LOCK_TTL_SECONDS = 600
_EXPIRABLE = {"pinned": {"$nin": RETENTION_PROTECTED_FLAG_VALUES}, "status": {"$nin": SCAN_ACTIVE_STATUSES}}
_LOGGED_FAILED_IDS = 20


async def _referenced_scan_ids(db: Any, scan_ids: list[str]) -> set[str]:
    """Asked per batch: one estate-wide set spliced into the retention cursor as $nin outgrows the 16 MB BSON limit."""
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
    """Covers uploads whose scan never existed; the age window spares a callgraph that arrives before its scan."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ORPHAN_MIN_AGE_HOURS)

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
_RESCAN_TIP_PROJECTION = {**RESCAN_SOURCE_PROJECTION, "status": 1, "is_rescan": 1}


def resolve_rescan_interval(project: Project, system_settings: Any) -> int | None:
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


def _is_rescan_due(source_scan: dict, interval_hours: int) -> bool:
    last_rescan: datetime | None = source_scan.get("last_rescanned_at") or source_scan.get("created_at")
    if not last_rescan:
        return False
    next_rescan_due = last_rescan + timedelta(hours=interval_hours)
    return datetime.now(timezone.utc) >= next_rescan_due


async def _rescan_targets(project: Project, db: Any) -> list[dict]:
    """The branch tip plus each environment's newest release, which has to keep being re-evaluated as well."""
    # Head's own tip build, not its lineage, so the rescan refreshes what head reports instead of the last rescan.
    tip = await ScanRepository(db).head_build(project, {}, _RESCAN_TIP_PROJECTION)
    targets = [tip] if tip and is_usable_build(tip) and tip.get("sbom_refs") else []

    # The marked scan, never its rescan, which would grow the chain past effective_scan_ids' bound.
    marked_ids = set((await released_scan_ids(db, project.id)).values()) - {target["_id"] for target in targets}
    if marked_ids:
        marked = db.scans.find(
            {
                "project_id": project.id,
                "_id": {"$in": sorted(marked_ids)},
                # A failed one is retried as well, since nothing else analyses it.
                "status": {"$nin": [SCAN_STATUS_PENDING, SCAN_STATUS_PROCESSING]},
                **HAS_SBOM_MATCH,
            },
            RESCAN_SOURCE_PROJECTION,
        )
        targets.extend(await marked.to_list(None))
    return targets


async def _process_project_rescan(
    project_data: dict, system_settings: Any, db: Any, worker_manager: "AnalysisWorkerManager"
) -> None:
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


async def check_scheduled_rescans(worker_manager: "AnalysisWorkerManager") -> None:
    logger.debug("Checking for scheduled re-scans...")
    db = await get_database()

    repo = SystemSettingsRepository(db)
    system_settings = await repo.get()

    async for project_data in db.projects.find({"last_scan_at": {"$ne": None}}, _RESCAN_PROJECT_PROJECTION):
        # The due targets left over stay due, so a later pass, in whichever process has room, takes them.
        if worker_manager.is_saturated():
            break
        try:
            await _process_project_rescan(project_data, system_settings, db, worker_manager)
        except Exception as e:
            logger.exception("Error processing project %s: %s", project_data.get("name"), e)


async def _reap_stale_metadata(db: Any, batch_size: int = ARCHIVE_BATCH_SIZE) -> int:
    """Drops the metadata of scans restored since archiving, which leaves their S3 object to the orphan reaper."""
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


async def _reap_orphan_page(db: Any, page: list[dict[str, Any]], bundle_key: re.Pattern[str], cutoff: datetime) -> int:
    scan_id_by_key = {
        obj["Key"]: match["scan_id"]
        for obj in page
        if (match := bundle_key.fullmatch(obj.get("Key") or "")) and obj.get("LastModified", cutoff) <= cutoff
    }
    if not scan_id_by_key:
        return 0
    known = {
        meta.get("s3_key")
        async for meta in db.archive_metadata.find(
            {"scan_id": {"$in": sorted(set(scan_id_by_key.values()))}}, {"s3_key": 1}
        )
    }
    deleted = 0
    for key in sorted(scan_id_by_key.keys() - known):
        try:
            await delete_object(key)
            deleted += 1
            archive_housekeeping_scans_processed_total.labels(status="orphan_reaped").inc()
            logger.info("Reaped orphan S3 object: %s", key)
        except Exception as e:
            logger.warning("Failed to delete orphan %s: %s", key, e)
    return deleted


async def _reap_orphan_s3_objects(db: Any) -> int:
    if not is_archive_enabled():
        return 0

    await _reap_stale_metadata(db)

    prefix = archive_key_prefix()
    bundle_key = re.compile(re.escape(prefix) + ARCHIVE_KEY_PATTERN)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ORPHAN_MIN_AGE_HOURS)
    deleted = 0
    try:
        async for page in list_objects(prefix):
            deleted += await _reap_orphan_page(db, page, bundle_key, cutoff)
    except Exception as e:
        logger.warning("Orphan reaper stopped: %s", e)
    return deleted


async def _delete_expirable(db: Any, scans: dict[str, Any], label: str) -> int:
    """Delete the scans a pin, a release or a new run has not taken out of retention since it picked them."""
    expirable = await db.scans.distinct("_id", {**scans, **_EXPIRABLE})
    released = await release_protected_scan_ids(db, expirable)
    doomed = [sid for sid in expirable if sid not in released]
    await db.scans.update_many({"_id": {"$in": doomed}}, {"$set": {"retention_deleting": True}})
    return await delete_scans_and_related_data(db, doomed, label)


async def _archive_scans_and_delete(db: Any, scan_ids: list[str], label: str) -> None:
    from app.services.archive import archive_scan

    picked_at = datetime.now(timezone.utc)
    failed_ids: list[str] = []

    for scan_id in scan_ids:
        try:
            metadata = await archive_scan(db, scan_id)
        except Exception as e:
            logger.exception("Failed to archive scan %s: %s", scan_id, e)
            metadata = None
        if not metadata:
            failed_ids.append(scan_id)
        archive_housekeeping_scans_processed_total.labels(status="archived" if metadata else "failed").inc()

    if failed_ids:
        logger.warning(
            "%s: %d scan(s) failed to archive and will NOT be deleted, among them %s",
            label,
            len(failed_ids),
            ", ".join(failed_ids[:_LOGGED_FAILED_IDS]),
        )
        archive_housekeeping_batch_total.labels(status="partial_failure").inc()
    else:
        archive_housekeeping_batch_total.labels(status="success").inc()

    archived = {"$in": scan_ids, "$nin": failed_ids}
    # A scan written to since its archive began holds data its bundle lacks.
    deleted = await _delete_expirable(db, {"_id": archived, "$nor": [{"updated_at": {"$gt": picked_at}}]}, label)
    # Archive anew a kept scan its new bundle predates, unless a cascade or a restore still relies on that bundle.
    kept = {
        "_id": archived,
        "created_at": {"$lt": picked_at},
        "updated_at": {"$gt": picked_at},
        "retention_deleting": {"$ne": True},
        "restore_in_progress": {"$ne": True},
    }
    async for scan in db.scans.find(kept, {"updated_at": 1}):
        stale = {"$gte": picked_at, "$lt": scan["updated_at"]}
        await db.archive_metadata.delete_one({"scan_id": scan["_id"], "archived_at": stale})

    logger.info(f"{label}: Archived {len(scan_ids) - len(failed_ids)} scans, deleted {deleted} from MongoDB.")


def _retention_can_act(action: str, label: str) -> bool:
    if action == RETENTION_ACTION_DELETE or (action == RETENTION_ACTION_ARCHIVE and is_archive_enabled()):
        return True
    if action == RETENTION_ACTION_ARCHIVE:
        logger.warning(
            f"{label}: Retention action is 'archive' but S3 is not configured. "
            "Skipping cleanup. Configure S3 or change retention action to 'delete'."
        )
    else:
        # A value stored before the request schemas constrained it; silence would leave disk growth the only signal.
        logger.warning(
            f"{label}: Unknown retention action {action!r}; expected one of {RETENTION_ACTIONS}. "
            "Scans past their retention window are left in place."
        )
    return False


async def _handle_retention_action(db: Any, scan_ids: list[str], action: str, label: str) -> None:
    if not scan_ids:
        return
    if action == RETENTION_ACTION_ARCHIVE:
        await _archive_scans_and_delete(db, scan_ids, label)
    elif action == RETENTION_ACTION_DELETE:
        await _delete_expirable(db, {"_id": {"$in": scan_ids}}, label)


async def _project_heads(db: Any, project_ids: set[str]) -> set[str]:
    projects = await db.projects.find(
        {"_id": {"$in": sorted(project_ids)}}, {"latest_scan_id": 1, "default_branch": 1, "deleted_branches": 1}
    ).to_list(None)
    return set((await ScanRepository(db).get_latest_active_scan_ids(projects)).values())


async def _unreferenced(db: Any, scans: list[dict[str, Any]]) -> list[str]:
    """Spares rescan sources, both ends of a release's analysis chain, and heads, which would pass to another build."""
    scan_ids = [str(doc["_id"]) for doc in scans]
    protected = await _referenced_scan_ids(db, scan_ids)
    protected |= await release_protected_scan_ids(db, scan_ids)
    protected |= await _project_heads(db, {doc["project_id"] for doc in scans if doc.get("project_id")})
    return [scan_id for scan_id in scan_ids if scan_id not in protected]


async def _process_scans_in_batches(
    db: Any,
    scans: AsyncIterable[dict[str, Any]] | Iterable[dict[str, Any]],
    action: str,
    label: str,
    batch_size: int = ARCHIVE_BATCH_SIZE,
) -> None:
    async for batch in abatched(scans, batch_size):
        await _handle_retention_action(db, await _unreferenced(db, batch), action, label)


async def _superseded_rescans(db: Any, scope: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
    """Rescans past each build's newest RESCAN_HISTORY_RUNS usable ones, sparing the one latest_rescan_id names."""
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
    """A stored retention no cutoff can be computed for fails only its own group."""
    if not _retention_can_act(action, label):
        return
    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        # Read up front: a cursor would sit idle past the server's cursor timeout while the batches archive.
        expired = db.scans.find(
            {**scope, "created_at": {"$lt": cutoff_date}, **_EXPIRABLE}, {"_id": 1, "project_id": 1}
        )
        await _process_scans_in_batches(db, await expired.to_list(None), action, label)
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


async def _best_effort[*Ts](label: str, task: Callable[[*Ts], Awaitable[object]], *args: *Ts) -> None:
    try:
        await task(*args)
    except Exception as e:
        logger.exception("%s failed: %s", label, e)


async def run_housekeeping(db: Any) -> None:
    # Held to expiry, never released: its TTL is the cadence across pods.
    if not await DistributedLocksRepository(db).acquire_lock(
        "housekeeping", new_lock_holder(), ttl_seconds=HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS * 3600
    ):
        return
    logger.info("Starting housekeeping task...")
    for label, sweep in (
        ("Housekeeping: release flag reconcile", reconcile_release_flags),
        ("Housekeeping: policy audit retention", prune_old_audit_entries),
        ("Housekeeping: compliance report sweep", sweep_expired_compliance_reports),
        ("Orphan reaper", _reap_orphan_s3_objects),
        ("Callgraph orphan reaper", _reap_orphan_callgraphs),
        ("GridFS orphan reaper", reap_orphan_gridfs_files),
    ):
        await _best_effort(label, sweep, db)


async def trigger_stale_pending_scans(worker_manager: "AnalysisWorkerManager") -> None:
    """Covers findings-only runs no SBOM triggered and scans whose queue entry died with its pod."""
    if worker_manager.is_saturated():
        return
    db = await get_database()
    quiet_since = datetime.now(timezone.utc) - timedelta(seconds=HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS)
    cursor = (
        db.scans.find(
            {
                "status": SCAN_STATUS_PENDING,
                "$or": [
                    {"last_result_at": {"$lt": quiet_since}},
                    {"last_result_at": None, "created_at": {"$lt": quiet_since}},
                ],
            },
            {"_id": 1},
        )
        .sort("created_at", 1)
        .limit(worker_manager.num_workers)
    )
    async for scan in cursor:
        await worker_manager.add_job(str(scan["_id"]))


async def requeue_waiting_adhoc_jobs(worker_manager: "AnalysisWorkerManager") -> None:
    """Covers ad-hoc jobs whose queue entry died with its pod."""
    if worker_manager.is_saturated():
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


async def recover_stuck_scans(worker_manager: "AnalysisWorkerManager") -> None:
    logger.debug("Running stuck scan recovery...")
    db = await get_database()
    timeout_threshold = datetime.now(timezone.utc) - timedelta(seconds=settings.HOUSEKEEPING_STUCK_SCAN_TIMEOUT_SECONDS)
    max_retries = HOUSEKEEPING_MAX_SCAN_RETRIES
    scan_repo = ScanRepository(db)

    cursor = db.scans.find(
        {
            "status": SCAN_STATUS_PROCESSING,
            "$or": [
                {"analysis_started_at": {"$lt": timeout_threshold}},
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
            if requeued:
                await worker_manager.add_job(str(scan_id))

        else:
            logger.error(f"Scan {scan_id} failed after {max_retries} retries.")
            error = "Analysis timed out or worker crashed multiple times."
            # Every pod runs this loop; only the one whose write lands announces the failure.
            if await scan_repo.mark_failed(scan_id, error, worker_id=scan.get("worker_id")):
                await notify_analysis_failed(db, scan_id, scan.get("project_id"), error)


async def sync_branch_status(db: Any) -> None:
    # Held to expiry, never released: its TTL is the cadence across pods.
    if not await DistributedLocksRepository(db).acquire_lock(
        "branch_sync", new_lock_holder(), ttl_seconds=HOUSEKEEPING_BRANCH_SYNC_INTERVAL_HOURS * 3600
    ):
        return
    logger.info("Starting branch status sync...")

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


async def stale_scan_loop(worker_manager: "AnalysisWorkerManager") -> None:
    while True:
        for requeue in (trigger_stale_pending_scans, requeue_waiting_adhoc_jobs):
            await _best_effort(f"Stale scan loop: {requeue.__name__}", requeue, worker_manager)

        await asyncio.sleep(HOUSEKEEPING_STALE_SCAN_INTERVAL_SECONDS)


def _reconcile_due(now: datetime, last_run: datetime) -> bool:
    """Calendar-day gated: an elapsed-time gate would anchor the heavy run to whenever the lock winner was deployed."""
    return now.hour == HOUSEKEEPING_UPDATE_FREQUENCY_RECONCILE_HOUR_UTC and last_run.date() < now.date()


async def reconcile_update_frequency_ledger() -> None:
    if not settings.UPDATE_FREQUENCY_RECONCILE_ENABLED:
        return
    await _best_effort("Update-frequency reconcile", run_update_frequency_reconcile, await get_database())


async def update_frequency_reconcile_loop() -> None:
    last_run = datetime.min.replace(tzinfo=timezone.utc)
    while True:
        # Stamped whatever the reconcile did, so the pods that lost the lock do not retry it every five minutes.
        now = datetime.now(timezone.utc)
        if _reconcile_due(now, last_run):
            await reconcile_update_frequency_ledger()
            last_run = now
        await asyncio.sleep(HOUSEKEEPING_MAIN_LOOP_INTERVAL_SECONDS)


async def _every_main_interval(label: str, job: Callable[[Any], Awaitable[object]]) -> None:
    while True:
        await _best_effort(label, job, await get_database())
        await asyncio.sleep(HOUSEKEEPING_MAIN_LOOP_INTERVAL_SECONDS)


async def housekeeping_loop(worker_manager: "AnalysisWorkerManager") -> None:
    while True:
        await _best_effort("Stuck scan recovery", recover_stuck_scans, worker_manager)
        await _best_effort("Scheduled re-scan check", check_scheduled_rescans, worker_manager)

        db = await get_database()
        await update_db_stats(db)
        await update_archive_stats(db)
        await update_cache_stats()

        await asyncio.sleep(HOUSEKEEPING_MAIN_LOOP_INTERVAL_SECONDS)


def background_loops(worker_manager: "AnalysisWorkerManager") -> list[Coroutine[Any, Any, None]]:
    """One loop per job: a long run on the pod holding a job's lock then delays no other job."""
    return [
        housekeeping_loop(worker_manager),
        stale_scan_loop(worker_manager),
        update_frequency_reconcile_loop(),
        _every_main_interval("Waiver recalculation", run_waiver_recalc),
        _every_main_interval("Housekeeping task", run_housekeeping),
        _every_main_interval("Housekeeping: retention", _run_retention),
        _every_main_interval("Branch status sync", sync_branch_status),
    ]
