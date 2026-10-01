import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.core.config import settings
from app.core.constants import (
    ADHOC_JOB_TTL_SECONDS,
    ANALYSIS_MAX_RETRIES,
    HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS,
    HOUSEKEEPING_STARTUP_RECOVERY_LIMIT,
    INSTANCE_ID,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_PROCESSING,
    ScanStatus,
)
from app.core.housekeeping import housekeeping_loop, stale_scan_loop
from app.core.metrics import (
    worker_active_count,
    worker_job_duration_seconds,
    worker_jobs_processed_total,
    worker_queue_size,
)
from app.db.mongodb import get_database, open_gridfs_download_with_retry
from app.repositories.scans import ScanRepository
from app.schemas.adhoc import AdhocAnalyzeRequest
from app.services.analysis import run_analysis
from app.services.analysis.adhoc import run_adhoc_analysis
from app.services.analysis.notifications import notify_analysis_failed

logger = logging.getLogger(__name__)

# Default graceful shutdown timeout (should be less than K8s terminationGracePeriodSeconds)
DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 25

# Far below HOUSEKEEPING_STUCK_SCAN_TIMEOUT_SECONDS, so a live run is never taken for a stuck one.
_CLAIM_RENEW_SECONDS = 60

_ADHOC_JOB = "adhoc:"

# Strong references: the event loop keeps only weak ones to running tasks.
_failure_notices: set[asyncio.Task[None]] = set()


async def _keep_claim(renew: Callable[[], Awaitable[bool]], label: str) -> None:
    while True:
        await asyncio.sleep(_CLAIM_RENEW_SECONDS)
        try:
            if not await renew():
                return
        except Exception:
            logger.exception("Could not renew the claim on %s", label)


async def _renew_adhoc_claim(db: AsyncIOMotorDatabase, job_id: str, worker_id: str) -> bool:
    renewed = await db.adhoc_jobs.update_one(
        {"_id": job_id, "status": SCAN_STATUS_PROCESSING, "worker_id": worker_id},
        {"$set": {"heartbeat_at": datetime.now(timezone.utc)}},
    )
    return bool(renewed.matched_count)


async def _run_adhoc_job(db: AsyncIOMotorDatabase, job: dict[str, Any]) -> dict[str, Any]:
    """The fields that finish the job: its result file, or the error that ended it."""
    fs = AsyncIOMotorGridFSBucket(db)
    try:
        raw = await (await open_gridfs_download_with_retry(fs, ObjectId(job["input_file_id"]))).read()
        request = await asyncio.to_thread(AdhocAnalyzeRequest.model_validate_json, raw)
        result = await run_adhoc_analysis(request, db)
        data = await asyncio.to_thread(lambda: result.model_dump_json().encode())
        result_file_id = await fs.upload_from_stream(f"adhoc-{job['_id']}-result.json", data)
    except Exception as exc:
        logger.exception("Ad-hoc analysis %s failed", job["_id"])
        return {"status": SCAN_STATUS_FAILED, "error": str(exc)}
    return {"status": SCAN_STATUS_COMPLETED, "result_file_id": str(result_file_id)}


def _record_job(status: str, started: float) -> None:
    if worker_jobs_processed_total:
        worker_jobs_processed_total.labels(status=status).inc()
    if worker_job_duration_seconds:
        worker_job_duration_seconds.observe(time.time() - started)


async def _fail_scan(
    db: AsyncIOMotorDatabase,
    scan: dict[str, Any],
    error: str,
    started: float,
    *,
    status: ScanStatus = SCAN_STATUS_PROCESSING,
    worker_id: str | None = None,
) -> None:
    """Fail the scan while it is still in ``status`` (and ``worker_id``'s); count and announce it in the background."""
    if await ScanRepository(db).mark_failed(scan["_id"], error, status=status, worker_id=worker_id):
        _record_job("failed", started)
        notice = asyncio.create_task(notify_analysis_failed(db, scan["_id"], scan.get("project_id"), error))
        _failure_notices.add(notice)
        notice.add_done_callback(_failure_notices.discard)


class AnalysisWorkerManager:
    """Manages analysis worker tasks and job queue."""

    def __init__(self, num_workers: int = 2) -> None:
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.num_workers = num_workers
        self.workers: list[asyncio.Task[None]] = []
        self.housekeeping_task: asyncio.Task[None] | None = None
        self.stale_scan_task: asyncio.Task[None] | None = None
        self._shutting_down: bool = False
        self._active_scans: set[str] = set()
        self._no_active_scans = asyncio.Event()
        self._no_active_scans.set()

    def is_saturated(self) -> bool:
        """Whether a job already waits for every worker, so work that can wait should."""
        return self.queue.qsize() >= self.num_workers

    async def start(self) -> None:
        """Start workers and recover pending jobs from the DB."""
        logger.info(f"Starting {self.num_workers} analysis workers...")

        for i in range(self.num_workers):
            task = asyncio.create_task(self.worker(f"worker-{i}"))
            self.workers.append(task)

        if worker_active_count:
            worker_active_count.set(self.num_workers)

        self.housekeeping_task = asyncio.create_task(housekeeping_loop(self))
        logger.info("Housekeeping task started.")

        self.stale_scan_task = asyncio.create_task(stale_scan_loop(self))
        logger.info("Stale scan loop started.")

        try:
            db = await get_database()
            ready_before = datetime.now(timezone.utc) - timedelta(seconds=HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS)
            # The stale loop owns scans holding results; a newer scan may still be registering its first one.
            without_results: dict[str, Any] = {
                "status": SCAN_STATUS_PENDING,
                "received_results": {"$in": [None, []]},
                "created_at": {"$lt": ready_before},
            }
            cursor = (
                db.scans.find(without_results, {"_id": 1})
                .sort("created_at", 1)
                .limit(HOUSEKEEPING_STARTUP_RECOVERY_LIMIT)
            )

            count = 0
            async for scan in cursor:
                await self.add_job(str(scan["_id"]))
                count += 1

            if count > 0:
                logger.info(f"Recovered {count} pending scans without results from database.")
            if count >= HOUSEKEEPING_STARTUP_RECOVERY_LIMIT:
                logger.warning(
                    f"Recovery limit ({HOUSEKEEPING_STARTUP_RECOVERY_LIMIT}) reached; "
                    f"pending scans without results beyond it wait for the next process start."
                )
        except Exception as e:
            logger.exception("Failed to recover pending jobs: %s", e)

    async def _stop_background_tasks(self) -> None:
        background = [task for task in (self.housekeeping_task, self.stale_scan_task) if task]
        for task in background:
            task.cancel()
        if background:
            # Lets their cleanup (lock release, multipart abort) run before shutdown closes the Mongo client.
            await asyncio.wait(background, timeout=3)
            logger.info("Background tasks cancelled.")

    def _drain_queue(self) -> None:
        """Drop remaining queue items — they stay 'pending' in the DB and will be
        recovered by other pods."""
        queue_size = self.queue.qsize()
        if queue_size == 0:
            return

        logger.info(
            f"Leaving {queue_size} items in queue - they remain 'pending' in DB "
            f"and will be recovered by other pods or on restart."
        )
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except asyncio.QueueEmpty:
                break

    def _track_scan(self, scan_id: str) -> None:
        self._active_scans.add(scan_id)
        self._no_active_scans.clear()

    def _untrack_scan(self, scan_id: str) -> None:
        self._active_scans.discard(scan_id)
        if not self._active_scans:
            self._no_active_scans.set()

    async def _await_active_scans(self) -> None:
        if not self._active_scans:
            return

        timeout = DEFAULT_SHUTDOWN_TIMEOUT_SECONDS
        logger.info(f"Waiting for {len(self._active_scans)} active scan(s) to complete: {self._active_scans}")
        try:
            async with asyncio.timeout(timeout):
                await self._no_active_scans.wait()
            logger.info("All active scans completed gracefully.")
        except TimeoutError:
            logger.warning(
                f"Shutdown timeout ({timeout}s) exceeded. "
                f"Force-cancelling {len(self._active_scans)} active scan(s): "
                f"{self._active_scans}. "
                f"These will be recovered by housekeeping as stuck scans."
            )

    async def stop(self) -> None:
        """Graceful shutdown: stop accepting jobs, finish active scans within
        ``DEFAULT_SHUTDOWN_TIMEOUT_SECONDS``, then force-cancel any stragglers."""
        timeout = DEFAULT_SHUTDOWN_TIMEOUT_SECONDS

        logger.info(
            f"Initiating graceful shutdown (timeout: {timeout}s, "
            f"active scans: {len(self._active_scans)}, "
            f"queue size: {self.queue.qsize()})..."
        )

        self._shutting_down = True

        await self._stop_background_tasks()

        self._drain_queue()

        await self._await_active_scans()

        for task in self.workers:
            if not task.done():
                task.cancel()

        if self.workers:
            await asyncio.gather(*self.workers, return_exceptions=True)

        if worker_active_count:
            worker_active_count.set(0)
        if worker_queue_size:
            worker_queue_size.set(0)

        logger.info("Graceful shutdown complete.")

    async def add_job(self, scan_id: str) -> bool:
        """Add a scan to the queue. Returns False when rejected during shutdown."""
        if self._shutting_down:
            logger.warning(
                f"Job {scan_id} rejected - worker manager is shutting down. "
                f"Scan remains 'pending' in DB and will be processed by another pod."
            )
            return False

        await self.queue.put(scan_id)
        queue_size = self.queue.qsize()
        logger.info(f"Job {scan_id} added to queue. Queue size: {queue_size}")

        if worker_queue_size:
            worker_queue_size.set(queue_size)

        return True

    async def add_adhoc_job(self, job_id: str) -> bool:
        return await self.add_job(_ADHOC_JOB + job_id)

    async def _handle_rescheduled(self, scan: dict[str, Any], db: AsyncIOMotorDatabase, started: float) -> None:
        """Re-queue a scan the engine sent back to pending, or fail it once its retry budget is spent."""
        scan_id = scan["_id"]
        # Every reschedule follows exactly one engine requeue, which added one to the claimed retry_count.
        retry_count = scan.get("retry_count", 0) + 1
        if retry_count < ANALYSIS_MAX_RETRIES:
            logger.info(f"Scan {scan_id} was rescheduled. Re-queueing (attempt {retry_count}/{ANALYSIS_MAX_RETRIES}).")
            await self.queue.put(scan_id)
            return

        logger.error(f"Scan {scan_id} was rescheduled {retry_count} times. Marking as failed.")
        error = f"Analysis failed after {retry_count} retry attempts: new input kept arriving or an SBOM failed to load"
        # The engine sent it back to pending, so a scan another worker has claimed since is left alone.
        await _fail_scan(db, scan, error, started, status=SCAN_STATUS_PENDING)

    async def _process(self, scan_id: str, worker_id: str) -> None:
        logger.info(f"Worker {worker_id} picked up scan {scan_id}")
        if worker_queue_size:
            worker_queue_size.set(self.queue.qsize())
        started = time.time()

        db = await get_database()
        scan_repo = ScanRepository(db)
        scan = await scan_repo.claim_pending(scan_id, worker_id)
        if not scan:
            logger.info(f"Scan {scan_id} already claimed or not found. Skipping.")
            return

        self._track_scan(scan_id)
        claim_keeper = asyncio.create_task(
            _keep_claim(partial(scan_repo.renew_claim, scan_id, worker_id), f"scan {scan_id}")
        )
        try:
            project = await db.projects.find_one({"_id": scan["project_id"]})
            if not project:
                logger.error(f"Project for scan {scan_id} not found, skipping.")
                await _fail_scan(db, scan, "Project not found", started, worker_id=worker_id)
                return

            outcome = await run_analysis(
                scan_id=scan_id,
                sboms=scan.get("sbom_refs", []),
                active_analyzers=project.get("active_analyzers", []),
                db=db,
                worker_id=worker_id,
                sbom_generation=scan.get("sbom_generation"),
            )
            if outcome == SCAN_STATUS_PENDING:
                await self._handle_rescheduled(scan, db, started)
            elif outcome is not None:
                _record_job("failed" if outcome == SCAN_STATUS_FAILED else "success", started)
        except Exception as e:
            logger.exception("Error processing scan %s: %s", scan_id, e)
            await _fail_scan(db, scan, str(e), started, worker_id=worker_id)
        finally:
            claim_keeper.cancel()
            self._untrack_scan(scan_id)
        logger.info(f"Worker {worker_id} finished scan {scan_id}")

    async def _process_adhoc(self, job_id: str, worker_id: str) -> None:
        started = time.time()
        db = await get_database()
        job = await db.adhoc_jobs.find_one_and_update(
            {"_id": job_id, "status": SCAN_STATUS_PENDING},
            {
                "$set": {
                    "status": SCAN_STATUS_PROCESSING,
                    "worker_id": worker_id,
                    "heartbeat_at": datetime.now(timezone.utc),
                }
            },
        )
        if not job:
            logger.info(f"Ad-hoc job {job_id} already claimed, finished or expired. Skipping.")
            return

        self._track_scan(job_id)
        claim_keeper = asyncio.create_task(
            _keep_claim(partial(_renew_adhoc_claim, db, job_id, worker_id), f"ad-hoc job {job_id}")
        )
        try:
            outcome = await _run_adhoc_job(db, job)
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=ADHOC_JOB_TTL_SECONDS)
            await db.adhoc_jobs.update_one(
                {"_id": job_id, "status": SCAN_STATUS_PROCESSING, "worker_id": worker_id},
                {"$set": {**outcome, "expires_at": expires_at}},
            )
            _record_job("success" if outcome["status"] == SCAN_STATUS_COMPLETED else "failed", started)
        finally:
            claim_keeper.cancel()
            self._untrack_scan(job_id)

    async def worker(self, name: str) -> None:
        worker_id = f"{INSTANCE_ID}/{name}"
        logger.info(f"Worker {worker_id} started")

        while True:
            try:
                if self._shutting_down and self.queue.empty():
                    logger.info(f"Worker {worker_id} exiting - shutdown signaled and queue empty")
                    break

                # 1s timeout so we can periodically re-check the shutdown flag.
                try:
                    scan_id = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    if self._shutting_down:
                        logger.info(f"Worker {worker_id} exiting - shutdown signaled")
                        break
                    continue

                try:
                    if self._shutting_down:
                        # Leave the scan as 'pending' in DB so other pods can pick it up.
                        logger.info(f"Worker {worker_id} returning scan {scan_id} to queue - shutting down")
                        break
                    if scan_id.startswith(_ADHOC_JOB):
                        await self._process_adhoc(scan_id.removeprefix(_ADHOC_JOB), worker_id)
                    else:
                        await self._process(scan_id, worker_id)
                finally:
                    self.queue.task_done()

            except asyncio.CancelledError:
                logger.info(f"Worker {worker_id} cancelled during shutdown")
                raise
            except Exception as e:
                logger.exception("Worker %s crashed: %s", worker_id, e)
                await asyncio.sleep(1)  # Prevents tight loop on persistent failure.


WorkerManager = AnalysisWorkerManager

worker_manager = AnalysisWorkerManager(num_workers=settings.WORKER_COUNT)
