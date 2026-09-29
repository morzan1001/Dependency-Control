import asyncio
import logging
import os
import time
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.constants import SCAN_STATUS_FAILED, SCAN_STATUS_PENDING
from app.core.housekeeping import housekeeping_loop, stale_scan_loop
from app.core.metrics import (
    worker_active_count,
    worker_job_duration_seconds,
    worker_jobs_processed_total,
    worker_queue_size,
)
from app.db.mongodb import get_database
from app.repositories.scans import ScanRepository
from app.services.analysis import run_analysis
from app.services.analysis.notifications import notify_analysis_failed

logger = logging.getLogger(__name__)

# Default graceful shutdown timeout (should be less than K8s terminationGracePeriodSeconds)
DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 25

# Far below HOUSEKEEPING_STUCK_SCAN_TIMEOUT_SECONDS, so a live run is never taken for a stuck one.
_CLAIM_RENEW_SECONDS = 60


async def _keep_claim(scan_repo: ScanRepository, scan_id: str, worker_id: str) -> None:
    while True:
        await asyncio.sleep(_CLAIM_RENEW_SECONDS)
        try:
            if not await scan_repo.renew_claim(scan_id, worker_id):
                return
        except Exception:
            logger.exception("Could not renew the claim on scan %s", scan_id)


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
            # Cap recovery so a backlog of stale pending scans doesn't flood the queue.
            recovery_limit = 1000
            cursor = (
                db.scans.find({"status": SCAN_STATUS_PENDING}, {"_id": 1}).sort("created_at", 1).limit(recovery_limit)
            )

            count = 0
            async for scan in cursor:
                await self.queue.put(str(scan["_id"]))
                count += 1

            if count > 0:
                logger.info(f"Recovered {count} pending scans from database.")
                if count >= recovery_limit:
                    logger.warning(
                        f"Recovery limit ({recovery_limit}) reached. "
                        f"Some pending scans may not have been queued. "
                        f"They will be picked up by housekeeping."
                    )
        except Exception as e:
            logger.exception("Failed to recover pending jobs: %s", e)

    def _cancel_background_tasks(self) -> None:
        if self.housekeeping_task:
            self.housekeeping_task.cancel()
            logger.info("Housekeeping task cancelled.")

        if self.stale_scan_task:
            self.stale_scan_task.cancel()
            logger.info("Stale scan loop cancelled.")

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

        self._cancel_background_tasks()

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

    async def _handle_rescheduled(self, scan: dict[str, Any], scan_id: str, db: AsyncIOMotorDatabase) -> bool:
        """Apply the retry ceiling. Engine owns status and retry_count writes."""
        max_retries = 5
        retry_count = scan.get("retry_count", 0) + 1
        self._untrack_scan(scan_id)

        if retry_count >= max_retries:
            logger.error(
                f"Scan {scan_id} failed after {retry_count} retries due to persistent race conditions. Marking as failed."
            )
            error_message = f"Analysis failed after {retry_count} retry attempts due to race conditions."
            # The engine sent it back to pending, so a scan another worker has claimed since is left alone.
            if await ScanRepository(db).mark_failed(scan_id, error_message, status=SCAN_STATUS_PENDING):
                await notify_analysis_failed(db, scan_id, scan.get("project_id"), error_message)
            return True

        logger.info(
            f"Scan {scan_id} requires re-processing (race condition). "
            f"Re-queueing (attempt {retry_count}/{max_retries})."
        )
        await self.queue.put(scan_id)
        return False

    async def worker(self, name: str) -> None:
        hostname = os.getenv("HOSTNAME", "unknown")
        worker_id = f"{hostname}/{name}"
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

                if self._shutting_down:
                    # Leave the scan as 'pending' in DB so other pods can pick it up.
                    logger.info(f"Worker {worker_id} returning scan {scan_id} to queue - shutting down")
                    self.queue.task_done()
                    break

                logger.info(f"Worker {worker_id} picked up scan {scan_id}")

                if worker_queue_size:
                    worker_queue_size.set(self.queue.qsize())

                job_start_time = time.time()

                db = await get_database()

                scan_repo = ScanRepository(db)
                scan = await scan_repo.claim_pending(scan_id, worker_id)

                if not scan:
                    logger.info(f"Scan {scan_id} already claimed or not found. Skipping.")
                    self.queue.task_done()
                    continue

                # Track this scan as actively processing (for graceful shutdown)
                self._track_scan(scan_id)

                project = await db.projects.find_one({"_id": scan["project_id"]})
                if not project:
                    logger.error(f"Project for scan {scan_id} not found, skipping.")
                    await scan_repo.mark_failed(scan_id, "Project not found", worker_id=worker_id)
                    self._untrack_scan(scan_id)
                    self.queue.task_done()
                    continue

                claim_keeper = asyncio.create_task(_keep_claim(scan_repo, scan_id, worker_id))
                try:
                    outcome = await run_analysis(
                        scan_id=scan_id,
                        sboms=scan.get("sbom_refs", []),
                        active_analyzers=project.get("active_analyzers", []),
                        db=db,
                        worker_id=worker_id,
                        sbom_generation=scan.get("sbom_generation"),
                    )
                    if outcome == SCAN_STATUS_PENDING:
                        await self._handle_rescheduled(scan, scan_id, db)
                    elif outcome is not None:
                        if worker_jobs_processed_total:
                            job_status = "failed" if outcome == SCAN_STATUS_FAILED else "success"
                            worker_jobs_processed_total.labels(status=job_status).inc()
                        if worker_job_duration_seconds:
                            worker_job_duration_seconds.observe(time.time() - job_start_time)

                except Exception as e:
                    logger.exception("Error processing scan %s: %s", scan_id, e)
                    if await scan_repo.mark_failed(scan_id, str(e), worker_id=worker_id):
                        if worker_jobs_processed_total:
                            worker_jobs_processed_total.labels(status="failed").inc()
                        await notify_analysis_failed(db, scan_id, scan.get("project_id"), str(e))
                finally:
                    claim_keeper.cancel()

                self._untrack_scan(scan_id)
                self.queue.task_done()
                logger.info(f"Worker {worker_id} finished scan {scan_id}")

            except asyncio.CancelledError:
                logger.info(f"Worker {worker_id} cancelled during shutdown")
                raise
            except Exception as e:
                logger.exception("Worker %s crashed: %s", worker_id, e)
                await asyncio.sleep(1)  # Prevents tight loop on persistent failure.


WorkerManager = AnalysisWorkerManager

worker_manager = AnalysisWorkerManager(num_workers=settings.WORKER_COUNT)
