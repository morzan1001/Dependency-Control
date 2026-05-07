import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from typing import List, Optional, Set

from pymongo import ReadPreference

from app.core.config import settings
from app.core.housekeeping import housekeeping_loop, stale_scan_loop
from app.db.mongodb import get_database
from app.services.analysis import run_analysis
from app.services.notifications.service import safe_notify_project_event
from app.services.webhooks import webhook_service

logger = logging.getLogger(__name__)

try:
    from app.core.metrics import (
        worker_active_count,
        worker_job_duration_seconds,
        worker_jobs_processed_total,
        worker_queue_size,
    )
except ImportError:
    worker_queue_size = None  # type: ignore[assignment]
    worker_active_count = None  # type: ignore[assignment]
    worker_jobs_processed_total = None  # type: ignore[assignment]
    worker_job_duration_seconds = None  # type: ignore[assignment]

# Default graceful shutdown timeout (should be less than K8s terminationGracePeriodSeconds)
DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 25


class AnalysisWorkerManager:
    """Manages analysis worker tasks and job queue."""

    def __init__(self, num_workers: int = 2) -> None:
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.num_workers = num_workers
        self.workers: List[asyncio.Task[None]] = []
        self.housekeeping_task: Optional[asyncio.Task[None]] = None
        self.stale_scan_task: Optional[asyncio.Task[None]] = None
        self._shutting_down: bool = False
        self._active_scans: Set[str] = set()
        self._shutdown_event: asyncio.Event = asyncio.Event()

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
            # Strong read: after a pod crash we need the authoritative state.
            scans_primary = db.scans.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]
            cursor = scans_primary.find({"status": "pending"}, {"_id": 1}).sort("created_at", 1).limit(recovery_limit)

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
            logger.error(f"Failed to recover pending jobs: {e}")

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

    async def _await_active_scans(self, timeout: int) -> None:
        if not self._active_scans:
            return

        logger.info(f"Waiting for {len(self._active_scans)} active scan(s) to complete: {self._active_scans}")
        try:
            await asyncio.wait_for(self._wait_for_active_scans(), timeout=timeout)
            logger.info("All active scans completed gracefully.")
        except asyncio.TimeoutError:
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
        self._shutdown_event.set()

        self._cancel_background_tasks()

        self._drain_queue()

        await self._await_active_scans(timeout)

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

    async def _wait_for_active_scans(self) -> None:
        while self._active_scans:
            await asyncio.sleep(0.5)

    def is_shutting_down(self) -> bool:
        return self._shutting_down

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

    async def _handle_failed_analysis(self, scan: dict, scan_id: str, db) -> bool:
        """Decide whether to retry or mark a failed scan terminal. Returns True if terminal.

        Engine owns status and retry_count writes; this only enforces the retry ceiling.
        """
        max_retries = 5
        retry_count = scan.get("retry_count", 0) + 1
        self._active_scans.discard(scan_id)

        if retry_count >= max_retries:
            logger.error(
                f"Scan {scan_id} failed after {retry_count} retries due to persistent race conditions. Marking as failed."
            )
            await db.scans.update_one(
                {"_id": scan_id},
                {
                    "$set": {
                        "status": "failed",
                        "error": f"Analysis failed after {retry_count} retry attempts due to race conditions.",
                    }
                },
            )
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

                # Atomic claim — flip 'pending' → 'processing' only if still pending.
                # Prevents multiple workers across pods from processing the same scan.
                scan = await db.scans.find_one_and_update(
                    {"_id": scan_id, "status": "pending"},
                    {
                        "$set": {
                            "status": "processing",
                            "worker_id": worker_id,
                            "analysis_started_at": datetime.now(timezone.utc),
                        }
                    },
                    return_document=True,
                )

                if not scan:
                    logger.info(f"Scan {scan_id} already claimed or not found. Skipping.")
                    self.queue.task_done()
                    continue

                # Track this scan as actively processing (for graceful shutdown)
                self._active_scans.add(scan_id)

                # Fetch project config (for active analyzers)
                project = await db.projects.find_one({"_id": scan["project_id"]})
                if not project:
                    logger.error(f"Project for scan {scan_id} not found, skipping.")
                    await db.scans.update_one(
                        {"_id": scan_id},
                        {"$set": {"status": "failed", "error": "Project not found"}},
                    )
                    self._active_scans.discard(scan_id)
                    self.queue.task_done()
                    continue

                try:
                    sbom_refs = scan.get("sbom_refs", [])

                    success = await run_analysis(
                        scan_id=scan_id,
                        sboms=sbom_refs,
                        active_analyzers=project.get("active_analyzers", []),
                        db=db,
                    )

                    if not success:
                        await self._handle_failed_analysis(scan, scan_id, db)
                        self.queue.task_done()
                        continue

                    # run_analysis updates status to 'completed' on success.
                    if worker_jobs_processed_total:
                        worker_jobs_processed_total.labels(status="success").inc()
                    if worker_job_duration_seconds:
                        job_duration = time.time() - job_start_time
                        worker_job_duration_seconds.observe(job_duration)

                except Exception as e:
                    logger.error(f"Error processing scan {scan_id}: {e}")
                    await db.scans.update_one(
                        {"_id": scan_id},
                        {"$set": {"status": "failed", "error": str(e)}},
                    )
                    if worker_jobs_processed_total:
                        worker_jobs_processed_total.labels(status="failed").inc()

                    try:
                        project = await db.projects.find_one({"_id": scan.get("project_id")})
                        if project:
                            project_id_str = str(project["_id"])
                            project_name = project.get("name", "Unknown")
                            await webhook_service.trigger_analysis_failed(
                                db=db,
                                scan_id=scan_id,
                                project_id=project_id_str,
                                project_name=project_name,
                                error_message=str(e),
                            )
                            await safe_notify_project_event(
                                db,
                                project_id=project_id_str,
                                event_type="analysis_failed",
                                subject=f"Scan failed: {project_name}",
                                message=f"Scan {scan_id} for project {project_name} failed: {e}",
                                context="worker.analysis_failed",
                            )
                    except Exception as webhook_err:
                        logger.error(f"Failed to trigger analysis_failed webhook: {webhook_err}")

                self._active_scans.discard(scan_id)
                self.queue.task_done()
                logger.info(f"Worker {worker_id} finished scan {scan_id}")

            except asyncio.CancelledError:
                logger.info(f"Worker {worker_id} cancelled during shutdown")
                raise
            except Exception as e:
                logger.error(f"Worker {worker_id} crashed: {e}")
                await asyncio.sleep(1)  # Prevents tight loop on persistent failure.


WorkerManager = AnalysisWorkerManager

worker_manager = AnalysisWorkerManager(num_workers=settings.WORKER_COUNT)
